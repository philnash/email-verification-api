import { resolveTxt as defaultResolveTxt } from "node:dns/promises";
import * as z from "zod";
import { err, errorCause, ok, type Result } from "./result.js";
import {
  DnsVerifiedTokenSchema,
  ExpectedValuesValidatedTokenSchema,
  type DnsVerifiedToken,
} from "./schemas.js";

export type ResolveTxt = (hostname: string) => Promise<string[][]>;

const ResolveTxtSchema = z.custom<ResolveTxt>(
  (value) => typeof value === "function",
);

const VerifyDnsDelegationInputSchema = z.object({
  token: ExpectedValuesValidatedTokenSchema,
  resolveTxt: ResolveTxtSchema.optional().transform(
    (value) => value ?? defaultResolveTxt,
  ),
});

const DnsRecordsSchema = z.array(z.array(z.string()));
const IssuerValueSchema = z.string().min(1);

export function canonicalIssuer(value: unknown): Result<string> {
  try {
    const stringResult = IssuerValueSchema.safeParse(value);
    if (!stringResult.success) {
      return invalidIssuer(
        "Issuer must be a DNS hostname or a strict HTTPS URL.",
        stringResult.error,
      );
    }

    const issuer = stringResult.data;
    if (issuer !== issuer.trim()) {
      return invalidIssuer("Issuer must not contain surrounding whitespace.");
    }

    const hostname = issuerLooksLikeUrl(issuer)
      ? hostnameFromUrl(issuer)
      : normalizeHostname(issuer);
    if (hostname === undefined) {
      return invalidIssuer(
        "Issuer must be a valid DNS hostname or an HTTPS URL without credentials, a non-default port, path, query, or fragment.",
      );
    }

    return ok(hostname);
  } catch (cause) {
    return invalidIssuer("Issuer could not be read safely.", cause);
  }
}

export async function verifyDnsDelegation(
  input: unknown,
): Promise<Result<DnsVerifiedToken>> {
  const inputResult = parseInput(input);
  if (!inputResult.ok) return inputResult;

  const { token, resolveTxt } = inputResult.value;
  const claimedIssuerResult = canonicalIssuer(token.token.evt.claims.iss);
  if (!claimedIssuerResult.ok) {
    return dnsError(
      "ISSUER_MISMATCH",
      "The EVT issuer is not a valid issuer hostname or HTTPS URL.",
      claimedIssuerResult.error.cause,
    );
  }

  const emailDomain = token.email.slice(token.email.lastIndexOf("@") + 1);
  const dnsTarget = `_email-verification.${emailDomain}`;
  const recordsResult = await resolveRecords(resolveTxt, dnsTarget);
  if (!recordsResult.ok) return recordsResult;

  if (recordsResult.value.length > 1) {
    return dnsError(
      "DNS_DELEGATION_AMBIGUOUS",
      `More than one TXT record was found at ${dnsTarget}.`,
    );
  }

  const joinedRecords = recordsResult.value.map((chunks) => chunks.join(""));
  const issuerRecords = joinedRecords.filter((record) =>
    record.startsWith("iss="),
  );

  if (issuerRecords.length === 0) {
    return dnsError(
      "DNS_DELEGATION_MISSING",
      `No issuer delegation was found at ${dnsTarget}.`,
    );
  }
  if (issuerRecords.length > 1) {
    return dnsError(
      "DNS_DELEGATION_AMBIGUOUS",
      `More than one issuer delegation was found at ${dnsTarget}.`,
    );
  }

  const issuerRecord = issuerRecords[0];
  if (issuerRecord === undefined) {
    return dnsError(
      "DNS_DELEGATION_MISSING",
      `No issuer delegation was found at ${dnsTarget}.`,
    );
  }

  if (issuerRecord.slice(4).includes("iss=")) {
    return dnsError(
      "DNS_DELEGATION_AMBIGUOUS",
      `More than one issuer value was found at ${dnsTarget}.`,
    );
  }

  const delegatedIssuerResult = canonicalIssuer(issuerRecord.slice(4));
  if (!delegatedIssuerResult.ok) {
    return dnsError(
      "DNS_DELEGATION_MISSING",
      `The issuer delegation at ${dnsTarget} is invalid.`,
      delegatedIssuerResult.error.cause,
    );
  }

  if (delegatedIssuerResult.value !== claimedIssuerResult.value) {
    return dnsError(
      "ISSUER_MISMATCH",
      "The DNS-delegated issuer does not exactly match the EVT issuer.",
    );
  }

  try {
    const verifiedResult = DnsVerifiedTokenSchema.safeParse({
      token,
      issuer: claimedIssuerResult.value,
    });
    if (!verifiedResult.success) {
      return invalidInput(
        "The DNS-verified token could not be represented safely.",
        verifiedResult.error,
      );
    }
    return ok(verifiedResult.data);
  } catch (cause) {
    return invalidInput(
      "The DNS-verified token could not be represented safely.",
      cause,
    );
  }
}

function parseInput(
  input: unknown,
): Result<z.infer<typeof VerifyDnsDelegationInputSchema>> {
  try {
    const result = VerifyDnsDelegationInputSchema.safeParse(input);
    if (!result.success) {
      return invalidInput(
        "DNS verification requires an expected-values-validated token and an optional TXT resolver.",
        result.error,
      );
    }
    return ok(result.data);
  } catch (cause) {
    return invalidInput(
      "DNS verification input could not be read safely.",
      cause,
    );
  }
}

async function resolveRecords(
  resolveTxt: ResolveTxt,
  dnsTarget: string,
): Promise<Result<string[][]>> {
  try {
    const records = await resolveTxt(dnsTarget);
    const result = DnsRecordsSchema.safeParse(records);
    if (!result.success) {
      return dnsError(
        "DNS_LOOKUP_FAILED",
        `The TXT resolver returned an invalid response for ${dnsTarget}.`,
        result.error,
      );
    }
    return ok(result.data);
  } catch (cause) {
    return dnsError(
      "DNS_LOOKUP_FAILED",
      `The TXT lookup failed for ${dnsTarget}.`,
      cause,
    );
  }
}

function issuerLooksLikeUrl(value: string): boolean {
  return value.includes("://");
}

function hostnameFromUrl(value: string): string | undefined {
  if (!/^https:\/\/[^/?#]+\/?$/iu.test(value)) return undefined;

  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.port !== "" ||
      url.pathname !== "/" ||
      url.search !== "" ||
      url.hash !== ""
    ) {
      return undefined;
    }
    return normalizeHostname(url.hostname);
  } catch {
    return undefined;
  }
}

function normalizeHostname(value: string): string | undefined {
  const withoutTrailingDot = value.endsWith(".") ? value.slice(0, -1) : value;
  if (
    withoutTrailingDot.length === 0 ||
    withoutTrailingDot.length > 253 ||
    withoutTrailingDot.endsWith(".")
  ) {
    return undefined;
  }

  const labels = withoutTrailingDot.split(".");
  const validLabel = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/iu;
  if (labels.some((label) => !validLabel.test(label))) return undefined;
  return withoutTrailingDot.toLowerCase();
}

function invalidIssuer(message: string, cause?: unknown): Result<never> {
  return dnsError("INVALID_INPUT", message, cause);
}

function invalidInput(message: string, cause?: unknown): Result<never> {
  return dnsError("INVALID_INPUT", message, cause);
}

function dnsError(
  code:
    | "INVALID_INPUT"
    | "DNS_LOOKUP_FAILED"
    | "DNS_DELEGATION_MISSING"
    | "DNS_DELEGATION_AMBIGUOUS"
    | "ISSUER_MISMATCH",
  message: string,
  cause?: unknown,
): Result<never> {
  return err({
    stage: "dns",
    code,
    message,
    ...(cause === undefined ? {} : { cause: errorCause(cause) }),
  });
}
