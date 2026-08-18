import {
  compactVerify,
  createLocalJWKSet,
  errors,
  type JWK,
  type LocalJWKSet,
} from "jose";
import * as z from "zod";
import { err, errorCause, ok, type Result } from "./result.js";
import {
  DnsVerifiedTokenSchema,
  IssuerMetadataSchema,
  IssuerVerifiedTokenSchema,
  JsonWebKeySetSchema,
  type IssuerMetadata,
  type IssuerVerifiedToken,
  type JsonWebKeySet,
  type PublicJwk,
} from "./schemas.js";
import { canonicalIssuer } from "./verify-dns-delegation.js";

const MAXIMUM_MATCHING_KEYS = 10;

type FetchFunction = typeof globalThis.fetch;
type JsonReader = () => unknown;
type DocumentKind = "metadata" | "JWKS";

const FetchSchema = z.custom<FetchFunction>(
  (value) => typeof value === "function",
);

const VerifyIssuerSignatureInputSchema = z.object({
  token: DnsVerifiedTokenSchema,
  fetch: FetchSchema.optional().transform((value) => value ?? globalThis.fetch),
});

const FetchResponseSchema = z.looseObject({
  ok: z.boolean(),
  status: z.number().int().nonnegative().max(599),
  url: z.string(),
  json: z.custom<JsonReader>((value) => typeof value === "function"),
});

export async function verifyIssuerSignature(
  input: unknown,
): Promise<Result<IssuerVerifiedToken>> {
  const inputResult = parseInput(input);
  if (!inputResult.ok) return inputResult;

  const { token, fetch } = inputResult.value;
  const canonicalIssuerResult = canonicalIssuer(token.issuer);
  if (
    !canonicalIssuerResult.ok ||
    canonicalIssuerResult.value !== token.issuer
  ) {
    return issuerError(
      "INVALID_INPUT",
      "Issuer verification requires a canonical DNS-verified issuer hostname.",
    );
  }
  const metadataUrl = `https://${token.issuer}/.well-known/email-verification`;

  const metadataDocument = await fetchJsonDocument({
    fetch,
    url: metadataUrl,
    issuer: token.issuer,
    kind: "metadata",
  });
  if (!metadataDocument.ok) return metadataDocument;

  const metadataResult = parseMetadata(metadataDocument.value, token.issuer);
  if (!metadataResult.ok) return metadataResult;
  const metadata = metadataResult.value;

  const algorithm = token.token.token.evt.header.alg;
  if (!metadata.signing_alg_values_supported.includes(algorithm)) {
    return issuerError(
      "ALGORITHM_UNSUPPORTED",
      "The EVT signing algorithm is not advertised by the issuer.",
    );
  }

  const jwksDocument = await fetchJsonDocument({
    fetch,
    url: metadata.jwks_uri,
    issuer: token.issuer,
    kind: "JWKS",
  });
  if (!jwksDocument.ok) return jwksDocument;

  const jwksResult = parseJwks(jwksDocument.value);
  if (!jwksResult.ok) return jwksResult;

  const signatureResult = await verifyEvtSignature(
    token.token.token.evt.compact,
    algorithm,
    jwksResult.value,
  );
  if (!signatureResult.ok) return signatureResult;

  try {
    const verifiedResult = IssuerVerifiedTokenSchema.safeParse({
      token,
      metadata,
    });
    if (!verifiedResult.success) {
      return issuerError(
        "INVALID_INPUT",
        "The issuer-verified token could not be represented safely.",
      );
    }
    return ok(verifiedResult.data);
  } catch (cause) {
    return issuerError(
      "INVALID_INPUT",
      "The issuer-verified token could not be represented safely.",
      cause,
    );
  }
}

function parseInput(
  input: unknown,
): Result<z.infer<typeof VerifyIssuerSignatureInputSchema>> {
  try {
    const result = VerifyIssuerSignatureInputSchema.safeParse(input);
    if (!result.success) {
      return issuerError(
        "INVALID_INPUT",
        "Issuer verification requires a DNS-verified token and an optional Fetch implementation.",
      );
    }
    return ok(result.data);
  } catch (cause) {
    return issuerError(
      "INVALID_INPUT",
      "Issuer verification input could not be read safely.",
      cause,
    );
  }
}

async function fetchJsonDocument({
  fetch,
  url,
  issuer,
  kind,
}: {
  fetch: FetchFunction;
  url: string;
  issuer: string;
  kind: DocumentKind;
}): Promise<Result<unknown>> {
  let responseValue: unknown;
  try {
    responseValue = await fetch(url);
  } catch (cause) {
    return fetchError(kind, `${kind} could not be fetched.`, cause);
  }

  let responseResult: z.ZodSafeParseResult<z.infer<typeof FetchResponseSchema>>;
  try {
    responseResult = FetchResponseSchema.safeParse(responseValue);
  } catch (cause) {
    return fetchError(
      kind,
      `${kind} Fetch returned an unreadable response.`,
      cause,
    );
  }

  if (!responseResult.success) {
    return fetchError(kind, `${kind} Fetch returned an invalid response.`);
  }

  const response = responseResult.data;
  if (response.url !== "" && !isIssuerBoundHttpsUrl(response.url, issuer)) {
    return documentError(
      kind,
      `${kind} was returned from an unsafe redirect URL.`,
    );
  }

  if (!response.ok) {
    return fetchError(
      kind,
      `${kind} request failed with HTTP status ${String(response.status)}.`,
    );
  }

  try {
    return ok(await Reflect.apply(response.json, responseValue, []));
  } catch {
    // JSON parser messages can contain response text, so do not expose the cause.
    return documentError(kind, `${kind} response did not contain valid JSON.`);
  }
}

function parseMetadata(value: unknown, issuer: string): Result<IssuerMetadata> {
  let result: z.ZodSafeParseResult<IssuerMetadata>;
  try {
    result = IssuerMetadataSchema.safeParse(value);
  } catch {
    return issuerError(
      "METADATA_INVALID",
      "Issuer metadata could not be read safely.",
    );
  }

  if (!result.success) {
    return issuerError(
      "METADATA_INVALID",
      "Issuer metadata does not match the required schema.",
    );
  }

  if (
    !isIssuerBoundHttpsUrl(result.data.issuance_endpoint, issuer) ||
    !isIssuerBoundHttpsUrl(result.data.jwks_uri, issuer)
  ) {
    return issuerError(
      "METADATA_INVALID",
      "Issuer metadata endpoints must be issuer-bound HTTPS URLs.",
    );
  }

  return ok(result.data);
}

function parseJwks(value: unknown): Result<JsonWebKeySet> {
  try {
    const result = JsonWebKeySetSchema.safeParse(value);
    if (!result.success) {
      return issuerError(
        "JWKS_INVALID",
        "The issuer JWKS does not match the required schema.",
      );
    }
    return ok(result.data);
  } catch {
    return issuerError(
      "JWKS_INVALID",
      "The issuer JWKS could not be read safely.",
    );
  }
}

function isIssuerBoundHttpsUrl(value: string, issuer: string): boolean {
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.port !== ""
    ) {
      return false;
    }

    const hostname = url.hostname.endsWith(".")
      ? url.hostname.slice(0, -1)
      : url.hostname;
    const normalizedHostname = hostname.toLowerCase();
    return (
      normalizedHostname === issuer || normalizedHostname.endsWith(`.${issuer}`)
    );
  } catch {
    return false;
  }
}

async function verifyEvtSignature(
  compactEvt: string,
  algorithm: string,
  jwks: JsonWebKeySet,
): Promise<Result<true>> {
  let issuerKeys: LocalJWKSet;
  try {
    issuerKeys = createLocalJWKSet({ keys: jwks.keys.map(toJoseJwk) });
  } catch (cause) {
    return issuerError(
      "JWKS_INVALID",
      "The issuer JWKS could not be used for signature verification.",
      cause,
    );
  }

  try {
    await compactVerify(compactEvt, issuerKeys, {
      algorithms: [algorithm],
    });
    return ok(true);
  } catch (cause) {
    if (cause instanceof errors.JWKSMultipleMatchingKeys) {
      return verifyWithMatchingKeys(compactEvt, algorithm, cause);
    }
    if (cause instanceof errors.JWKSInvalid) {
      return issuerError(
        "JWKS_INVALID",
        "The issuer JWKS could not be used for signature verification.",
        cause,
      );
    }
    return issuerError(
      "EVT_SIGNATURE_INVALID",
      "The EVT signature could not be verified with an issuer key.",
      cause,
    );
  }
}

function toJoseJwk(jwk: PublicJwk): JWK {
  const common: JWK = {
    kty: jwk.kty,
    ...(jwk.alg === undefined ? {} : { alg: jwk.alg }),
    ...(jwk.kid === undefined ? {} : { kid: jwk.kid }),
    ...(jwk.use === undefined ? {} : { use: jwk.use }),
    ...(jwk.key_ops === undefined ? {} : { key_ops: jwk.key_ops }),
    ...(jwk.ext === undefined ? {} : { ext: jwk.ext }),
  };

  switch (jwk.kty) {
    case "RSA":
      return { ...common, e: jwk.e, n: jwk.n };
    case "EC":
      return { ...common, crv: jwk.crv, x: jwk.x, y: jwk.y };
    case "OKP":
      return { ...common, crv: jwk.crv, x: jwk.x };
  }
}

async function verifyWithMatchingKeys(
  compactEvt: string,
  algorithm: string,
  matchingKeys: errors.JWKSMultipleMatchingKeys,
): Promise<Result<true>> {
  let attempts = 0;

  try {
    for await (const key of matchingKeys) {
      if (attempts === MAXIMUM_MATCHING_KEYS) {
        return issuerError(
          "JWKS_INVALID",
          `More than ${String(MAXIMUM_MATCHING_KEYS)} issuer keys matched the EVT header.`,
        );
      }
      attempts += 1;

      try {
        await compactVerify(compactEvt, key, { algorithms: [algorithm] });
        return ok(true);
      } catch (cause) {
        if (cause instanceof errors.JWSSignatureVerificationFailed) continue;
        return issuerError(
          "JWKS_INVALID",
          "A matching issuer key could not be used safely.",
          cause,
        );
      }
    }
  } catch (cause) {
    return issuerError(
      "JWKS_INVALID",
      "Matching issuer keys could not be read safely.",
      cause,
    );
  }

  return issuerError(
    "EVT_SIGNATURE_INVALID",
    "No matching issuer key verified the EVT signature.",
  );
}

function fetchError(
  kind: DocumentKind,
  message: string,
  cause?: unknown,
): Result<never> {
  return issuerError(
    kind === "metadata" ? "METADATA_FETCH_FAILED" : "JWKS_FETCH_FAILED",
    message,
    cause,
  );
}

function documentError(kind: DocumentKind, message: string): Result<never> {
  return issuerError(
    kind === "metadata" ? "METADATA_INVALID" : "JWKS_INVALID",
    message,
  );
}

function issuerError(
  code:
    | "INVALID_INPUT"
    | "METADATA_FETCH_FAILED"
    | "METADATA_INVALID"
    | "JWKS_FETCH_FAILED"
    | "JWKS_INVALID"
    | "ALGORITHM_UNSUPPORTED"
    | "EVT_SIGNATURE_INVALID",
  message: string,
  cause?: unknown,
): Result<never> {
  return err({
    stage: "issuer",
    code,
    message,
    ...(cause === undefined ? {} : { cause: errorCause(cause) }),
  });
}
