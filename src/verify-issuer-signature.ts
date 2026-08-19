import { isDeepStrictEqual } from "node:util";
import { compactVerify, errors, importJWK, type JWK } from "jose";
import * as z from "zod";
import {
  isSafeNetworkHostname,
  validateResolvedAddresses,
} from "./network-safety.js";
import { parseToken } from "./parse-token.js";
import { err, errorCause, ok, type Result } from "./result.js";
import { containsAsciiWhitespaceOrControl } from "./security-text.js";
import {
  DnsVerifiedTokenSchema,
  defaultResolveHost,
  IssuerMetadataSchema,
  IssuerVerifiedTokenSchema,
  JsonWebKeySetSchema,
  ResolveHostSchema,
  type IssuerMetadata,
  type IssuerVerifiedToken,
  type JsonWebKeySet,
  type PublicJwk,
  type ResolveHost,
} from "./schemas.js";
import { validateExpectedValues } from "./validate-expected-values.js";
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
  resolveHost: ResolveHostSchema.optional().transform(
    (value) => value ?? defaultResolveHost,
  ),
});

const FetchResponseSchema = z.looseObject({
  ok: z.boolean(),
  status: z.number().int().nonnegative().max(599),
  url: z.string(),
  redirected: z.boolean(),
  json: z.custom<JsonReader>((value) => typeof value === "function"),
});

export async function verifyIssuerSignature(
  input: unknown,
): Promise<Result<IssuerVerifiedToken>> {
  const inputResult = parseInput(input);
  if (!inputResult.ok) return inputResult;

  const { token: inputToken, fetch, resolveHost } = inputResult.value;
  const canonicalIssuerResult = canonicalIssuer(inputToken.issuer);
  if (
    !canonicalIssuerResult.ok ||
    canonicalIssuerResult.value !== inputToken.issuer
  ) {
    return issuerError(
      "INVALID_INPUT",
      "Issuer verification requires a canonical DNS-verified issuer hostname.",
    );
  }
  if (!isSafeNetworkHostname(inputToken.issuer)) {
    return issuerError(
      "METADATA_INVALID",
      "The issuer hostname is not permitted for network access.",
    );
  }

  const authenticatedTokenResult = await reparseDnsVerifiedToken(inputToken);
  if (!authenticatedTokenResult.ok) return authenticatedTokenResult;
  const token = authenticatedTokenResult.value;

  const metadataUrl = `https://${token.issuer}/.well-known/email-verification`;

  const metadataDocument = await fetchJsonDocument({
    fetch,
    url: metadataUrl,
    issuer: token.issuer,
    kind: "metadata",
    resolveHost,
  });
  if (!metadataDocument.ok) return metadataDocument;

  const metadataResult = parseMetadata(metadataDocument.value);
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
    resolveHost,
  });
  if (!jwksDocument.ok) return jwksDocument;

  const jwksResult = parseJwks(jwksDocument.value);
  if (!jwksResult.ok) return jwksResult;

  const signatureResult = await verifyEvtSignature(
    token.token.token.evt.compact,
    algorithm,
    token.token.token.evt.header.kid,
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
  resolveHost,
}: {
  fetch: FetchFunction;
  url: string;
  issuer: string;
  kind: DocumentKind;
  resolveHost: ResolveHost;
}): Promise<Result<unknown>> {
  const target = safeHttpsUrl(
    valueWithoutAsciiControls(url),
    kind === "metadata" ? issuer : undefined,
  );
  if (target === undefined) {
    return documentError(
      kind,
      kind === "metadata"
        ? "metadata target is not a permitted issuer-bound HTTPS URL."
        : "JWKS target is not a permitted HTTPS URL.",
    );
  }

  const resolutionResult = await resolveNetworkTarget(
    resolveHost,
    target.hostname,
    kind,
  );
  if (!resolutionResult.ok) return resolutionResult;

  let responseValue: unknown;
  try {
    responseValue = await fetch(url, {
      method: "GET",
      redirect: "error",
      credentials: "omit",
    });
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
  if (response.redirected) {
    return documentError(kind, `${kind} response must not be redirected.`);
  }
  if (
    response.url !== "" &&
    safeHttpsUrl(
      valueWithoutAsciiControls(response.url),
      kind === "metadata" ? issuer : undefined,
    )?.href !== target.href
  ) {
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

function parseMetadata(value: unknown): Result<IssuerMetadata> {
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
    safeHttpsUrl(valueWithoutAsciiControls(result.data.issuance_endpoint)) ===
      undefined ||
    safeHttpsUrl(valueWithoutAsciiControls(result.data.jwks_uri)) === undefined
  ) {
    return issuerError(
      "METADATA_INVALID",
      "Issuer metadata endpoints must be permitted HTTPS URLs.",
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

function safeHttpsUrl(
  value: string | undefined,
  issuer?: string,
): URL | undefined {
  if (value === undefined) return undefined;
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.port !== ""
    ) {
      return undefined;
    }

    const hostname = url.hostname.endsWith(".")
      ? url.hostname.slice(0, -1)
      : url.hostname;
    const normalizedHostname = hostname.toLowerCase();
    if (!isSafeNetworkHostname(normalizedHostname)) return undefined;
    if (
      issuer !== undefined &&
      normalizedHostname !== issuer &&
      !normalizedHostname.endsWith(`.${issuer}`)
    ) {
      return undefined;
    }
    return url;
  } catch {
    return undefined;
  }
}

function valueWithoutAsciiControls(value: string): string | undefined {
  return containsAsciiWhitespaceOrControl(value) ? undefined : value;
}

async function resolveNetworkTarget(
  resolveHost: ResolveHost,
  hostname: string,
  kind: DocumentKind,
): Promise<Result<true>> {
  let addresses: unknown;
  try {
    addresses = await resolveHost(hostname);
  } catch (cause) {
    return fetchError(
      kind,
      `${kind} target hostname could not be resolved.`,
      cause,
    );
  }

  const validation = validateResolvedAddresses(addresses);
  if (!validation.ok) {
    return documentError(
      kind,
      `${kind} target did not resolve exclusively to globally reachable addresses.`,
    );
  }
  return ok(true);
}

async function reparseDnsVerifiedToken(
  token: z.infer<typeof DnsVerifiedTokenSchema>,
): Promise<Result<z.infer<typeof DnsVerifiedTokenSchema>>> {
  let parsedResult: Awaited<ReturnType<typeof parseToken>>;
  try {
    parsedResult = await parseToken(token.token.token.token);
  } catch (cause) {
    return issuerError(
      "INVALID_INPUT",
      "The exact token presentation could not be parsed safely.",
      cause,
    );
  }

  if (!parsedResult.ok) {
    return issuerError(
      "INVALID_INPUT",
      "The parsed token does not match the exact token presentation.",
    );
  }

  const parsedTokenMatches = safeDeepStrictEqual(
    parsedResult.value,
    token.token.token,
    "The parsed token could not be compared safely with the exact token presentation.",
  );
  if (!parsedTokenMatches.ok) return parsedTokenMatches;
  if (!parsedTokenMatches.value) {
    return issuerError(
      "INVALID_INPUT",
      "The parsed token does not match the exact token presentation.",
    );
  }

  const expectedValuesResult = validateExpectedValues({
    token: parsedResult.value,
    email: token.token.email,
    nonce: parsedResult.value.kb.claims.nonce,
    audience: token.token.audience,
    maxTokenAgeSeconds: token.token.maxTokenAgeSeconds,
    clockToleranceSeconds: token.token.clockToleranceSeconds,
    now: () => token.token.nowEpochSeconds * 1_000,
  });
  if (!expectedValuesResult.ok) {
    return issuerError(
      "INVALID_INPUT",
      "The reparsed token does not preserve expected-value validation.",
    );
  }

  const expectedValuesMatch = safeDeepStrictEqual(
    expectedValuesResult.value,
    token.token,
    "Expected-value invariants could not be compared safely.",
  );
  if (!expectedValuesMatch.ok) return expectedValuesMatch;
  if (!expectedValuesMatch.value) {
    return issuerError(
      "INVALID_INPUT",
      "The reparsed token does not preserve expected-value validation.",
    );
  }

  const claimedIssuerResult = canonicalIssuer(
    parsedResult.value.evt.claims.iss,
  );
  if (!claimedIssuerResult.ok || claimedIssuerResult.value !== token.issuer) {
    return issuerError(
      "INVALID_INPUT",
      "The reparsed EVT issuer does not match the DNS-verified issuer.",
    );
  }

  try {
    const authenticatedResult = DnsVerifiedTokenSchema.safeParse({
      issuer: claimedIssuerResult.value,
      token: expectedValuesResult.value,
    });
    if (!authenticatedResult.success) {
      return issuerError(
        "INVALID_INPUT",
        "The reparsed DNS-verified token could not be represented safely.",
      );
    }
    return ok(authenticatedResult.data);
  } catch (cause) {
    return issuerError(
      "INVALID_INPUT",
      "The reparsed DNS-verified token could not be represented safely.",
      cause,
    );
  }
}

function safeDeepStrictEqual(
  left: unknown,
  right: unknown,
  message: string,
): Result<boolean> {
  try {
    return ok(isDeepStrictEqual(left, right));
  } catch (cause) {
    return issuerError("INVALID_INPUT", message, cause);
  }
}

async function verifyEvtSignature(
  compactEvt: string,
  algorithm: string,
  keyId: string | undefined,
  jwks: JsonWebKeySet,
): Promise<Result<true>> {
  const matchingKeys = jwks.keys.filter((jwk) =>
    matchesEvtHeader(jwk, algorithm, keyId),
  );
  if (matchingKeys.length === 0) {
    return issuerError(
      "EVT_SIGNATURE_INVALID",
      "No issuer key matches the EVT protected header.",
    );
  }
  if (matchingKeys.length > MAXIMUM_MATCHING_KEYS) {
    return issuerError(
      "JWKS_INVALID",
      `More than ${String(MAXIMUM_MATCHING_KEYS)} issuer keys matched the EVT header.`,
    );
  }

  const importedKeys: Awaited<ReturnType<typeof importJWK>>[] = [];
  for (const jwk of matchingKeys) {
    try {
      importedKeys.push(await importJWK(toJoseJwk(jwk), algorithm));
    } catch (cause) {
      return issuerError(
        "JWKS_INVALID",
        "A matching issuer JWK contains invalid cryptographic key material.",
        cause,
      );
    }
  }

  for (const key of importedKeys) {
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

  return issuerError(
    "EVT_SIGNATURE_INVALID",
    "No matching issuer key verified the EVT signature.",
  );
}

function matchesEvtHeader(
  jwk: PublicJwk,
  algorithm: string,
  keyId: string | undefined,
): boolean {
  return (
    isAlgorithmCompatibleJwk(jwk, algorithm) &&
    (keyId === undefined || jwk.kid === keyId) &&
    (jwk.alg === undefined || jwk.alg === algorithm) &&
    (jwk.use === undefined || jwk.use === "sig") &&
    (jwk.key_ops === undefined || jwk.key_ops.includes("verify"))
  );
}

function isAlgorithmCompatibleJwk(jwk: PublicJwk, algorithm: string): boolean {
  switch (algorithm) {
    case "RS256":
    case "RS384":
    case "RS512":
    case "PS256":
    case "PS384":
    case "PS512":
      return jwk.kty === "RSA";
    case "ES256":
      return jwk.kty === "EC" && jwk.crv === "P-256";
    case "ES384":
      return jwk.kty === "EC" && jwk.crv === "P-384";
    case "ES512":
      return jwk.kty === "EC" && jwk.crv === "P-521";
    case "EdDSA":
    case "Ed25519":
      return jwk.kty === "OKP" && jwk.crv === "Ed25519";
    default:
      return false;
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
