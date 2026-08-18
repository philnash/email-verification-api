import { timingSafeEqual } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { base64UrlToUint8Array, uint8ArrayToBase64Url } from "@sd-jwt/core";
import { compactVerify, importJWK, type JWK } from "jose";
import * as z from "zod";
import { hashFunction } from "./hash.js";
import { parseToken } from "./parse-token.js";
import { err, errorCause, ok, type Result } from "./result.js";
import {
  IssuerVerifiedTokenSchema,
  KeyBindingVerifiedTokenSchema,
  type IssuerVerifiedToken,
  type KeyBindingVerifiedToken,
  type ParsedToken,
  type PublicJwk,
} from "./schemas.js";
import { canonicalIssuer } from "./verify-dns-delegation.js";

const VerifyKeyBindingInputSchema = z.object({
  token: IssuerVerifiedTokenSchema,
});

export async function verifyKeyBinding(
  input: unknown,
): Promise<Result<KeyBindingVerifiedToken>> {
  const inputResult = parseInput(input);
  if (!inputResult.ok) return inputResult;

  const token = inputResult.value.token;
  const parsedTokenResult = await reparseExactToken(token);
  if (!parsedTokenResult.ok) return parsedTokenResult;
  const parsedToken = parsedTokenResult.value;

  const signatureResult = await verifyHolderSignature(parsedToken);
  if (!signatureResult.ok) return signatureResult;

  const hashResult = await verifyPresentationHash(parsedToken);
  if (!hashResult.ok) return hashResult;

  const issuerResult = canonicalAuthenticatedIssuer(parsedToken);
  if (!issuerResult.ok) return issuerResult;
  const audienceResult = canonicalAuthenticatedAudience(parsedToken);
  if (!audienceResult.ok) return audienceResult;

  try {
    const result = KeyBindingVerifiedTokenSchema.safeParse({
      email: parsedToken.evt.claims.email,
      issuer: issuerResult.value,
      audience: audienceResult.value,
      issuedAt: {
        evt: parsedToken.evt.claims.iat,
        keyBinding: parsedToken.kb.claims.iat,
      },
      claims: parsedToken.evt.claims,
    });
    if (!result.success) {
      return keyBindingError(
        "INVALID_INPUT",
        "The key-binding-verified token could not be represented safely.",
      );
    }
    return ok(result.data);
  } catch (cause) {
    return keyBindingError(
      "INVALID_INPUT",
      "The key-binding-verified token could not be represented safely.",
      cause,
    );
  }
}

function parseInput(
  input: unknown,
): Result<z.infer<typeof VerifyKeyBindingInputSchema>> {
  try {
    const result = VerifyKeyBindingInputSchema.safeParse(input);
    if (!result.success) {
      return keyBindingError(
        "INVALID_INPUT",
        "Key-binding verification requires an issuer-verified token.",
      );
    }
    return ok(result.data);
  } catch (cause) {
    return keyBindingError(
      "INVALID_INPUT",
      "Key-binding verification input could not be read safely.",
      cause,
    );
  }
}

async function reparseExactToken(
  token: IssuerVerifiedToken,
): Promise<Result<ParsedToken>> {
  const stagedToken = token.token.token.token;
  let parsedResult: Awaited<ReturnType<typeof parseToken>>;
  try {
    parsedResult = await parseToken(stagedToken.token);
  } catch (cause) {
    return keyBindingError(
      "INVALID_INPUT",
      "The exact token presentation could not be parsed safely.",
      cause,
    );
  }

  if (!parsedResult.ok) {
    return keyBindingError(
      "INVALID_INPUT",
      "The issuer-verified token does not match its exact presentation.",
    );
  }

  try {
    if (!isDeepStrictEqual(parsedResult.value, stagedToken)) {
      return keyBindingError(
        "INVALID_INPUT",
        "The issuer-verified token does not match its exact presentation.",
      );
    }
  } catch (cause) {
    return keyBindingError(
      "INVALID_INPUT",
      "The issuer-verified token could not be compared safely with its exact presentation.",
      cause,
    );
  }

  return ok(parsedResult.value);
}

function canonicalAuthenticatedIssuer(token: ParsedToken): Result<string> {
  const result = canonicalIssuer(token.evt.claims.iss);
  if (!result.ok) {
    return keyBindingError(
      "INVALID_INPUT",
      "The authenticated EVT issuer is invalid.",
    );
  }
  return result;
}

function canonicalAuthenticatedAudience(token: ParsedToken): Result<string> {
  try {
    const audience = new URL(token.kb.claims.aud);
    if (
      (audience.protocol !== "https:" && audience.protocol !== "http:") ||
      audience.href !== `${audience.origin}/`
    ) {
      return invalidAuthenticatedAudience();
    }
    return ok(audience.origin);
  } catch {
    return invalidAuthenticatedAudience();
  }
}

function invalidAuthenticatedAudience(): Result<never> {
  return keyBindingError(
    "INVALID_INPUT",
    "The authenticated KB-JWT audience is not an HTTP(S) origin.",
  );
}

async function verifyHolderSignature(
  token: ParsedToken,
): Promise<Result<true>> {
  const algorithm = token.kb.header.alg;
  const holderJwk = token.evt.claims.cnf.jwk;
  if (!isHolderKeyAllowed(holderJwk, algorithm)) {
    return keyBindingError(
      "KB_SIGNATURE_INVALID",
      "The authenticated holder key is not compatible with the KB-JWT algorithm.",
    );
  }

  let holderKey: Awaited<ReturnType<typeof importJWK>>;
  try {
    holderKey = await importJWK(toJoseJwk(holderJwk), algorithm);
  } catch (cause) {
    return keyBindingError(
      "KB_SIGNATURE_INVALID",
      "The authenticated holder JWK contains invalid cryptographic key material.",
      cause,
    );
  }

  try {
    await compactVerify(token.kb.compact, holderKey, {
      algorithms: [algorithm],
    });
    return ok(true);
  } catch (cause) {
    return keyBindingError(
      "KB_SIGNATURE_INVALID",
      "The KB-JWT signature is invalid.",
      cause,
    );
  }
}

async function verifyPresentationHash(
  token: ParsedToken,
): Promise<Result<true>> {
  let expectedHash: string;
  try {
    const digest = await hashFunction(token.presentation, "sha-256");
    expectedHash = uint8ArrayToBase64Url(digest);
  } catch (cause) {
    return keyBindingError(
      "SD_HASH_MISMATCH",
      "The exact SD-JWT presentation could not be hashed safely.",
      cause,
    );
  }

  try {
    const expectedBytes = base64UrlToUint8Array(expectedHash);
    const actualBytes = base64UrlToUint8Array(token.kb.claims.sd_hash);
    if (
      expectedBytes.byteLength !== actualBytes.byteLength ||
      !timingSafeEqual(expectedBytes, actualBytes)
    ) {
      return keyBindingError(
        "SD_HASH_MISMATCH",
        "The KB-JWT sd_hash does not match the exact SD-JWT presentation.",
      );
    }
    return ok(true);
  } catch (cause) {
    return keyBindingError(
      "SD_HASH_MISMATCH",
      "The KB-JWT sd_hash could not be compared safely.",
      cause,
    );
  }
}

function isHolderKeyAllowed(jwk: PublicJwk, algorithm: string): boolean {
  return (
    isAlgorithmCompatibleJwk(jwk, algorithm) &&
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

function keyBindingError(
  code: "INVALID_INPUT" | "KB_SIGNATURE_INVALID" | "SD_HASH_MISMATCH",
  message: string,
  cause?: unknown,
): Result<never> {
  return err({
    stage: "key-binding",
    code,
    message,
    ...(cause === undefined ? {} : { cause: errorCause(cause) }),
  });
}
