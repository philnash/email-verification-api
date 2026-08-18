import * as z from "zod";

export const VerificationStageSchema = z.enum([
  "input",
  "parse",
  "expected-values",
  "dns",
  "issuer",
  "key-binding",
]);

export const VerificationErrorCodeSchema = z.enum([
  "INVALID_INPUT",
  "TOKEN_MALFORMED",
  "DISCLOSURE_INVALID",
  "EMAIL_MISMATCH",
  "EMAIL_NOT_VERIFIED",
  "NONCE_MISMATCH",
  "AUDIENCE_MISMATCH",
  "TOKEN_EXPIRED",
  "TOKEN_NOT_YET_VALID",
  "DNS_LOOKUP_FAILED",
  "DNS_DELEGATION_MISSING",
  "DNS_DELEGATION_AMBIGUOUS",
  "ISSUER_MISMATCH",
  "METADATA_FETCH_FAILED",
  "METADATA_INVALID",
  "JWKS_FETCH_FAILED",
  "JWKS_INVALID",
  "ALGORITHM_UNSUPPORTED",
  "EVT_SIGNATURE_INVALID",
  "KB_SIGNATURE_INVALID",
  "SD_HASH_MISMATCH",
]);

export const VerificationErrorSchema = z.object({
  stage: VerificationStageSchema,
  code: VerificationErrorCodeSchema,
  message: z.string().min(1),
  cause: z.string().min(1).optional(),
});

export type VerificationStage = z.infer<typeof VerificationStageSchema>;
export type VerificationErrorCode = z.infer<typeof VerificationErrorCodeSchema>;
export type VerificationError = z.infer<typeof VerificationErrorSchema>;

export type Result<T, E = VerificationError> =
  { ok: true; value: T } | { ok: false; error: E };

const UNKNOWN_ERROR_CAUSE = "Unknown error";

export const ok = <T>(value: T): Result<T, never> => ({ ok: true, value });
export const err = <E>(error: E): Result<never, E> => ({ ok: false, error });
export const isOk = <T, E>(
  result: Result<T, E>,
): result is { ok: true; value: T } => result.ok;
export const isErr = <T, E>(
  result: Result<T, E>,
): result is { ok: false; error: E } => !result.ok;

export function errorCause(cause: unknown): string {
  try {
    if (cause instanceof Error) {
      try {
        const message: unknown = cause.message;
        return typeof message === "string" ? message : UNKNOWN_ERROR_CAUSE;
      } catch {
        return UNKNOWN_ERROR_CAUSE;
      }
    }
  } catch {
    return UNKNOWN_ERROR_CAUSE;
  }

  if (typeof cause === "string") return cause;
  try {
    const serializedCause: unknown = JSON.stringify(cause);
    return typeof serializedCause === "string"
      ? serializedCause
      : String(cause);
  } catch {
    try {
      return String(cause);
    } catch {
      return UNKNOWN_ERROR_CAUSE;
    }
  }
}
