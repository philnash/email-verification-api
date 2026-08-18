import * as z from "zod";
import { err, errorCause, ok, type Result } from "./result.js";
import {
  ExpectedValuesInputSchema,
  ExpectedValuesValidatedTokenSchema,
  type ExpectedValuesValidatedToken,
} from "./schemas.js";

const ClockResultSchema = z.number().nonnegative();

export function validateExpectedValues(
  input: unknown,
): Result<ExpectedValuesValidatedToken> {
  const inputResult = parseInput(input);
  if (!inputResult.ok) return inputResult;
  const inputValues = inputResult.value;

  const clockResult = readClock(inputValues.now);
  if (!clockResult.ok) return clockResult;

  const { token } = inputValues;
  const expectedEmail = inputValues.email.toLowerCase();
  if (expectedEmail !== token.evt.claims.email.toLowerCase()) {
    return err({
      stage: "expected-values",
      code: "EMAIL_MISMATCH",
      message: "The expected email does not match the token email.",
    });
  }

  if (!token.evt.claims.email_verified) {
    return err({
      stage: "expected-values",
      code: "EMAIL_NOT_VERIFIED",
      message: "The token does not assert that the email is verified.",
    });
  }

  if (inputValues.nonce !== token.kb.claims.nonce) {
    return err({
      stage: "expected-values",
      code: "NONCE_MISMATCH",
      message: "The expected nonce does not match the KB-JWT nonce.",
    });
  }

  const expectedAudience = canonicalOrigin(inputValues.audience);
  if (!expectedAudience.ok) return expectedAudience;
  const tokenAudience = canonicalOrigin(token.kb.claims.aud);
  if (!tokenAudience.ok) return tokenAudience;
  if (expectedAudience.value !== tokenAudience.value) {
    return err({
      stage: "expected-values",
      code: "AUDIENCE_MISMATCH",
      message: "The expected audience does not match the KB-JWT audience.",
    });
  }

  const nowEpochSeconds = Math.floor(clockResult.value / 1_000);
  const evtTimeResult = validateIssuedAt(
    "EVT",
    token.evt.claims.iat,
    nowEpochSeconds,
    inputValues.maxTokenAgeSeconds,
    inputValues.clockToleranceSeconds,
  );
  if (!evtTimeResult.ok) return evtTimeResult;

  const kbTimeResult = validateIssuedAt(
    "KB-JWT",
    token.kb.claims.iat,
    nowEpochSeconds,
    inputValues.maxTokenAgeSeconds,
    inputValues.clockToleranceSeconds,
  );
  if (!kbTimeResult.ok) return kbTimeResult;

  const validatedResult = ExpectedValuesValidatedTokenSchema.safeParse({
    token,
    email: expectedEmail,
    audience: expectedAudience.value,
    maxTokenAgeSeconds: inputValues.maxTokenAgeSeconds,
    clockToleranceSeconds: inputValues.clockToleranceSeconds,
    nowEpochSeconds,
  });
  if (!validatedResult.success) {
    return invalidInput(
      "The validated expected values could not be represented safely.",
      validatedResult.error,
    );
  }

  return ok(validatedResult.data);
}

function parseInput(
  input: unknown,
): Result<z.infer<typeof ExpectedValuesInputSchema>> {
  try {
    const result = ExpectedValuesInputSchema.safeParse(input);
    if (!result.success) {
      return invalidInput(
        "Expected values must include a parsed token, email, nonce, audience, and valid timing options.",
        result.error,
      );
    }
    return ok(result.data);
  } catch (cause) {
    return invalidInput("Expected values could not be read safely.", cause);
  }
}

function readClock(now: () => unknown): Result<number> {
  try {
    const result = ClockResultSchema.safeParse(now());
    if (!result.success) {
      return invalidInput(
        "The clock must return a finite, nonnegative Unix-millisecond value.",
        result.error,
      );
    }
    return ok(result.data);
  } catch (cause) {
    return invalidInput(
      "The clock failed while reading the current time.",
      cause,
    );
  }
}

function canonicalOrigin(value: string): Result<string> {
  try {
    const parsed = new URL(value);
    if (
      (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
      parsed.href !== `${parsed.origin}/`
    ) {
      return invalidAudience();
    }
    return ok(parsed.origin);
  } catch {
    return invalidAudience();
  }
}

function validateIssuedAt(
  tokenName: "EVT" | "KB-JWT",
  issuedAt: number,
  nowEpochSeconds: number,
  maxTokenAgeSeconds: number,
  clockToleranceSeconds: number,
): Result<undefined> {
  const ageSeconds = nowEpochSeconds - issuedAt;
  if (ageSeconds > maxTokenAgeSeconds + clockToleranceSeconds) {
    return err({
      stage: "expected-values",
      code: "TOKEN_EXPIRED",
      message: `The ${tokenName} issued-at time is older than the allowed token age.`,
    });
  }
  if (ageSeconds < -clockToleranceSeconds) {
    return err({
      stage: "expected-values",
      code: "TOKEN_NOT_YET_VALID",
      message: `The ${tokenName} issued-at time is later than the allowed clock tolerance.`,
    });
  }
  return ok(undefined);
}

function invalidAudience(): Result<never> {
  return err({
    stage: "expected-values",
    code: "AUDIENCE_MISMATCH",
    message:
      "Audience must be an HTTP(S) origin without credentials, path, query, or fragment.",
  });
}

function invalidInput(message: string, cause?: unknown): Result<never> {
  return err({
    stage: "expected-values",
    code: "INVALID_INPUT",
    message,
    ...(cause === undefined ? {} : { cause: errorCause(cause) }),
  });
}
