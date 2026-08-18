import * as z from "zod";
import { parseToken } from "./parse-token.js";
import { err, errorCause, ok, type Result } from "./result.js";
import {
  VerifiedEmailSchema,
  VerifyEmailTokenInputSchema,
  type VerifiedEmail,
  type VerifyEmailTokenInput,
} from "./schemas.js";
import { validateExpectedValues } from "./validate-expected-values.js";
import { verifyDnsDelegation } from "./verify-dns-delegation.js";
import { verifyIssuerSignature } from "./verify-issuer-signature.js";
import { verifyKeyBinding } from "./verify-key-binding.js";

export async function verifyEmailToken(
  input: VerifyEmailTokenInput,
): Promise<Result<VerifiedEmail>> {
  try {
    const parsedInput = VerifyEmailTokenInputSchema.safeParse(input);
    if (!parsedInput.success) {
      return invalidInput(
        "Email token verification input is invalid.",
        z.prettifyError(parsedInput.error),
      );
    }

    const parsed = await parseToken(parsedInput.data.token);
    if (!parsed.ok) return parsed;

    const expected = validateExpectedValues({
      token: parsed.value,
      email: parsedInput.data.email,
      nonce: parsedInput.data.nonce,
      audience: parsedInput.data.audience,
      maxTokenAgeSeconds: parsedInput.data.maxTokenAgeSeconds,
      clockToleranceSeconds: parsedInput.data.clockToleranceSeconds,
      now: parsedInput.data.now,
    });
    if (!expected.ok) return expected;

    const delegated = await verifyDnsDelegation({
      token: expected.value,
      resolveTxt: parsedInput.data.resolveTxt,
    });
    if (!delegated.ok) return delegated;

    const issuerVerified = await verifyIssuerSignature({
      token: delegated.value,
      fetch: parsedInput.data.fetch,
      resolveHost: parsedInput.data.resolveHost,
    });
    if (!issuerVerified.ok) return issuerVerified;

    const keyBound = await verifyKeyBinding({ token: issuerVerified.value });
    if (!keyBound.ok) return keyBound;

    const verifiedEmail = VerifiedEmailSchema.safeParse(keyBound.value);
    if (!verifiedEmail.success) {
      return invalidInput(
        "The authenticated email result could not be represented safely.",
        z.prettifyError(verifiedEmail.error),
      );
    }
    return ok(verifiedEmail.data);
  } catch (cause) {
    return invalidInput(
      "Email token verification could not complete safely.",
      cause,
    );
  }
}

function invalidInput(message: string, cause?: unknown): Result<never> {
  return err({
    stage: "input",
    code: "INVALID_INPUT",
    message,
    ...(cause === undefined ? {} : { cause: errorCause(cause) }),
  });
}
