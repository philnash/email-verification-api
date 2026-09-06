import * as z from "zod";
import { parseToken } from "./parse-token.js";
import {
  checkInterruption,
  createRequestControl,
  interruptionResult,
  runControlledOperation,
} from "./request-control.js";
import { err, errorCause, ok, type Result } from "./result.js";
import {
  VerifiedEmailSchema,
  VerifyEmailTokenInputSchema,
  type VerifiedEmail,
  type VerifyEmailTokenInput,
} from "./schemas.js";
import { validateExpectedValues } from "./validate-expected-values.js";
import { verifyDnsDelegationWithControl } from "./verify-dns-delegation.js";
import { verifyIssuerSignatureWithControl } from "./verify-issuer-signature.js";
import { verifyKeyBinding } from "./verify-key-binding.js";

export async function verifyEmailToken(
  input: VerifyEmailTokenInput,
): Promise<Result<VerifiedEmail>> {
  const startedAt = performance.now();
  try {
    const parsedInput = VerifyEmailTokenInputSchema.safeParse(input);
    if (!parsedInput.success) {
      return invalidInput(
        "Email token verification input is invalid.",
        z.prettifyError(parsedInput.error),
      );
    }

    const control = createRequestControl({
      ...(parsedInput.data.signal === undefined
        ? {}
        : { signal: parsedInput.data.signal }),
      timeoutMs: parsedInput.data.timeoutMs,
      startedAt,
    });
    const initialInterruption = checkInterruption(control);
    if (initialInterruption !== undefined) {
      return interruptionResult(
        "input",
        "Email token verification",
        initialInterruption,
      );
    }

    const controlledParsed = await runControlledOperation(control, null, () =>
      parseToken(parsedInput.data.token),
    );
    if (!controlledParsed.ok) {
      if ("interruption" in controlledParsed) {
        return interruptionResult(
          "parse",
          "Token parsing",
          controlledParsed.interruption,
        );
      }
      return invalidInput(
        "The token could not be parsed safely.",
        controlledParsed.cause,
      );
    }
    const parsed = controlledParsed.value;
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
    const expectedInterruption = checkInterruption(control);
    if (expectedInterruption !== undefined) {
      return interruptionResult(
        "expected-values",
        "Expected-values validation",
        expectedInterruption,
      );
    }
    if (!expected.ok) return expected;

    const delegated = await verifyDnsDelegationWithControl(
      {
        token: expected.value,
        resolveTxt: parsedInput.data.resolveTxt,
        timeoutMs: parsedInput.data.timeouts.resolveTxtMs,
      },
      control,
    );
    const dnsInterruption = checkInterruption(control);
    if (dnsInterruption !== undefined) {
      return interruptionResult("dns", "DNS verification", dnsInterruption);
    }
    if (!delegated.ok) return delegated;

    const issuerVerified = await verifyIssuerSignatureWithControl(
      {
        token: delegated.value,
        fetch: parsedInput.data.fetch,
        resolveHost: parsedInput.data.resolveHost,
        resolveHostTimeoutMs: parsedInput.data.timeouts.resolveHostMs,
        metadataFetchTimeoutMs: parsedInput.data.timeouts.metadataFetchMs,
        jwksFetchTimeoutMs: parsedInput.data.timeouts.jwksFetchMs,
      },
      control,
    );
    const issuerInterruption = checkInterruption(control);
    if (issuerInterruption !== undefined) {
      return interruptionResult(
        "issuer",
        "Issuer verification",
        issuerInterruption,
      );
    }
    if (!issuerVerified.ok) return issuerVerified;

    const controlledKeyBound = await runControlledOperation(control, null, () =>
      verifyKeyBinding({ token: issuerVerified.value }),
    );
    if (!controlledKeyBound.ok) {
      if ("interruption" in controlledKeyBound) {
        return interruptionResult(
          "key-binding",
          "Key-binding verification",
          controlledKeyBound.interruption,
        );
      }
      return invalidInput(
        "Key binding could not be verified safely.",
        controlledKeyBound.cause,
      );
    }
    const keyBound = controlledKeyBound.value;
    if (!keyBound.ok) return keyBound;

    const verifiedEmail = VerifiedEmailSchema.safeParse(keyBound.value);
    if (!verifiedEmail.success) {
      return invalidInput(
        "The authenticated email result could not be represented safely.",
        z.prettifyError(verifiedEmail.error),
      );
    }
    const finalInterruption = checkInterruption(control);
    if (finalInterruption !== undefined) {
      return interruptionResult(
        "key-binding",
        "Verified result validation",
        finalInterruption,
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
