import { err, type Result, type VerificationStage } from "./result.js";

export type RequestInterruption = "aborted" | "timeout";

export interface RequestControl {
  signal?: AbortSignal;
  deadlineAt?: number;
}

interface InterruptionState {
  value?: RequestInterruption;
}

export type ControlledOperationResult<T> =
  | { ok: true; value: T }
  | { ok: false; interruption: RequestInterruption }
  | { ok: false; cause: unknown };

const INTERRUPTED = Object.freeze({ interrupted: true });
const MAX_TIMER_DELAY_MS = 2_147_483_647;

export function createRequestControl({
  signal,
  timeoutMs,
  startedAt = performance.now(),
}: {
  signal?: AbortSignal;
  timeoutMs: number | null;
  startedAt?: number;
}): RequestControl {
  return {
    ...(signal === undefined ? {} : { signal }),
    ...(timeoutMs === null ? {} : { deadlineAt: startedAt + timeoutMs }),
  };
}

export function checkInterruption(
  control: RequestControl,
): RequestInterruption | undefined {
  if (control.signal?.aborted) return "aborted";
  if (
    control.deadlineAt !== undefined &&
    performance.now() >= control.deadlineAt
  ) {
    return "timeout";
  }
  return undefined;
}

export async function runControlledOperation<T>(
  control: RequestControl,
  timeoutMs: number | null,
  operation: (signal: AbortSignal) => PromiseLike<T>,
): Promise<ControlledOperationResult<T>> {
  const initial = checkInterruption(control);
  if (initial !== undefined) return { ok: false, interruption: initial };

  const operationController = new AbortController();
  const interruption: InterruptionState = {};
  let resolveInterruption!: (value: typeof INTERRUPTED) => void;
  const interrupted = new Promise<typeof INTERRUPTED>((resolve) => {
    resolveInterruption = resolve;
  });
  const getInterruption = (): RequestInterruption | undefined =>
    interruption.value;
  const interrupt = (next: RequestInterruption) => {
    if (interruption.value !== undefined) return;
    interruption.value = next;
    resolveInterruption(INTERRUPTED);
    operationController.abort();
  };
  const onCallerAbort = () => {
    interrupt("aborted");
  };
  control.signal?.addEventListener("abort", onCallerAbort, { once: true });
  if (control.signal?.aborted) onCallerAbort();
  const registrationInterruption = getInterruption();
  if (registrationInterruption !== undefined) {
    control.signal?.removeEventListener("abort", onCallerAbort);
    return { ok: false, interruption: registrationInterruption };
  }

  const operationDeadlineAt =
    timeoutMs === null ? undefined : performance.now() + timeoutMs;
  const effectiveDeadlineAt =
    control.deadlineAt === undefined
      ? operationDeadlineAt
      : operationDeadlineAt === undefined
        ? control.deadlineAt
        : Math.min(control.deadlineAt, operationDeadlineAt);
  if (
    effectiveDeadlineAt !== undefined &&
    effectiveDeadlineAt <= performance.now()
  ) {
    control.signal?.removeEventListener("abort", onCallerAbort);
    return {
      ok: false,
      interruption: control.signal?.aborted ? "aborted" : "timeout",
    };
  }
  const checkEffectiveInterruption = (): RequestInterruption | undefined => {
    if (control.signal?.aborted) return "aborted";
    if (
      effectiveDeadlineAt !== undefined &&
      performance.now() >= effectiveDeadlineAt
    ) {
      return "timeout";
    }
    return getInterruption();
  };

  let timer: NodeJS.Timeout | undefined;
  const scheduleDeadline = () => {
    if (effectiveDeadlineAt === undefined) return;
    const remaining = effectiveDeadlineAt - performance.now();
    if (remaining <= 0) {
      interrupt("timeout");
      return;
    }
    timer = setTimeout(
      scheduleDeadline,
      Math.min(remaining, MAX_TIMER_DELAY_MS),
    );
  };
  scheduleDeadline();

  try {
    const raced = await Promise.race([
      Promise.resolve().then<T | typeof INTERRUPTED>(() => {
        const deferredInterruption = checkEffectiveInterruption();
        if (deferredInterruption !== undefined) {
          interrupt(deferredInterruption);
          return INTERRUPTED;
        }
        return operation(operationController.signal);
      }),
      interrupted,
    ]);
    if (raced === INTERRUPTED) {
      const currentInterruption = getInterruption();
      return {
        ok: false,
        interruption: control.signal?.aborted
          ? "aborted"
          : (currentInterruption ?? "timeout"),
      };
    }
    if (control.signal?.aborted) {
      return { ok: false, interruption: "aborted" };
    }
    const currentInterruption = checkEffectiveInterruption();
    if (currentInterruption !== undefined) {
      return {
        ok: false,
        interruption: currentInterruption,
      };
    }
    return { ok: true, value: raced as T };
  } catch (cause) {
    if (control.signal?.aborted) {
      return { ok: false, interruption: "aborted" };
    }
    const currentInterruption = checkEffectiveInterruption();
    if (currentInterruption !== undefined) {
      return { ok: false, interruption: currentInterruption };
    }
    return { ok: false, cause };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    control.signal?.removeEventListener("abort", onCallerAbort);
  }
}

export function interruptionResult(
  stage: VerificationStage,
  operation: string,
  interruption: RequestInterruption,
): Result<never> {
  return err({
    stage,
    code: interruption === "aborted" ? "REQUEST_ABORTED" : "REQUEST_TIMEOUT",
    message:
      interruption === "aborted"
        ? `${operation} was aborted by the caller.`
        : `${operation} timed out.`,
  });
}
