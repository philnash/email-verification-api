import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createRequestControl,
  runControlledOperation,
} from "../src/request-control.js";

void describe("request control", () => {
  void it("leaves an operation unbounded when both limits are null", async () => {
    const result = await runControlledOperation(
      createRequestControl({ timeoutMs: null }),
      null,
      (signal) => {
        assert.equal(signal.aborted, false);
        return Promise.resolve("complete");
      },
    );
    assert.deepEqual(result, { ok: true, value: "complete" });
  });

  void it("classifies caller cancellation separately from timeout", async () => {
    const controller = new AbortController();
    const pending = runControlledOperation(
      createRequestControl({ signal: controller.signal, timeoutMs: null }),
      null,
      () => new Promise<never>(() => undefined),
    );
    controller.abort("DO_NOT_EXPOSE");
    assert.deepEqual(await pending, {
      ok: false,
      interruption: "aborted",
    });

    const timedOut = await runControlledOperation(
      createRequestControl({ timeoutMs: null }),
      1,
      () => new Promise<never>(() => undefined),
    );
    assert.deepEqual(timedOut, {
      ok: false,
      interruption: "timeout",
    });
  });

  void it("prefers caller cancellation at a checkpoint", async () => {
    const controller = new AbortController();
    controller.abort();
    const result = await runControlledOperation(
      createRequestControl({
        signal: controller.signal,
        timeoutMs: 1,
        startedAt: Number.NEGATIVE_INFINITY,
      }),
      1,
      () => Promise.resolve("must not run"),
    );
    assert.deepEqual(result, {
      ok: false,
      interruption: "aborted",
    });
  });

  void it("does not start the operation when cancellation occurs during listener setup", async () => {
    const controller = new AbortController();
    const signal = controller.signal;
    const addEventListener = signal.addEventListener.bind(signal);
    Object.defineProperty(signal, "addEventListener", {
      value: (...args: Parameters<AbortSignal["addEventListener"]>) => {
        addEventListener(...args);
        controller.abort();
      },
    });
    let operationStarted = false;

    const result = await runControlledOperation(
      createRequestControl({ signal, timeoutMs: null }),
      null,
      () => {
        operationStarted = true;
        return Promise.resolve("must not run");
      },
    );

    assert.deepEqual(result, { ok: false, interruption: "aborted" });
    assert.equal(operationStarted, false);
  });

  void it("does not start a deferred operation after immediate cancellation", async () => {
    const controller = new AbortController();
    let operationCalls = 0;
    const pending = runControlledOperation(
      createRequestControl({ signal: controller.signal, timeoutMs: null }),
      null,
      () => {
        operationCalls += 1;
        return Promise.resolve("must not run");
      },
    );

    controller.abort();

    assert.deepEqual(await pending, {
      ok: false,
      interruption: "aborted",
    });
    assert.equal(operationCalls, 0);
  });

  void it("prefers caller cancellation when a timeout makes both observable", async () => {
    const controller = new AbortController();
    const result = await runControlledOperation(
      createRequestControl({ signal: controller.signal, timeoutMs: null }),
      1,
      (signal) =>
        new Promise<never>(() => {
          signal.addEventListener(
            "abort",
            () => {
              controller.abort();
            },
            { once: true },
          );
        }),
    );

    assert.deepEqual(result, { ok: false, interruption: "aborted" });
  });

  void it("does not start a deferred operation after its deadline", async () => {
    let operationCalls = 0;
    const pending = runControlledOperation(
      createRequestControl({ timeoutMs: null }),
      1,
      () => {
        operationCalls += 1;
        return Promise.resolve("must not run");
      },
    );
    const blockedUntil = performance.now() + 5;
    while (performance.now() < blockedUntil) {
      // Keep the operation microtask queued until its deadline has passed.
    }

    assert.deepEqual(await pending, {
      ok: false,
      interruption: "timeout",
    });
    assert.equal(operationCalls, 0);
  });
});
