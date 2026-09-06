# External Request Timeouts and Cancellation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in overall and per-operation timeouts plus caller-driven cancellation to every external verification operation, with distinct `REQUEST_TIMEOUT` and `REQUEST_ABORTED` results and complete README documentation.

**Architecture:** Add a focused request-control module that tracks caller cancellation, an optional monotonic overall deadline, and an optional operation deadline. Public input schemas normalize omitted and `null` timeout values to no limit; DNS and issuer stages run external promises through the shared controller, while `verifyEmailToken()` owns the overall control context and passes it through internal stage entry points.

**Tech Stack:** TypeScript 6, Node.js 20+, Fetch and AbortController APIs, Zod 4, `node:test`, `jose` 6.

## Global Constraints

- Every timeout is opt-in and defaults to `null`.
- Numeric timeouts are positive finite integer milliseconds; invalid timeout and signal inputs return `INVALID_INPUT` rather than throwing.
- Caller cancellation returns `REQUEST_ABORTED`; a deadline returns `REQUEST_TIMEOUT`.
- Caller cancellation wins when both cancellation and timeout are observable at the same checkpoint.
- Fetch and response-body reading are actively aborted; non-abortable DNS work may continue but its late settlement must be safely ignored.
- Preserve DNS, metadata, JWKS, EVT, and key-binding trust order and all existing SSRF checks.
- Preserve the public non-throwing `Result` API and do not expose response bodies or arbitrary abort reasons.
- Add no runtime dependencies; the package must retain exactly `@sd-jwt/core`, `jose`, and `zod`.
- Document all new options and the recommended 10s/2s/2s/4s/4s interactive profile in `README.md`.

---

## File Structure

- Create `src/request-control.ts`: monotonic overall deadline, operation racing, composed abort signal, interruption classification, and cleanup.
- Create `test/request-control.test.ts`: deterministic unit coverage for the request-control primitive.
- Modify `src/schemas.ts`: timeout and signal schemas, the public `ExternalRequestTimeouts` type, and normalized orchestrator input.
- Modify `src/result.ts`: add the two public error codes.
- Modify `src/index.ts`: export the new public timeout schema and type.
- Modify `src/verify-dns-delegation.ts`: public stage options plus controlled TXT resolution.
- Modify `src/verify-issuer-signature.ts`: public stage options plus controlled hostname resolution and fetch/body reads.
- Modify `src/verify-token.ts`: create and propagate the overall request-control context and check local async stages.
- Modify `test/verify-dns-delegation.test.ts`, `test/verify-issuer-signature.test.ts`, `test/verify-token.test.ts`, and `test/public-types.test.ts`: stage, orchestration, schema, and public API coverage.
- Modify `README.md`: API table, examples, error codes, recommended policy, and DNS cancellation limitation.

### Task 1: Request-control primitive and public configuration

**Files:**
- Create: `src/request-control.ts`
- Create: `test/request-control.test.ts`
- Modify: `src/schemas.ts:135-187,242-279`
- Modify: `src/result.ts:1-35`
- Modify: `src/index.ts:1-58`
- Test: `test/verify-token.test.ts:176-188`
- Test: `test/public-types.test.ts:1-145`

**Interfaces:**
- Produces: `ExternalRequestTimeoutsSchema` and `ExternalRequestTimeouts` with the four optional nullable millisecond fields.
- Produces internally: `TimeoutMillisecondsSchema`, `AbortSignalSchema`, and `NormalizedExternalRequestTimeouts`.
- Produces internally: `createRequestControl(options): RequestControl`, `checkInterruption(control): RequestInterruption | undefined`, `runControlledOperation(control, timeoutMs, operation): Promise<ControlledOperationResult<T>>`, and `interruptionResult(stage, operation, interruption): Result<never>`.
- Produces publicly: error codes `REQUEST_ABORTED` and `REQUEST_TIMEOUT`.

- [ ] **Step 1: Write failing request-control and schema tests**

Create `test/request-control.test.ts` with focused cases using a deferred promise rather than real network access:

```ts
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
      async (signal) => {
        assert.equal(signal.aborted, false);
        return "complete";
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
});
```

Extend the documented-default test in `test/verify-token.test.ts` to assert that `signal` is absent, `timeoutMs === null`, and every normalized `timeouts` field is `null`. Extend `test/public-types.test.ts` to import and exercise `ExternalRequestTimeoutsSchema`, `ExternalRequestTimeouts`, and both new error-code literals. Add explicit non-export assertions:

```ts
// @ts-expect-error createRequestControl is an internal primitive.
assert.equal(publicApi.createRequestControl, undefined);
// @ts-expect-error runControlledOperation is an internal primitive.
assert.equal(publicApi.runControlledOperation, undefined);
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
npm run test:compile
node --test --test-name-pattern='request control|documented defaults|public API' .test-dist/test/request-control.test.js .test-dist/test/verify-token.test.js .test-dist/test/public-types.test.js
```

Expected: compilation fails because the request-control module, timeout schema/type, and error codes do not exist.

- [ ] **Step 3: Add timeout/signal schemas and error codes**

Add this shape to `src/schemas.ts`, keeping normalization separate from the public partial input type:

```ts
export const TimeoutMillisecondsSchema = z.number().int().positive().nullable();
export const AbortSignalSchema = z.custom<AbortSignal>(
  (value) => value instanceof AbortSignal,
);

export const ExternalRequestTimeoutsSchema = z.object({
  resolveTxtMs: TimeoutMillisecondsSchema.optional(),
  resolveHostMs: TimeoutMillisecondsSchema.optional(),
  metadataFetchMs: TimeoutMillisecondsSchema.optional(),
  jwksFetchMs: TimeoutMillisecondsSchema.optional(),
});

export type ExternalRequestTimeouts = z.input<
  typeof ExternalRequestTimeoutsSchema
>;
export type NormalizedExternalRequestTimeouts = {
  resolveTxtMs: number | null;
  resolveHostMs: number | null;
  metadataFetchMs: number | null;
  jwksFetchMs: number | null;
};

function normalizeExternalRequestTimeouts(
  value: ExternalRequestTimeouts | null | undefined,
): NormalizedExternalRequestTimeouts {
  return {
    resolveTxtMs: value?.resolveTxtMs ?? null,
    resolveHostMs: value?.resolveHostMs ?? null,
    metadataFetchMs: value?.metadataFetchMs ?? null,
    jwksFetchMs: value?.jwksFetchMs ?? null,
  };
}
```

Add these fields to `VerifyEmailTokenInputSchema`:

```ts
signal: AbortSignalSchema.optional(),
timeoutMs: TimeoutMillisecondsSchema.optional().transform(
  (value) => value ?? null,
),
timeouts: ExternalRequestTimeoutsSchema.nullable()
  .optional()
  .transform(normalizeExternalRequestTimeouts),
```

Add `REQUEST_ABORTED` and `REQUEST_TIMEOUT` to `VerificationErrorCodeSchema`. Export `ExternalRequestTimeoutsSchema` and the `ExternalRequestTimeouts` type from `src/index.ts`.

- [ ] **Step 4: Implement the request-control primitive**

Create `src/request-control.ts`. Use one internal controller per operation so Fetch always receives a real signal, and race the operation even if it ignores that signal:

```ts
import { err, type Result, type VerificationStage } from "./result.js";

export type RequestInterruption = "aborted" | "timeout";

export type RequestControl = {
  signal?: AbortSignal;
  deadlineAt?: number;
};

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
  let interruption: RequestInterruption | undefined;
  let resolveInterruption!: (value: typeof INTERRUPTED) => void;
  const interrupted = new Promise<typeof INTERRUPTED>((resolve) => {
    resolveInterruption = resolve;
  });
  const interrupt = (next: RequestInterruption) => {
    if (interruption !== undefined) return;
    interruption = next;
    resolveInterruption(INTERRUPTED);
    operationController.abort();
  };
  const onCallerAbort = () => interrupt("aborted");
  control.signal?.addEventListener("abort", onCallerAbort, { once: true });
  if (control.signal?.aborted) onCallerAbort();

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
      Promise.resolve().then(() => operation(operationController.signal)),
      interrupted,
    ]);
    if (raced === INTERRUPTED) {
      return { ok: false, interruption: interruption ?? "timeout" };
    }
    if (control.signal?.aborted) {
      return { ok: false, interruption: "aborted" };
    }
    if (
      interruption !== undefined ||
      (effectiveDeadlineAt !== undefined &&
        performance.now() >= effectiveDeadlineAt)
    ) {
      return { ok: false, interruption: interruption ?? "timeout" };
    }
    return { ok: true, value: raced as T };
  } catch (cause) {
    if (control.signal?.aborted) {
      return { ok: false, interruption: "aborted" };
    }
    if (interruption !== undefined) {
      return { ok: false, interruption: interruption ?? "timeout" };
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
    code:
      interruption === "aborted" ? "REQUEST_ABORTED" : "REQUEST_TIMEOUT",
    message:
      interruption === "aborted"
        ? `${operation} was aborted by the caller.`
        : `${operation} timed out.`,
  });
}
```

During implementation, keep the `startedAt` test seam internal to this module's exports and do not re-export it from `src/index.ts`.

- [ ] **Step 5: Run focused and regression tests**

Run:

```bash
npx prettier --write src/request-control.ts src/schemas.ts src/result.ts src/index.ts test/request-control.test.ts test/verify-token.test.ts test/public-types.test.ts
npm run test:compile
node --test .test-dist/test/request-control.test.js .test-dist/test/result.test.js .test-dist/test/public-types.test.js .test-dist/test/verify-token.test.js
```

Expected: all selected tests pass, including the existing error schema and public surface tests.

- [ ] **Step 6: Commit the foundation**

```bash
git add src/request-control.ts src/schemas.ts src/result.ts src/index.ts test/request-control.test.ts test/verify-token.test.ts test/public-types.test.ts
git commit -m "feat: add verification request controls"
```

### Task 2: DNS timeout and cancellation

**Files:**
- Modify: `src/verify-dns-delegation.ts:1-24,62-81,159-201`
- Test: `test/verify-dns-delegation.test.ts:47-361`

**Interfaces:**
- Consumes: `RequestControl`, `createRequestControl`, `runControlledOperation`, `interruptionResult`, `AbortSignalSchema`, and `TimeoutMillisecondsSchema` from Task 1.
- Produces publicly: `verifyDnsDelegation({ token, resolveTxt?, signal?, timeoutMs? })`, where `timeoutMs` defaults to `null` and controls only TXT resolution.
- Produces internally: `verifyDnsDelegationWithControl(input, control)` for the orchestrator in Task 4.

- [ ] **Step 1: Write failing DNS timeout and cancellation tests**

Add tests that prove timeout, cancellation, opt-out, and safe late settlement:

```ts
void it("times out TXT resolution without starting later work", async () => {
  const validated = await createValidatedToken();
  const result = await verifyDnsDelegation({
    token: validated,
    timeoutMs: 1,
    resolveTxt: () => new Promise<string[][]>(() => undefined),
  });
  assertErrorCode(result, "REQUEST_TIMEOUT");
});

void it("aborts TXT resolution and ignores a late rejection", async () => {
  const validated = await createValidatedToken();
  const controller = new AbortController();
  let rejectLookup!: (cause: unknown) => void;
  const pending = verifyDnsDelegation({
    token: validated,
    signal: controller.signal,
    timeoutMs: null,
    resolveTxt: () =>
      new Promise<string[][]>((_resolve, reject) => {
        rejectLookup = reject;
      }),
  });
  controller.abort("DO_NOT_EXPOSE");
  const result = await pending;
  assertErrorCode(result, "REQUEST_ABORTED");
  assert.equal(JSON.stringify(result).includes("DO_NOT_EXPOSE"), false);
  rejectLookup(new Error("late DNS failure"));
  await new Promise<void>((resolve) => setImmediate(resolve));
});
```

Also extend the invalid-input table with `signal: {}`, `timeoutMs: 0`, `timeoutMs: -1`, `timeoutMs: 1.5`, and `timeoutMs: Number.POSITIVE_INFINITY`. Add a success case with `timeoutMs: null` to prove the existing behavior remains unbounded.

- [ ] **Step 2: Run the DNS tests and verify they fail**

Run:

```bash
npm run test:compile
node --test --test-name-pattern='TXT resolution|late rejection|invalid and hostile public input' .test-dist/test/verify-dns-delegation.test.js
```

Expected: timeout/cancellation assertions fail because the stage does not parse or enforce the new controls.

- [ ] **Step 3: Add controlled DNS resolution**

Extend `VerifyDnsDelegationInputSchema` with:

```ts
signal: AbortSignalSchema.optional(),
timeoutMs: TimeoutMillisecondsSchema.optional().transform(
  (value) => value ?? null,
),
```

Rename the current function body to `verifyDnsDelegationWithControl`, add its
`control` parameter, and add this public wrapper before it:

```ts
export async function verifyDnsDelegation(
  input: unknown,
): Promise<Result<DnsVerifiedToken>> {
  const inputResult = parseInput(input);
  if (!inputResult.ok) return inputResult;
  const { signal, timeoutMs } = inputResult.value;
  return verifyDnsDelegationWithControl(
    inputResult.value,
    createRequestControl({
      ...(signal === undefined ? {} : { signal }),
      timeoutMs: null,
    }),
  );
}

export async function verifyDnsDelegationWithControl(
  input: z.infer<typeof VerifyDnsDelegationInputSchema>,
  control: RequestControl,
): Promise<Result<DnsVerifiedToken>> {
  const { token, resolveTxt, timeoutMs } = input;
  // Begin with the current canonical-issuer validation at line 69 and retain
  // the remainder of that function through its result-schema containment.
}
```

The comment in this planning excerpt is an edit boundary, not code to add:
move the current lines 69-156 beneath the shown destructuring without changing
their issuer-validation and result-construction statements. Change only the
`resolveRecords` call so it receives `control` and `timeoutMs`.

Replace the raw resolver await in `resolveRecords` with:

```ts
const controlled = await runControlledOperation(
  control,
  timeoutMs,
  () => resolveTxt(dnsTarget),
);
if (!controlled.ok) {
  if ("interruption" in controlled) {
    return interruptionResult("dns", `TXT lookup for ${dnsTarget}`, controlled.interruption);
  }
  return dnsError(
    "DNS_LOOKUP_FAILED",
    `The TXT lookup failed for ${dnsTarget}.`,
    controlled.cause,
  );
}
const records = controlled.value;
```

Update the invalid-input message to mention the optional TXT resolver, signal, and timeout. Keep all record parsing and issuer matching unchanged.

- [ ] **Step 4: Run all DNS tests**

Run:

```bash
npx prettier --write src/verify-dns-delegation.ts test/verify-dns-delegation.test.ts
npm run test:compile
node --test .test-dist/test/verify-dns-delegation.test.js
```

Expected: all DNS tests pass; Node's test runner reports no late unhandled rejection.

- [ ] **Step 5: Commit DNS controls**

```bash
git add src/verify-dns-delegation.ts test/verify-dns-delegation.test.ts
git commit -m "feat: control DNS verification requests"
```

### Task 3: Issuer hostname, metadata, and JWKS controls

**Files:**
- Modify: `src/verify-issuer-signature.ts:27-51,53-143,145-252,330-380`
- Modify: `test/helpers/network-fixture.ts:13-40`
- Test: `test/verify-issuer-signature.test.ts:158-1110`

**Interfaces:**
- Consumes: the Task 1 request-control APIs and timeout/signal schemas.
- Produces publicly: `verifyIssuerSignature({ token, fetch?, resolveHost?, signal?, resolveHostTimeoutMs?, metadataFetchTimeoutMs?, jwksFetchTimeoutMs? })` with nullable, unbounded defaults.
- Produces internally: `verifyIssuerSignatureWithControl(input, control)` for Task 4.
- Preserves: `METADATA_FETCH_FAILED` and `JWKS_FETCH_FAILED` for ordinary dependency rejection, including an unrelated custom-fetch `AbortError`.

- [ ] **Step 1: Make the fetch fixture expose request signals**

Extend `createFetchFixture` without changing its call routing. The resulting
state declarations and return object are:

```ts
const signals: (AbortSignal | null | undefined)[] = [];

return {
  calls,
  inits,
  signals,
  fetch: async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    calls.push(url);
    inits.push(init);
    signals.push(init?.signal);
    const route = routes[url];
    if (route === undefined) {
      return new Response("not found", { status: 404 });
    }
    return typeof route === "function" ? route() : route;
  },
};
```

Update both strict `RequestInit` assertions: the successful request assertion at
current line 170 and the redirect-failure assertion at current lines 187-189.
For every captured init, assert `method === "GET"`, `redirect === "error"`,
`credentials === "omit"`, and `signal instanceof AbortSignal`. Assert the
captured URL separately. Do not deep-equal either init to `secureFetchInit`
after signals are added.

- [ ] **Step 2: Write failing table-driven issuer control tests**

Add a `never()` helper and cases for each external operation:

```ts
function never<T>(): Promise<T> {
  return new Promise<T>(() => undefined);
}

void it("times out each issuer external operation", async () => {
  const { fixture, token } = await createDnsVerifiedFixture();
  const cases = [
    {
      name: "metadata hostname resolution",
      input: {
        token,
        resolveHostTimeoutMs: 1,
        resolveHost: () => never<readonly { address: string; family: 4 }[]>(),
      },
    },
    {
      name: "metadata fetch",
      input: {
        token,
        metadataFetchTimeoutMs: 1,
        fetch: () => never<Response>(),
      },
    },
    {
      name: "metadata body",
      input: {
        token,
        metadataFetchTimeoutMs: 1,
        fetch: () =>
          Promise.resolve({
            ok: true,
            status: 200,
            url: metadataUrl,
            redirected: false,
            json: () => never<unknown>(),
          }),
      },
    },
  ];
  for (const testCase of cases) {
    const result = await verifyIssuerSignature(testCase.input);
    assertIssuerError(result, "REQUEST_TIMEOUT");
  }
});
```

Complete the table with these exact three JWKS rows:

| Name | Timeout option | Successful earlier work | Stalled work |
| --- | --- | --- | --- |
| JWKS hostname resolution | `resolveHostTimeoutMs: 1` | first `resolveHost` returns `publicResolveHost()` and metadata Fetch returns `jsonResponse(metadata())` | second `resolveHost` returns `never()` |
| JWKS Fetch | `jwksFetchTimeoutMs: 1` | both hostname calls return `publicResolveHost()` and metadata Fetch returns `jsonResponse(metadata())` | Fetch of `jwksUrl` returns `never()` |
| JWKS body | `jwksFetchTimeoutMs: 1` | both hostname calls and metadata Fetch succeed; JWKS Fetch returns a response-shaped object | that object's `json()` returns `never()` |

For cancellation, reuse the same six operation arrangements with all timeout
fields `null`. Call `controller.abort("DO_NOT_EXPOSE")` immediately before each
stalled promise is returned, pass `signal: controller.signal`, and expect
`REQUEST_ABORTED`. Record hostname and Fetch calls and assert each list ends at
the interrupted operation, so no later dependency starts.

Add a test where a custom Fetch rejects with `new DOMException("custom", "AbortError")` while no controlled signal is aborted; it must remain `METADATA_FETCH_FAILED`. Extend invalid public inputs with every timeout set to `0`, a fractional value, and infinity, plus `signal: {}`. Add a `null` success case.

- [ ] **Step 3: Run focused issuer tests and verify they fail**

Run:

```bash
npm run test:compile
node --test --test-name-pattern='issuer external operation|caller controller|unrelated AbortError|nullable timeouts' .test-dist/test/verify-issuer-signature.test.js
```

Expected: the new inputs are ignored or rejected and stalled operations do not return the expected timeout/cancellation results.

- [ ] **Step 4: Parse issuer controls and thread the shared context**

Add these fields to `VerifyIssuerSignatureInputSchema`:

```ts
signal: AbortSignalSchema.optional(),
resolveHostTimeoutMs: TimeoutMillisecondsSchema.optional().transform(
  (value) => value ?? null,
),
metadataFetchTimeoutMs: TimeoutMillisecondsSchema.optional().transform(
  (value) => value ?? null,
),
jwksFetchTimeoutMs: TimeoutMillisecondsSchema.optional().transform(
  (value) => value ?? null,
),
```

Make `verifyIssuerSignature()` parse once, create a control with no overall deadline, and delegate to `verifyIssuerSignatureWithControl(parsedInput, control)`. Pass `resolveHostTimeoutMs` to both hostname checks, `metadataFetchTimeoutMs` to the metadata document operation, and `jwksFetchTimeoutMs` to the JWKS document operation.

- [ ] **Step 5: Control hostname resolution and the complete Fetch/body operation**

Use these explicit internal signatures:

```ts
async function resolveNetworkTarget(
  control: RequestControl,
  timeoutMs: number | null,
  resolveHost: ResolveHost,
  hostname: string,
  kind: DocumentKind,
): Promise<Result<true>>;

async function fetchJsonDocument({
  control,
  fetch,
  url,
  issuer,
  kind,
  resolveHost,
  resolveHostTimeoutMs,
  timeoutMs,
}: {
  control: RequestControl;
  fetch: FetchFunction;
  url: string;
  issuer: string;
  kind: DocumentKind;
  resolveHost: ResolveHost;
  resolveHostTimeoutMs: number | null;
  timeoutMs: number | null;
}): Promise<Result<unknown>>;
```

The declarations above specify the resulting signatures; implement them as
ordinary function definitions rather than TypeScript overload declarations.

Change `resolveNetworkTarget` to execute `resolveHost(hostname)` through `runControlledOperation`. On interruption, return:

```ts
return interruptionResult(
  "issuer",
  `${kind} target hostname resolution`,
  controlled.interruption,
);
```

Wrap the complete Fetch, response validation, HTTP checks, and `response.json()`
call in one `runControlledOperation` callback. Move the current response-schema,
redirect, exact-URL, status, and body-reading statements from lines 210-251 into
the callback without changing their returned `Result` values. This gives the
response body the remaining portion of the same metadata or JWKS deadline
rather than restarting its timer:

```ts
const controlled = await runControlledOperation(
  control,
  timeoutMs,
  async (signal): Promise<Result<unknown>> => {
    const responseValue = await fetch(url, {
      method: "GET",
      redirect: "error",
      credentials: "omit",
      signal,
    });
    let responseResult: z.ZodSafeParseResult<
      z.infer<typeof FetchResponseSchema>
    >;
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
    } catch (cause) {
      if (signal.aborted) throw cause;
      return documentError(
        kind,
        `${kind} response did not contain valid JSON.`,
      );
    }
  },
);

if (!controlled.ok) {
  if ("interruption" in controlled) {
    return interruptionResult("issuer", `${kind} request`, controlled.interruption);
  }
  return fetchError(kind, `${kind} could not be fetched.`, controlled.cause);
}
return controlled.value;
```

Do not infer cancellation from an error name. Classification comes only from the tracked caller/overall/operation sources.

Run `reparseDnsVerifiedToken()` and `verifyEvtSignature()` through
`runControlledOperation(control, null, ...)`. Map interruption to stage
`issuer`, with operation labels `Issuer token parsing` and `EVT signature
verification`. Map a contained thrown cause to the same `INVALID_INPUT` or
signature error used by the current containment path. Check the shared control
after metadata parsing so an expired overall deadline cannot start the JWKS
resolution.

- [ ] **Step 6: Run issuer and security regression tests**

Run:

```bash
npx prettier --write src/verify-issuer-signature.ts test/verify-issuer-signature.test.ts test/helpers/network-fixture.ts
npm run test:compile
node --test .test-dist/test/verify-issuer-signature.test.js .test-dist/test/network-safety.test.js
```

Expected: all issuer controls, response-safety cases, SSRF checks, key-selection tests, and existing rejection tests pass.

- [ ] **Step 7: Commit issuer controls**

```bash
git add src/verify-issuer-signature.ts test/verify-issuer-signature.test.ts test/helpers/network-fixture.ts
git commit -m "feat: control issuer verification requests"
```

### Task 4: Overall verification deadline and orchestration

**Files:**
- Modify: `src/verify-token.ts:1-70`
- Test: `test/verify-token.test.ts:103-490`
- Test: `test/public-types.test.ts:70-145`

**Interfaces:**
- Consumes: normalized `signal`, `timeoutMs`, and `timeouts` from Task 1; internal controlled stage entry points from Tasks 2 and 3.
- Produces: `verifyEmailToken()` cancellation across local and network stages, one overall deadline shared by all operations, and per-operation limits capped by the remaining overall budget.

- [ ] **Step 1: Write failing orchestration tests**

Add tests for immediate cancellation, the overall deadline, per-operation forwarding, and short-circuiting:

```ts
void it("returns an aborted input result before dependencies run", async () => {
  const fixture = await createTokenFixture();
  const controller = new AbortController();
  controller.abort();
  const { input, dnsCalls, fetchCalls } = validInput(fixture, {
    signal: controller.signal,
  });
  const result = await verifyEmailToken(input);
  assertFailure(result, "input", "REQUEST_ABORTED");
  assert.deepEqual(dnsCalls, []);
  assert.deepEqual(fetchCalls, []);
});

void it("applies the overall deadline when operation limits are null", async () => {
  const fixture = await createTokenFixture();
  const { input, fetchCalls } = validInput(fixture, {
    timeoutMs: 1,
    timeouts: null,
    resolveTxt: () => new Promise<string[][]>(() => undefined),
  });
  const result = await verifyEmailToken(input);
  assertFailure(result, "dns", "REQUEST_TIMEOUT");
  assert.deepEqual(fetchCalls, []);
});
```

Add one case per nested timeout field that stalls only its named operation and proves the correct `dns` or `issuer` stage. Add a successful call with omitted timeout options to prove defaults are unbounded. Add a cancellation during DNS and confirm metadata/JWKS never run. Assert errors never contain the caller's abort reason.

- [ ] **Step 2: Run orchestrator tests and verify they fail**

Run:

```bash
npm run test:compile
node --test --test-name-pattern='aborted input result|overall deadline|nested timeout|defaults are unbounded' .test-dist/test/verify-token.test.js
```

Expected: the orchestrator does not yet create or pass a shared request-control context.

- [ ] **Step 3: Create the overall control at function entry**

Capture monotonic start time before input parsing and create the shared control immediately after successful parsing:

```ts
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
  } catch (cause) {
    return invalidInput(
      "Email token verification could not complete safely.",
      cause,
    );
  }
}
```

After the initial interruption branch, retain the current parse, expected-value,
DNS, issuer, key-binding, and final-schema order; Steps 4 and 5 specify the exact
calls that replace the current direct awaits.

- [ ] **Step 4: Apply the overall context across all stages**

Run asynchronous local stages through the overall control with no additional operation timeout, mapping interruption to their active stage. Call the controlled DNS and issuer entry points with the normalized per-operation values:

```ts
const delegated = await verifyDnsDelegationWithControl(
  {
    token: expected.value,
    resolveTxt: parsedInput.data.resolveTxt,
    timeoutMs: parsedInput.data.timeouts.resolveTxtMs,
  },
  control,
);

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
```

Replace the direct `parseToken()` await with:

```ts
const controlledParsed = await runControlledOperation(
  control,
  null,
  () => parseToken(parsedInput.data.token),
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
```

Immediately after `validateExpectedValues()` returns, check the shared control
before inspecting its `Result`:

```ts
const expectedInterruption = checkInterruption(control);
if (expectedInterruption !== undefined) {
  return interruptionResult(
    "expected-values",
    "Expected-values validation",
    expectedInterruption,
  );
}
if (!expected.ok) return expected;
```

Replace the direct `verifyKeyBinding()` await with:

```ts
const controlledKeyBound = await runControlledOperation(
  control,
  null,
  () => verifyKeyBinding({ token: issuerVerified.value }),
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
```

After `VerifiedEmailSchema.safeParse()` succeeds, perform one final checkpoint
before returning `ok(verifiedEmail.data)`:

```ts
const finalInterruption = checkInterruption(control);
if (finalInterruption !== undefined) {
  return interruptionResult(
    "key-binding",
    "Verified result validation",
    finalInterruption,
  );
}
```

This final check is intentional: the approved overall timeout covers local work,
and synchronous schema parsing cannot be interrupted until its next checkpoint.
Never start the next stage after an interruption.

- [ ] **Step 5: Run orchestration and public type tests**

Run:

```bash
npx prettier --write src/verify-token.ts test/verify-token.test.ts test/public-types.test.ts
npm run test:compile
node --test .test-dist/test/verify-token.test.js .test-dist/test/public-types.test.js
```

Expected: all end-to-end trust-order, short-circuit, default, timeout, cancellation, and compile-time API tests pass.

- [ ] **Step 6: Commit orchestration**

```bash
git add src/verify-token.ts test/verify-token.test.ts test/public-types.test.ts
git commit -m "feat: add overall verification deadline"
```

### Task 5: README documentation and complete verification

**Files:**
- Modify: `README.md:74-96,123-159,161-208`

**Interfaces:**
- Consumes: the final public API and error codes from Tasks 1-4.
- Produces: user-facing documentation for cancellation, all timeout scopes, null/omitted behavior, recommended values, and the DNS cancellation limitation.

- [ ] **Step 1: Update the optional-arguments table**

Add rows with direct descriptions:

```markdown
| `signal`    | none   | Cancels verification when its controller is aborted. |
| `timeoutMs` | `null` | Overall verification timeout in milliseconds.        |
| `timeouts`  | `null` | Per-operation timeout values in milliseconds.         |
```

Immediately below the table, document `resolveTxtMs`, `resolveHostMs`, `metadataFetchMs`, and `jwksFetchMs`. State that omitted and `null` values impose no limit and that timeout numbers must be positive finite integers.

- [ ] **Step 2: Add cancellation and recommended timeout examples**

Extend the existing `app.post("/emails", ...)` example and make its handler
`async`. Define the controller and response-close hook inside that handler, then
remove the hook when verification settles:

```ts
const controller = new AbortController();
const abortVerification = () => controller.abort();

// Cancel if the client connection closes before verification completes.
res.once("close", abortVerification);

const result = await verifyEmailToken({
  token,
  nonce,
  email,
  audience,
  signal: controller.signal,
  timeoutMs: 10_000,
  timeouts: {
    resolveTxtMs: 2_000,
    resolveHostMs: 2_000,
    metadataFetchMs: 4_000,
    jwksFetchMs: 4_000,
  },
}).finally(() => res.off("close", abortVerification));

if (!result.ok) {
  if (result.error.code === "REQUEST_ABORTED") {
    // The caller cancelled verification.
  } else if (result.error.code === "REQUEST_TIMEOUT") {
    // The overall or active operation deadline expired.
  }
}
```

Label these values as a recommendation for interactive verification, not library defaults. Include examples of `timeoutMs: null`, one nested field set to `null`, and `timeouts: null`.

- [ ] **Step 3: Document error and cancellation behavior**

Add `REQUEST_ABORTED` and `REQUEST_TIMEOUT` to the error-code list. Explain that Fetch and JSON body reading receive an abort signal. Explain that the default Node DNS calls cannot be interrupted individually, so verification returns promptly while the underlying DNS work may finish later and be ignored.

- [ ] **Step 4: Run documentation and full project checks**

Run:

```bash
npx prettier --write README.md
npm run check
git diff --check
```

Expected: Prettier updates only intended files; format, typecheck, lint, build, and all unit tests pass; `git diff --check` prints nothing.

- [ ] **Step 5: Inspect the final public package surface**

Run:

```bash
npm pack --dry-run --cache /private/tmp/email-verification-npm-cache
git status --short
```

Expected: the tarball includes built declarations and README documentation; only intended source, test, and README changes remain before the final commit.

- [ ] **Step 6: Commit documentation and final formatting**

```bash
git add README.md
git commit -m "docs: explain verification request controls"
```

- [ ] **Step 7: Re-run completion verification from the committed tree**

Run:

```bash
npm run check
git status --short
```

Expected: the full check passes and the working tree is clean.
