# External Request Timeouts and Cancellation Design

## Goal

Bound every external operation performed during email-token verification and let
callers cancel verification with an `AbortSignal`. Preserve the library's
non-throwing `Result` API and identify cancellation separately from timeout.

## Public API

`verifyEmailToken()` accepts these additional optional properties:

```ts
type ExternalRequestTimeouts = {
  resolveTxtMs?: number | null;
  resolveHostMs?: number | null;
  metadataFetchMs?: number | null;
  jwksFetchMs?: number | null;
};

type VerifyEmailTokenInput = {
  // Existing properties remain unchanged.
  signal?: AbortSignal;
  timeoutMs?: number | null;
  timeouts?: ExternalRequestTimeouts | null;
};
```

The defaults are:

```ts
timeoutMs: 10_000,
timeouts: {
  resolveTxtMs: 2_000,
  resolveHostMs: 2_000,
  metadataFetchMs: 4_000,
  jwksFetchMs: 4_000,
}
```

Omitting an option uses its default. Setting an individual value to `null`
disables that limit. Setting `timeouts` to `null` disables every per-operation
limit. Setting `timeoutMs` to `null` disables the overall limit. A caller that
wants no time limits sets both `timeoutMs` and `timeouts` to `null`.

Numeric timeout values are positive finite integers measured in milliseconds.
Invalid timeout or signal values return the existing `INVALID_INPUT` result.

The public stage functions expose the relevant subset of the same controls:

- `verifyDnsDelegation()` accepts `signal` and `timeoutMs`, whose default is
  2,000 ms and which applies to its TXT lookup.
- `verifyIssuerSignature()` accepts `signal`, `resolveHostTimeoutMs`,
  `metadataFetchTimeoutMs`, and `jwksFetchTimeoutMs`, with the same defaults as
  the orchestrator.

The orchestrator combines its caller signal and overall deadline before passing
them to the stages. Stage-level APIs do not invent an additional overall
verification deadline.

## Deadline and Cancellation Semantics

The overall deadline starts when `verifyEmailToken()` begins. It covers local
work and all external operations. Each external operation receives the smaller
of its configured limit and the remaining overall budget.

The controlled external operations are, in protocol order:

1. the DNS TXT lookup;
2. hostname resolution before the metadata request;
3. the metadata fetch, including reading its JSON body;
4. hostname resolution before the JWKS request; and
5. the JWKS fetch, including reading its JSON body.

The implementation checks cancellation and the overall deadline before each
stage, before each external operation, and after awaited local work. Fetch gets
a composed signal so cancellation actively aborts the request and body read.

The Node DNS promise APIs do not accept an `AbortSignal`. DNS operations are
raced against cancellation and their deadline. Verification returns promptly
and ignores any late DNS result. The underlying resolver may continue working.
Promise handlers remain attached so a late rejection cannot become unhandled.

Synchronous parsing or cryptographic code cannot be interrupted while it is
running. If cancellation or timeout occurs during such work, verification
returns the corresponding error at the next checkpoint.

The library never aborts or mutates the caller's `AbortController`. All timers
and listeners owned by the library are removed when their operation settles.

## Errors

Add two public verification error codes:

- `REQUEST_ABORTED`: the caller's signal cancelled verification.
- `REQUEST_TIMEOUT`: the overall or active per-operation deadline expired.

Both errors retain the active verification stage. Their messages identify the
operation that was interrupted when applicable. They do not expose response
bodies or arbitrary abort reasons.

If caller cancellation and a deadline are both observable at the same
checkpoint, caller cancellation wins. An unrelated `AbortError` thrown by a
custom fetch implementation remains the existing metadata or JWKS fetch failure
unless one of the library-controlled signals was actually aborted.

No subsequent stage or external operation starts after either outcome.

## Internal Structure

A focused internal cancellation/deadline helper will:

- validate and normalize timeout configuration;
- represent the overall deadline without using the injectable token clock;
- check caller cancellation and deadline expiry;
- compose caller, overall, and per-operation cancellation for Fetch;
- race non-abortable promises safely; and
- clean up timers and event listeners.

The helper tracks caller cancellation, the overall deadline, and the active
operation deadline as separate sources. This preserves correct
`REQUEST_ABORTED` versus `REQUEST_TIMEOUT` classification when signals are
composed. Public stage wrappers create their own control context, while the
orchestrator passes one shared context through its internal stage calls.

DNS and issuer modules use this helper without changing the existing protocol
trust order or network-safety checks. No new runtime dependency is added.

## Tests

Tests cover:

- defaults, overrides, `null` opt-outs, and invalid input;
- timeout of TXT resolution, both hostname resolutions, metadata fetch/body,
  and JWKS fetch/body;
- the overall deadline limiting a longer per-operation timeout;
- cancellation before verification and during every external operation;
- `REQUEST_ABORTED` versus `REQUEST_TIMEOUT` classification and precedence;
- forwarding a composed signal to custom Fetch implementations;
- short-circuiting all later stages after cancellation or timeout;
- safely ignoring late DNS fulfillment and rejection; and
- the timeout and signal options on the public stage APIs.

The full typecheck, unit test, lint, format, and build checks must pass.

## Documentation

The README optional-arguments table will include `signal`, `timeoutMs`, and
`timeouts`, with their defaults. A concise example will demonstrate:

- cancelling with `AbortController`;
- overriding one timeout;
- distinguishing `REQUEST_ABORTED` from `REQUEST_TIMEOUT`; and
- using `null` to disable individual, per-operation, or overall limits.

The README will state that Fetch is actively aborted, while Node DNS work can
continue internally after the verifier has returned.
