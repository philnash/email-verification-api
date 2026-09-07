# README Verification Examples Design

## Goal

Make the primary verification documentation easier to approach while retaining a complete example of timeout and cancellation controls.

## Structure

The `Verifying the token` section will contain three progressive examples in this order:

1. **Basic verification** calls `verifyEmailToken()` with only the four required values: `token`, `nonce`, `email`, and `audience`. It demonstrates the `Result` success and failure branches without introducing request controls.
2. **Timeouts and cancellation** creates an `AbortController` and calls `verifyEmailToken()` with `signal`, the overall `timeoutMs`, and all four per-operation timeout properties. It distinguishes `REQUEST_ABORTED` from `REQUEST_TIMEOUT` in the result handling.
3. **Express example** shows the complete flow in an Express-style request handler. It reads the submitted email and token, obtains the nonce from the session, derives the audience from the request origin, and guards a missing token with a comment indicating where to use an OTP or another fallback. It connects an `AbortController` to the response `close` event, removes that listener when verification settles, configures the overall timeout and all four per-operation timeouts, and handles success, cancellation, timeout, and other verification failures.

The detailed option tables, null opt-out examples, error documentation, and network behavior notes will remain in place after the examples.

## Boundaries

- The first two examples remain independent of Express or another server framework.
- The advanced example shows every timeout setting in one copyable block.
- The Express example is the third and most complete example.
- No runtime behavior, public API, or defaults change.

## Verification

Run the repository formatting check and inspect the rendered Markdown structure and diff for duplication or contradictions.
