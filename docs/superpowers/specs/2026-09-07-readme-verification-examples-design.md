# README Verification Examples Design

## Goal

Make the primary verification documentation easier to approach while retaining a complete example of timeout and cancellation controls.

## Structure

The `Verifying the token` section will contain two framework-neutral examples in this order:

1. **Basic verification** calls `verifyEmailToken()` with only the four required values: `token`, `nonce`, `email`, and `audience`. It demonstrates the `Result` success and failure branches without introducing request controls.
2. **Timeouts and cancellation** creates an `AbortController` and calls `verifyEmailToken()` with `signal`, the overall `timeoutMs`, and all four per-operation timeout properties. It distinguishes `REQUEST_ABORTED` from `REQUEST_TIMEOUT` in the result handling.

The detailed option tables, null opt-out examples, error documentation, and network behavior notes will remain in place after the examples.

## Boundaries

- Both examples remain independent of Express or another server framework.
- The advanced example shows every timeout setting in one copyable block.
- No runtime behavior, public API, or defaults change.

## Verification

Run the repository formatting check and inspect the rendered Markdown structure and diff for duplication or contradictions.
