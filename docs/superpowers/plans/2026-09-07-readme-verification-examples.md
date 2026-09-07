# README Verification Examples Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Present a minimal framework-neutral verification example before a complete framework-neutral timeout and cancellation example.

**Architecture:** Replace the existing Express-oriented example in `README.md` with two progressive examples. Keep the existing option tables and detailed behavior documentation as the authoritative reference after the examples.

**Tech Stack:** Markdown, JavaScript, Prettier

## Global Constraints

- Both examples are framework-neutral.
- The basic example uses only `token`, `nonce`, `email`, and `audience`.
- The advanced example includes `signal`, `timeoutMs`, `resolveTxtMs`, `resolveHostMs`, `metadataFetchMs`, and `jwksFetchMs`.
- Library defaults and runtime behavior do not change.

---

### Task 1: Rewrite the verification examples

**Files:**
- Modify: `README.md:42-100`

**Interfaces:**
- Consumes: `verifyEmailToken(input): Promise<Result<VerifiedEmail>>`
- Produces: Two copyable, framework-neutral examples documenting the existing public API.

- [x] **Step 1: Add the basic example**

Replace the current introductory example with a `Basic verification` subsection that imports `verifyEmailToken`, passes the four required values, and handles both `result.ok` branches:

```javascript
import { verifyEmailToken } from "email-verification-api";

const result = await verifyEmailToken({
  token: tokenFromBrowser,
  nonce: nonceForSession,
  email: "user@example.com",
  audience: "https://rp.example.com",
});

if (result.ok) {
  console.log(`${result.value.email} is verified by ${result.value.issuer}`);
} else {
  console.error(result.error);
}
```

- [x] **Step 2: Add the complete request-control example**

Follow the basic example with a `Timeouts and cancellation` subsection. Explain that all timeouts are opt-in, create an `AbortController`, state when callers should invoke `abort()`, and show the overall timeout plus every per-operation timeout:

```javascript
import { verifyEmailToken } from "email-verification-api";

const controller = new AbortController();

// Call controller.abort() if the client disconnects or verification is no longer needed.

const result = await verifyEmailToken({
  token: tokenFromBrowser,
  nonce: nonceForSession,
  email: "user@example.com",
  audience: "https://rp.example.com",
  signal: controller.signal,
  timeoutMs: 10_000,
  timeouts: {
    resolveTxtMs: 2_000,
    resolveHostMs: 2_000,
    metadataFetchMs: 4_000,
    jwksFetchMs: 4_000,
  },
});

if (!result.ok) {
  if (result.error.code === "REQUEST_ABORTED") {
    // The caller cancelled verification.
  } else if (result.error.code === "REQUEST_TIMEOUT") {
    // The overall or active operation deadline expired.
  }
}
```

- [x] **Step 3: Check formatting and review the diff**

Run:

```sh
npx prettier --check README.md
git diff --check
git diff -- README.md
```

Expected: Prettier reports that `README.md` uses its code style, `git diff --check` emits no errors, and the diff contains only the intended two-example rewrite.

- [x] **Step 4: Commit the documentation change**

```sh
git add README.md docs/superpowers/plans/2026-09-07-readme-verification-examples.md
git commit -m "docs: simplify verification examples"
```
