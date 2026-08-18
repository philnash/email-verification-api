# email-verification

Verify Email Verification Protocol EVT+KB presentation tokens on a relying-party
server.

This package implements the experimental token format described by the
[Chrome Email Verification API origin trial][chrome-origin-trial] and the
[Email Verification Protocol Internet-Draft][protocol-draft]: an issuer-signed
`evt+jwt` and a `kb+jwt` in an SD-JWT+KB presentation. The protocol is not
standards-stable, so applications should retain another way for users to verify
their email address.

The library verifies:

- direct and selectively disclosed email claims;
- the expected email, `email_verified` value, nonce, audience, and issue times;
- DNS delegation from the email domain to the claimed issuer;
- issuer metadata and JWKS endpoints, including issuer-bound HTTPS URLs;
- the issuer signature on the EVT;
- the KB-JWT signature with the holder key authenticated by that EVT; and
- `sd_hash` over the exact presented EVT and disclosure sequence.

It does not issue tokens, implement the browser API, create or store nonces,
prove that an inbox can receive mail, or replace an application's account and
session security.

## Installation

```sh
npm install email-verification
```

The package is ESM-only and includes TypeScript declarations. Its default
network implementations use global `fetch` and
`node:dns/promises.resolveTxt`.

## Verify a token

```ts
import { verifyEmailToken } from "email-verification";

declare const tokenFromBrowser: string;
declare const nonceForSession: string;

const result = await verifyEmailToken({
  token: tokenFromBrowser,
  nonce: nonceForSession,
  email: "user@example.com",
  audience: "https://rp.example.com",
});

if (!result.ok) {
  console.error({
    stage: result.error.stage,
    code: result.error.code,
    message: result.error.message,
    cause: result.error.cause,
  });
} else {
  console.log(`Verified ${result.value.email}`);
  console.log(`Issuer: ${result.value.issuer}`);
}
```

`verifyEmailToken()` needs four values:

| Property   | Meaning                                                       |
| ---------- | ------------------------------------------------------------- |
| `token`    | The complete SD-JWT+KB presentation returned by the browser.  |
| `nonce`    | The exact nonce previously bound to this application session. |
| `email`    | The email address the application expects to verify.          |
| `audience` | The relying party's absolute HTTP(S) origin.                  |

The email comparison is case-insensitive, while the nonce comparison is exact
and case-sensitive. The audience must serialize to an origin: paths, query
strings, fragments, and credentials are rejected.

The optional inputs are:

| Property                | Default                        | Meaning                                            |
| ----------------------- | ------------------------------ | -------------------------------------------------- |
| `maxTokenAgeSeconds`    | `300`                          | Maximum age of both the EVT and KB-JWT.            |
| `clockToleranceSeconds` | `60`                           | Clock skew allowed for age and future issue times. |
| `fetch`                 | global `fetch`                 | Fetch implementation used for metadata and JWKS.   |
| `resolveTxt`            | `node:dns/promises.resolveTxt` | DNS TXT resolver.                                  |
| `now`                   | `() => Date.now()`             | Clock returning Unix time in milliseconds.         |

Exact age and tolerance boundaries are accepted. Both timing options must be
finite, nonnegative numbers.

On success, the result contains authenticated values:

```ts
type VerifiedEmail = {
  email: string;
  issuer: string;
  audience: string;
  issuedAt: {
    evt: number;
    keyBinding: number;
  };
  claims: EvtClaims;
};
```

## Trust order

`verifyEmailToken()` stops at the first failed stage:

1. `parseToken()` validates the compact presentation and resolves disclosures.
2. `validateExpectedValues()` rejects unexpected claims and stale tokens before
   network access.
3. `verifyDnsDelegation()` confirms that the email domain delegates to the
   claimed issuer.
4. `verifyIssuerSignature()` retrieves metadata and JWKS, then authenticates
   the EVT.
5. `verifyKeyBinding()` uses the authenticated `cnf.jwk` to verify the KB-JWT
   and checks its `sd_hash`.

The local checks in stage 2 inspect untrusted claims only as an early rejection.
The EVT issuer signature in stage 4 is what authenticates `cnf.jwk`; the holder
key must not be trusted or used to verify the KB-JWT before that point.

## Errors and Results

Every verification stage returns `Result` or `Promise<Result>` rather than
throwing for invalid input, malformed tokens, or dependency failures:

```ts
type Result<T, E = VerificationError> =
  { ok: true; value: T } | { ok: false; error: E };

type VerificationError = {
  stage: VerificationStage;
  code: VerificationErrorCode;
  message: string;
  cause?: string;
};
```

Use `stage` and `code` for application logic. `message` is a descriptive log
message. `cause`, when present, is a normalized description of the underlying
failure and should not be shown directly to end users.

The stable stages are `input`, `parse`, `expected-values`, `dns`, `issuer`, and
`key-binding`. Stable error codes are:

```text
INVALID_INPUT                    TOKEN_MALFORMED
DISCLOSURE_INVALID               EMAIL_MISMATCH
EMAIL_NOT_VERIFIED               NONCE_MISMATCH
AUDIENCE_MISMATCH                TOKEN_EXPIRED
TOKEN_NOT_YET_VALID              DNS_LOOKUP_FAILED
DNS_DELEGATION_MISSING           DNS_DELEGATION_AMBIGUOUS
ISSUER_MISMATCH                  METADATA_FETCH_FAILED
METADATA_INVALID                 JWKS_FETCH_FAILED
JWKS_INVALID                     ALGORITHM_UNSUPPORTED
EVT_SIGNATURE_INVALID            KB_SIGNATURE_INVALID
SD_HASH_MISMATCH
```

The package also exports `ok()`, `err()`, `isOk()`, `isErr()`, the error
schemas, and their inferred TypeScript types.

## Dependency injection

Pass network and clock implementations per verification call when a runtime,
test, or application needs different behavior:

```ts
import { resolveTxt } from "node:dns/promises";
import { verifyEmailToken } from "email-verification";

declare const tokenFromBrowser: string;
declare const nonceForSession: string;

const result = await verifyEmailToken({
  token: tokenFromBrowser,
  nonce: nonceForSession,
  email: "user@example.com",
  audience: "https://rp.example.com",
  fetch: globalThis.fetch,
  resolveTxt,
  now: () => Date.now(),
  maxTokenAgeSeconds: 300,
  clockToleranceSeconds: 60,
});
```

Rejected promises, thrown values, and invalid responses from injected
dependencies are converted to failed Results.

## External caching

This release has no process-global cache. A caller can inject memoizing wrappers
without changing verification behavior:

```ts
import { resolveTxt } from "node:dns/promises";
import { verifyEmailToken } from "email-verification";

declare const tokenFromBrowser: string;
declare const nonceForSession: string;
declare const applicationDnsTtlMilliseconds: number;
declare const cachedFetch: typeof globalThis.fetch;

const txtCache = new Map<
  string,
  { expiresAt: number; value: Promise<string[][]> }
>();

function memoizedResolveTxt(
  hostname: string,
  ttlMilliseconds: number,
): Promise<string[][]> {
  const cached = txtCache.get(hostname);
  if (cached !== undefined && cached.expiresAt > Date.now()) {
    return cached.value;
  }

  const value = resolveTxt(hostname);
  const entry = {
    expiresAt: Date.now() + ttlMilliseconds,
    value,
  };
  txtCache.set(hostname, entry);
  void value.catch(() => {
    if (txtCache.get(hostname) === entry) txtCache.delete(hostname);
  });
  return value;
}

const cachedResolveTxt = (hostname: string) =>
  memoizedResolveTxt(hostname, applicationDnsTtlMilliseconds);

const result = await verifyEmailToken({
  token: tokenFromBrowser,
  nonce: nonceForSession,
  email: "user@example.com",
  audience: "https://rp.example.com",
  resolveTxt: cachedResolveTxt,
  fetch: cachedFetch,
});
```

The example deliberately leaves cache policy with the application. DNS cache
lifetimes must not exceed the authoritative record TTL; `resolveTxt` does not
return that TTL, so obtain it through an appropriate resolver or cache adapter.
An injected Fetch cache must honor HTTP cache directives, redirect handling,
expiry, and revalidation for both issuer metadata and JWKS. Do not use a single
arbitrary lifetime for both DNS and HTTP data.

## Use individual stages

The same public stages can be composed explicitly. Each stage validates its
input and returns the value required by the next stage:

```ts
import {
  parseToken,
  validateExpectedValues,
  verifyDnsDelegation,
  verifyIssuerSignature,
  verifyKeyBinding,
} from "email-verification";

declare const tokenFromBrowser: string;
declare const nonceForSession: string;

async function verifyInStages() {
  const parsed = await parseToken(tokenFromBrowser);
  if (!parsed.ok) return parsed;

  const expected = validateExpectedValues({
    token: parsed.value,
    nonce: nonceForSession,
    email: "user@example.com",
    audience: "https://rp.example.com",
  });
  if (!expected.ok) return expected;

  const delegated = await verifyDnsDelegation({ token: expected.value });
  if (!delegated.ok) return delegated;

  const issuerVerified = await verifyIssuerSignature({
    token: delegated.value,
  });
  if (!issuerVerified.ok) return issuerVerified;

  return verifyKeyBinding({ token: issuerVerified.value });
}
```

The intermediate schemas and their inferred types are exported from the package
root for applications that persist, inspect, or validate stage results. Internal
URL, issuer, JOSE, and error-construction helpers are intentionally not exported.

Pass each intermediate directly from one successful stage to the next within
the same verification operation. An intermediate is not a portable proof that
DNS or cryptographic verification occurred: its schema validates structure, not
provenance. If an intermediate crosses an untrusted storage, process, or message
boundary, discard it and restart verification from the original presentation.

## Application responsibilities

The application must:

- generate each nonce with a cryptographically secure random source;
- bind the nonce to the intended user, operation, and server-side session;
- expire and consume the nonce exactly once, including under concurrent use;
- avoid putting a reusable nonce or verification token in logs or client-side
  storage;
- provide a fallback verification method when the experimental protocol is not
  available or verification fails; and
- treat success as an authenticated issuer assertion, not proof that the inbox
  currently exists, accepts messages, or belongs permanently to the user.

## License

MIT

[chrome-origin-trial]: https://developer.chrome.com/blog/email-verification-protocol-origin-trial
[protocol-draft]: https://www.ietf.org/archive/id/draft-hardt-email-verification-00.html
