# 📧 ✅ Email Verification API for Node.js

[![npm version](https://img.shields.io/npm/v/email-verification-api.svg)](https://www.npmjs.com/package/email-verification-api)
[![CI](https://github.com/philnash/email-verification-api/actions/workflows/ci.yml/badge.svg)](https://github.com/philnash/email-verification-api/actions/workflows/ci.yml)

The [Email Verification API](https://github.com/WICG/email-verification) is a proposed standard to help users verify their email addresses without having to send one time passwords (OTPs) or magic links.

Instead, the browser will use a user's logged in session to their inbox to create a cryptographically signed token that a server can use to verify the email address.

This project provides a function for web developers to verify the Email Verification Token (EVT).

Read more about the [Email Verification API and how to use it](https://resend.com/blog/email-verification-api).

> [!Warning]
> This library is targeting a draft specification that is under development. It may be out of date at times, but I will be updating it to match what is specified and supported by browsers and mailbox providers.\

There is a demo app in the [./example](./example/) directory and you can interact with it in this [hosted demo](https://verifyemails.vercel.app/).

- [How to use](#how-to-use)
  - [Installation](#installation)
  - [Example app](#example-app)
  - [Get an Email Verification Token](#get-an-email-verification-token)
  - [Verifying the token](#verifying-the-token)
    - [Basic verification](#basic-verification)
    - [Timeouts and cancellation](#timeouts-and-cancellation)
    - [Express example](#express-example)
- [API reference](#api-reference)
- [Verification order](#verification-order)
- [Errors and Results](#errors-and-results)
- [Dependency injection](#dependency-injection)
- [Network security and runtime behavior](#network-security-and-runtime-behavior)
  - [HTTP requests](#http-requests)
  - [Cancellation and timeouts](#cancellation-and-timeouts)
- [Developing](#developing)
- [License](#license)

## How to use

### Installation

First install the package:

```sh
npm install email-verification-api
```

### Example app

There is an example Next.js application in the [example](./example/) directory. See the [README](./example/README.md) for how to run the example.

### Get an Email Verification Token

Full details on [how to implement a verifier site are available in this Chrome Developer article](https://developer.chrome.com/blog/email-verification-protocol-origin-trial#implement_the_verifier_site), but the process looks like this:

- On the server, generate a random nonce and bind it to the user session
- Render an HTML page with a form, an input field for the email address, and a hidden input field for the email verification token with the nonce as an attribute on this field
  ```html
  <input name="email" type="email" autocomplete="email" />
  <input
    type="hidden"
    name="token"
    nonce="rAnD0m-VaLuE"
    autocomplete="email-verification-token"
  />
  ```
  You must use the `autocomplete` attributes as shown above.
- When the user enters their email address into the input field, the browser triggers the process to generate a token
- The token is stored in the hidden input and submitted to the server when the user completes the form
- On the server, you use the email, the nonce, and the site URL to verify the token using this library

### Verifying the token

#### Basic verification

Pass the email the user submitted, the token, the nonce from the session, and your site URL as the audience to verify the email address.

A successful result returns an object with an `ok` property set to `true` and a `value` property with the details of the verifcation. If the result is unsuccessful for any reason, then `ok` will be `false` and there will be an `error` property with the details of the error.

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

#### Timeouts and cancellation

To stop verification from going on too long if external services aren't available, you can pass a timeout for the whole process and timeouts for each individual remote call. You can also pass an abort signal to control cancelling the process yourself.

All request timeouts are disabled unless you configure them. This example uses a recommended timeout profile for interactive verification and an abort signal that can cancel the entire operation.

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

#### Express example

```javascript
import { verifyEmailToken } from "email-verification-api";

app.post("/emails", async (req, res) => {
  const { email, token } = req.body;
  const nonce = req.session.nonce;
  const audience = `${req.protocol}://${req.host}`;

  if (!token) {
    // Return a response from your OTP or magic-link fallback flow here.
    return;
  }

  const controller = new AbortController();
  const abortVerification = () => controller.abort();

  // Cancel verification if the client connection closes.
  res.once("close", abortVerification);

  const result = await verifyEmailToken({
    email,
    token,
    audience,
    nonce,
    signal: controller.signal,
    timeoutMs: 10_000,
    timeouts: {
      resolveTxtMs: 2_000,
      resolveHostMs: 2_000,
      metadataFetchMs: 4_000,
      jwksFetchMs: 4_000,
    },
  }).finally(() => res.off("close", abortVerification));

  if (result.ok) {
    console.log(`${result.value.email} is verified by ${result.value.issuer}`);
  } else if (result.error.code === "REQUEST_ABORTED") {
    // The client disconnected or the caller otherwise cancelled verification.
  } else if (result.error.code === "REQUEST_TIMEOUT") {
    // The overall or active operation deadline expired.
  } else {
    console.error(result.error);
    // Fall back to another email verification method.
  }
});
```

## API reference

`verifyEmailToken()` needs four values:

| Property   | Meaning                                                       |
| ---------- | ------------------------------------------------------------- |
| `token`    | The complete SD-JWT+KB presentation returned by the browser.  |
| `nonce`    | The exact nonce previously bound to this application session. |
| `email`    | The email address the application expects to verify.          |
| `audience` | The relying party's absolute HTTP(S) origin.                  |

Email comparison is case-insensitive and the nonce comparison is exact and case-sensitive. The audience must serialize to an origin: paths, query strings, fragments, and credentials are rejected.

There are optional arguments to `verifyEmailToken` too. These are:

| Property                | Default                        | Meaning                                              |
| ----------------------- | ------------------------------ | ---------------------------------------------------- |
| `maxTokenAgeSeconds`    | `300`                          | Maximum age of both the EVT and KB-JWT.              |
| `clockToleranceSeconds` | `60`                           | Clock skew allowed for age and future issue times.   |
| `fetch`                 | global `fetch`                 | Fetch implementation used for metadata and JWKS.     |
| `resolveTxt`            | `node:dns/promises.resolveTxt` | DNS TXT resolver.                                    |
| `resolveHost`           | `node:dns/promises.lookup`     | Address resolver used before each issuer request.    |
| `now`                   | `() => Date.now()`             | Clock returning Unix time in milliseconds.           |
| `signal`                | none                           | Cancels verification when its controller is aborted. |
| `timeoutMs`             | `null`                         | Overall verification timeout in milliseconds.        |
| `timeouts`              | `null`                         | Per-operation timeout values in milliseconds.        |

The `timeouts` object supports four independent limits:

| Property          | Default | Meaning                                    |
| ----------------- | ------- | ------------------------------------------ |
| `resolveTxtMs`    | `null`  | Timeout for the DNS TXT lookup.            |
| `resolveHostMs`   | `null`  | Timeout for each hostname safety lookup.   |
| `metadataFetchMs` | `null`  | Timeout for fetching and reading metadata. |
| `jwksFetchMs`     | `null`  | Timeout for fetching and reading the JWKS. |

Omitted timeout options and values set to `null` impose no limit. Timeout numbers must be positive finite integers in milliseconds. `timeoutMs` limits the entire verification call; before each external operation, the smaller of its configured timeout and the remaining overall time applies.

You can explicitly opt out at either level:

```javascript
await verifyEmailToken({
  token,
  nonce,
  email,
  audience,
  timeoutMs: null,
  timeouts: { jwksFetchMs: null },
});

await verifyEmailToken({
  token,
  nonce,
  email,
  audience,
  timeouts: null,
});
```

Exact age and tolerance boundaries are accepted. Both age-related timing options must be nonnegative numbers.

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

## Verification order

`verifyEmailToken()` performs all the required verifications of the token in the following order. If any stage fails the function returns with an error object that describes what failed.

1. `parseToken()` validates the [SD-JWT token](https://curity.io/resources/learn/selective-disclosure-jwt/) and resolves disclosures.
2. `validateExpectedValues()` rejects unexpected claims and stale tokens before network access.
3. `verifyDnsDelegation()` confirms that the email domain delegates to the claimed issuer. That is, the email verification is correctly served by the URL listed as the `iss` property in the token payload.
4. `verifyIssuerSignature()` retrieves metadata and [JWKS](https://stytch.com/blog/understanding-jwks/) from the issuer, then authenticates the EVT.
5. `verifyKeyBinding()` uses the authenticated `cnf.jwk` to verify the KB-JWT and checks its `sd_hash`.

## Errors and Results

Every verification stage returns `Result` or `Promise<Result>` rather than throwing for invalid input, malformed tokens, or dependency failures:

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

Use `stage` and `code` for application logic. `message` is a descriptive log message. `cause`, when present, is a normalized description of the underlying failure and should not be shown directly to end users.

The stages are `input`, `parse`, `expected-values`, `dns`, `issuer`, and `key-binding`.

The error codes are:

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
SD_HASH_MISMATCH                 REQUEST_ABORTED
REQUEST_TIMEOUT
```

`REQUEST_ABORTED` means the caller's `AbortSignal` cancelled verification. `REQUEST_TIMEOUT` means the overall deadline or the active operation's deadline expired.

The package also exports `ok()`, `err()`, `isOk()`, `isErr()`, the error schemas, and their inferred TypeScript types.

## Dependency injection

Pass network and clock implementations per verification call when a runtime, test, or application needs different behavior:

```ts
import { lookup, resolveTxt } from "node:dns/promises";
import { verifyEmailToken } from "email-verification-api";
import type { ResolveHost } from "email-verification-api";

declare const tokenFromBrowser: string;
declare const nonceForSession: string;

const resolveHost: ResolveHost = async (hostname) => {
  const addresses = await lookup(hostname, { all: true, verbatim: true });
  return addresses.flatMap(({ address, family }) =>
    family === 4 || family === 6 ? [{ address, family }] : [],
  );
};

const result = await verifyEmailToken({
  token: tokenFromBrowser,
  nonce: nonceForSession,
  email: "user@example.com",
  audience: "https://rp.example.com",
  fetch: globalThis.fetch,
  resolveTxt,
  resolveHost,
  now: () => Date.now(),
  maxTokenAgeSeconds: 300,
  clockToleranceSeconds: 60,
});
```

`resolveHost` has a deliberately small cross-runtime shape:

```ts
type ResolveHost = (
  hostname: string,
) => Promise<readonly { address: string; family: 4 | 6 }[]>;
```

The library calls `resolveHost` immediately before each metadata and JWKS request. It calls `resolveHost` twice when both URLs use the same hostname. It does so to verify that hosts resolve to valid, globally reachable IP addresses.

## Network security and runtime behavior

Each address must match its declared family. Each address must also be globally reachable. Verification fails if the answer is empty, malformed, too large, or mixes public and private addresses.

### HTTP requests

Issuer requests use credentialless `GET`. Redirect handling is set to `error`. Responses marked as redirected are rejected.

### Cancellation and timeouts

The signal for each Fetch request remains active while its JSON response body is read, so cancellation and timeouts actively abort both the request and body reading.

Node's DNS promise APIs do not accept an `AbortSignal`; verification still returns promptly when a DNS operation is cancelled or times out, but the underlying DNS work may finish later and its result is ignored.

Rejected promises, thrown values, and invalid dependency responses become failed `Result`s.

## Developing

To work on the library first clone it from GitHub:

```sh
git clone https://github.com/philnash/email-verification-api.git
cd email-verification-api
```

Install the dependencies:

```sh
npm install
```

Ensure that the tests pass:

```sh
npm test
```

Before making a pull request, ensure that all the checks (lint, format, types, tests) pass:

```sh
npm run check
```

## License

MIT
