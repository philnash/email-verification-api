# Email Verification Library Design

## Summary

Build an ESM-only TypeScript library that verifies Email Verification Protocol
presentation tokens (EVT+KB) for relying-party servers. The library exposes one
high-level verification function and one function for each verification stage.
Every public function returns a discriminated `Result` and does not throw.

The implementation follows the five relying-party validation stages described
in the Chrome origin-trial guidance and the rough implementation in the sibling
`email-verification-impl` repository. It adjusts the cryptographic order so the
issuer authenticates the holder key before the holder key is trusted.

The protocol remains an active Internet-Draft. This library targets the token
format used by the Chrome origin trial: an `evt+jwt` issuer JWT and a `kb+jwt`
key-binding JWT in SD-JWT+KB compact form.

## Goals

- Provide one function that verifies a token from the expected nonce, email,
  and relying-party audience.
- Expose each stage so an application can compose its own verification flow.
- Use Zod at every untrusted boundary and infer public data types from schemas.
- Support direct and selectively disclosed email claims.
- Verify DNS delegation, issuer metadata, JWKS, the EVT signature, the KB-JWT
  signature, and the SD-JWT hash binding.
- Return descriptive, programmatically distinguishable errors without throwing.
- Use readable, focused modules with a comprehensive test suite written before
  production behavior.
- Publish modern ESM JavaScript and TypeScript declarations.

## Non-goals

- Implement the browser-facing form API.
- Implement issuer token issuance, account discovery, WebAuthn, or HTTP Message
  Signatures.
- Persist nonces or bind them to application sessions; the application owns
  nonce generation, storage, expiry, and one-time use.
- Add caching, retry policies, logging, telemetry, or framework integrations.
- Verify that an email address can receive mail.

## Runtime and dependencies

The package is ESM-only and supports modern server runtimes that implement the
Node DNS promises API and Fetch API. It uses `node:dns/promises.resolveTxt` and
global `fetch` by default. Both can be replaced per call for testing or runtime
integration.

There are exactly three direct runtime dependencies:

- `zod`
- `@sd-jwt/core`
- `jose`

TypeScript, ESLint, typescript-eslint, Prettier, Node type declarations, and
other build-time packages are development dependencies.

## Public result model

Every public function returns a plain discriminated union:

```ts
export type Result<T, E = VerificationError> =
  | { ok: true; value: T }
  | { ok: false; error: E };
```

The package exports small `ok()` and `err()` constructors and narrowing helpers
if they improve call-site readability. It does not use a stateful Result class.

```ts
export type VerificationError = {
  stage: VerificationStage;
  code: VerificationErrorCode;
  message: string;
  cause?: string;
};
```

`stage` identifies the protocol stage, `code` is stable for application logic,
`message` is suitable for application logs, and `cause` contains a normalized
description of an underlying Zod, DNS, Fetch, JSON, SD-JWT, or JOSE failure when
that information is useful. Errors never include the compact token, signatures,
private key material, or full fetched response bodies.

Representative codes include:

- `INVALID_INPUT`
- `TOKEN_MALFORMED`
- `DISCLOSURE_INVALID`
- `EMAIL_MISMATCH`
- `EMAIL_NOT_VERIFIED`
- `NONCE_MISMATCH`
- `AUDIENCE_MISMATCH`
- `TOKEN_EXPIRED`
- `TOKEN_NOT_YET_VALID`
- `DNS_LOOKUP_FAILED`
- `DNS_DELEGATION_MISSING`
- `DNS_DELEGATION_AMBIGUOUS`
- `ISSUER_MISMATCH`
- `METADATA_FETCH_FAILED`
- `METADATA_INVALID`
- `JWKS_FETCH_FAILED`
- `JWKS_INVALID`
- `ALGORITHM_UNSUPPORTED`
- `EVT_SIGNATURE_INVALID`
- `KB_SIGNATURE_INVALID`
- `SD_HASH_MISMATCH`

All exported functions validate their public arguments and catch synchronous or
asynchronous failures from dependencies. A malformed call from JavaScript is a
failed `Result`, not an exception.

## High-level API

The primary function is:

```ts
export async function verifyEmailVerificationToken(
  input: VerifyEmailVerificationTokenInput,
): Promise<Result<VerifiedEmail>>;
```

Required input properties are:

```ts
type VerifyEmailVerificationTokenInput = {
  token: string;
  nonce: string;
  email: string;
  audience: string;
  maxTokenAgeSeconds?: number;
  clockToleranceSeconds?: number;
  fetch?: typeof globalThis.fetch;
  resolveTxt?: typeof import("node:dns/promises").resolveTxt;
  now?: () => number;
};
```

The defaults are:

- `maxTokenAgeSeconds`: 300 seconds
- `clockToleranceSeconds`: 60 seconds
- `fetch`: `globalThis.fetch`
- `resolveTxt`: `node:dns/promises.resolveTxt`
- `now`: a function returning `Date.now()`

`now` returns Unix time in milliseconds to match `Date.now()`. JWT `iat` values
remain integer seconds since the Unix epoch.

The successful result contains only authenticated values:

```ts
type VerifiedEmail = {
  email: string;
  issuer: string;
  audience: string;
  issuedAt: {
    evt: number;
    keyBinding: number;
  };
  claims: VerifiedEmailClaims;
};
```

The returned email preserves the token's spelling. The issuer is the canonical
issuer hostname, and the audience is the canonical URL origin.

## Staged pipeline and trust order

The high-level function composes five exported stages and stops at the first
error:

1. `parseToken()` decodes the SD-JWT+KB and validates its structure and
   disclosures with Zod.
2. `validateExpectedValues()` performs inexpensive local checks for email,
   `email_verified`, nonce, audience, and freshness.
3. `verifyDnsDelegation()` confirms that the email domain delegates to the EVT's
   claimed issuer.
4. `verifyIssuerSignature()` fetches and parses issuer metadata and JWKS, then
   verifies the EVT signature using an allowed issuer key.
5. `verifyKeyBinding()` verifies the KB-JWT signature using the now-authenticated
   `cnf.jwk` and verifies `sd_hash` against the exact presented EVT.

Stage 2 reads untrusted claims only as an early rejection that avoids unnecessary
network traffic. Its values are not reported as verified until stages 4 and 5
succeed.

The issuer JWKS verifies the EVT. The verified EVT authenticates `cnf.jwk`.
`cnf.jwk` verifies the KB-JWT, while `sd_hash` proves that the KB-JWT is bound to
the exact EVT presentation. This is why key-binding verification follows issuer
signature verification.

Each successful stage returns a named, Zod-derived intermediate value containing
the data required by the next stage. Stage APIs accept their normal predecessor
output and any stage-specific dependency, so developers can use them separately
without recreating internal parsing rules.

## Token parsing and schemas

The parser accepts only a nonempty string in SD-JWT+KB compact form. It uses
`@sd-jwt/core` for SD-JWT decoding and disclosure resolution, `jose` for JOSE
operations, and Zod schemas for all decoded values.

The EVT protected header requires:

- nonempty `alg`
- nonempty `kid`
- `typ: "evt+jwt"`

The resolved EVT payload requires:

- an issuer identifier in `iss`
- an integer epoch-seconds `iat`
- a public JWK at `cnf.jwk`
- a syntactically valid `email`
- `email_verified: true`

The KB protected header requires a nonempty `alg` and `typ: "kb+jwt"`. Its
payload requires an HTTP(S) origin in `aud`, a nonempty `nonce`, an integer
epoch-seconds `iat`, and a nonempty base64url `sd_hash`.

Schemas preserve safe additional public claims so the authenticated result can
expose them, but required security fields always use explicit schemas. Public JWK
schemas support public RSA, EC, and OKP keys and reject private parameters such
as `d`, `p`, `q`, `dp`, `dq`, `qi`, and symmetric `k`.

For a direct email claim, `email` appears in the EVT payload. For a selectively
disclosed claim, the signed payload contains the corresponding digest and the
presentation contains the disclosure. The parser verifies disclosure digests
and resolves both representations into the same EVT claims schema. Missing,
unmatched, malformed, duplicated, or conflicting email disclosures fail.

## Expected-value validation

Email comparison is case-insensitive, matching the origin-trial behavior. No
provider-specific transformations are performed: dots, tags, Unicode, and local
parts are not rewritten. The verified result preserves the resolved token email.

The expected audience and KB `aud` must each be an absolute HTTP(S) URL whose
serialized value is exactly its origin. The comparison uses `URL.origin`, which
normalizes host case and default ports but preserves meaningful scheme, hostname,
and non-default port differences. Paths, search parameters, fragments, userinfo,
and non-HTTP schemes are invalid.

The nonce comparison is exact and case-sensitive.

Both EVT and KB `iat` claims use the same configurable age and tolerance:

- A claim is expired when `now - iat` is greater than
  `maxTokenAgeSeconds + clockToleranceSeconds`.
- A claim is from the future when `iat - now` is greater than
  `clockToleranceSeconds`.
- Exact boundary values are accepted.

The age and tolerance options must be finite, nonnegative numbers. `now()` must
produce a finite Unix-millisecond value.

## DNS delegation

The DNS stage derives the domain from the already parsed expected email and
queries TXT records at `_email-verification.<email-domain>`. It always performs
the lookup, including when the email domain and issuer domain match.

TXT chunks belonging to one record are concatenated before parsing. There must
be exactly one TXT record, and it must contain exactly one delegation in the form
`iss=<issuer-identifier>`. Empty, malformed, missing, or multiple records fail.

The DNS issuer and EVT issuer are converted to a canonical lowercase hostname.
The library accepts either the draft hostname form (`accounts.example.com`) or
the origin-trial URL form (`https://accounts.example.com`) for compatibility.
URL-form issuer identifiers must use HTTPS and contain no path other than `/`,
userinfo, query, fragment, or explicit non-default port.

Resolver rejections such as `ENOTFOUND`, `ENODATA`, timeout, and arbitrary thrown
values become stage-specific failed results.

## Issuer metadata, JWKS, and EVT verification

The metadata URL is built as
`https://<canonical-issuer>/.well-known/email-verification`. The response must be
successful JSON matching the metadata schema. Required properties are
`issuance_endpoint` and `jwks_uri`. `signing_alg_values_supported` is optional
and defaults to `["EdDSA"]`; it must be nonempty when supplied and must never
contain `none`.

Metadata endpoint URLs must use HTTPS. Their host must equal the issuer hostname
or be a true subdomain separated by a DNS label boundary. A hostname such as
`issuer.example.attacker.test` does not match `issuer.example`. The same checks
apply to the final response URL after redirects when the runtime exposes it.

The library fetches `jwks_uri`, requires a successful JSON response, and parses a
bounded nonempty set of public JWKs. It verifies the EVT compact JWS with `jose`,
requires the EVT header algorithm to be present in the metadata algorithm list,
and selects the issuer key by `kid` and compatible key properties. Missing,
ambiguous, excessive, incompatible, or invalid keys fail without falling back to
an unadvertised algorithm.

Fetch rejection, non-success status, JSON parsing failure, and schema validation
failure have distinct error codes or messages that identify metadata versus JWKS
work without leaking response bodies.

## Key-binding verification

After the EVT signature succeeds, the library imports the authenticated public
`cnf.jwk` and verifies the compact KB-JWT signature with `jose`. It does not use
or accept private JWK material.

The expected `sd_hash` is SHA-256 over the exact SD-JWT presentation preceding
the KB-JWT, including its trailing tilde and all disclosure segments in their
presented order. The result is base64url encoded and compared to the KB claim.
This preserves selective-disclosure binding as well as the direct-claim form.

The KB algorithm must be compatible with `cnf.jwk`; `none` is rejected. A bad
signature and a bad hash return separate errors.

## Source organization

The initial structure is:

```text
src/
  result.ts
  schemas.ts
  parse-token.ts
  validate-expected-values.ts
  verify-dns-delegation.ts
  verify-issuer-signature.ts
  verify-key-binding.ts
  verify-token.ts
  index.ts
test/
  helpers/
  parse-token.test.ts
  validate-expected-values.test.ts
  verify-dns-delegation.test.ts
  verify-issuer-signature.test.ts
  verify-key-binding.test.ts
  verify-token.test.ts
  public-types.test.ts
```

Files remain small and responsibility-focused. Protocol stage names appear in
filenames and exports. Shared helpers are extracted only when duplication or a
security boundary justifies them; the design avoids inheritance, enums, broad
utility modules, and speculative abstraction.

Schemas live close enough to their consumers to remain understandable, while
shared schemas have one definition in `schemas.ts`. Types are inferred from
schemas rather than manually duplicated. Variables name protocol concepts
directly. Comments explain protocol and security reasoning rather than restating
syntax.

`index.ts` is the explicit public surface. Internal helpers are not exported by
accident.

## Testing strategy

Tests use `node:test` and `node:assert/strict`. A test TypeScript configuration
compiles `src` and `test` to an ignored temporary directory before Node executes
the emitted test files. No test framework or TypeScript runtime loader is added.

A fixture builder creates valid issuer and holder key pairs and generates signed
direct-claim and selectively disclosed EVT+KB tokens. All identities use reserved
example values such as `user@example.com`, `accounts.example.com`, and
`https://rp.example.com`. The existing parsed token guides the fixture shape but
no personal email address, localhost audience, production key, or production
signature is copied.

Tests are written before each production behavior and cover:

- valid end-to-end direct and selectively disclosed tokens;
- all malformed compact-token sections, headers, payloads, disclosures, and
  required claims;
- disclosure digest mismatch, missing disclosure, duplicate/conflicting email,
  and unsupported digest behavior;
- case-insensitive email success and meaningful email mismatch;
- false `email_verified`, nonce mismatch, and audience scheme, host, port, path,
  query, fragment, userinfo, and normalization cases;
- valid, expired, and future EVT and KB timestamps at, inside, and outside exact
  configured boundaries;
- DNS split chunks, same-domain delegation, missing, malformed, and duplicate
  records, issuer mismatch, `ENOTFOUND`, `ENODATA`, timeout, and arbitrary thrown
  values;
- metadata and JWKS Fetch rejection, non-success statuses, invalid JSON, invalid
  schema, unsafe or cross-issuer URLs, redirect host mismatch, absent algorithm
  defaults, `none`, and unsupported algorithms;
- empty, private, oversized, missing-`kid`, ambiguous, and incompatible JWKS;
- valid and invalid EVT signatures, KB signatures, holder keys, and `sd_hash`;
- each public function returning an error rather than throwing for malformed
  inputs and dependency failures;
- high-level short-circuiting so local failures avoid DNS and HTTP, DNS failures
  avoid HTTP, and issuer failures avoid key-binding success;
- TypeScript narrowing of `Result`, public declaration consumption, and the
  absence of unintended public exports.

Mocks are limited to unavoidable boundaries: DNS and HTTP adapters and the
clock. Cryptographic behavior uses real keys and real signatures.

## Tooling and quality gates

TypeScript uses strict settings and emits ESM JavaScript, declaration files, and
source maps to `dist`. A separate no-emit type-check covers source, tests, and
configuration as appropriate.

ESLint uses strict type-aware and stylistic typescript-eslint configurations.
Prettier has a write command for developers and a check-only command for CI.
`npm run check` never rewrites files and runs, in order, formatting verification,
type checking, linting, the production build, and the full test suite.

The package manifest exposes only the ESM entry point and its declarations via
`exports`, and publishes only the required distributable files and documentation.
The README documents installation, the high-level function, every stage, Result
narrowing, defaults, dependency injection, security responsibilities, and the
fact that the underlying protocol is experimental.

## References

- [Chrome origin-trial implementation guidance](https://developer.chrome.com/blog/email-verification-protocol-origin-trial)
- [Email Verification Protocol Internet-Draft](https://www.ietf.org/archive/id/draft-hardt-email-verification-00.html)
- The sibling `email-verification-impl` rough implementation
