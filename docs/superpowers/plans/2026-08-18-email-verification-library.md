# Email Verification Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an ESM-only TypeScript library that verifies direct and selectively disclosed Email Verification Protocol EVT+KB tokens through a readable staged API that never throws.

**Architecture:** A functional pipeline parses untrusted token data, validates expected values, verifies DNS delegation, authenticates the issuer-signed EVT, and finally verifies key binding with the authenticated holder key. Every public boundary uses Zod and returns a discriminated `Result`; DNS, Fetch, and clock dependencies have safe defaults and injectable seams.

**Tech Stack:** TypeScript 6, Node.js 20+, `node:test`, Zod 4, `@sd-jwt/core` 0.20, JOSE 6, ESLint 10 with typescript-eslint, and Prettier 3.

## Global Constraints

- The package is ESM-only and emits `.d.ts` declarations and source maps.
- The only direct runtime dependencies are `zod`, `@sd-jwt/core`, and `jose`.
- The primary export is `verifyEmailToken()`.
- Every exported function returns `Result` or `Promise<Result>` and must not throw for malformed input or dependency failure.
- Every untrusted boundary is parsed with Zod; do not use `as` casts to force unknown data into domain types.
- The default maximum token age is 300 seconds and the default clock tolerance is 60 seconds; both are configurable.
- Default network implementations are global `fetch` and `node:dns/promises.resolveTxt`, with per-call injection supported.
- Support both direct and selectively disclosed email claims.
- Verify in this trust order: parse, expected values, DNS delegation, EVT issuer signature, then KB signature and `sd_hash`.
- Tests use only `node:test` and `node:assert/strict` and are written before production behavior.
- Use small, focused modules, explicit intermediate values, protocol terminology, and comments only for security or protocol reasoning.
- Do not implement caching, but keep DNS/Fetch injection and immutable stage results compatible with memoizing wrappers and a future cache adapter.

---

## File Map

- `package.json`: package metadata, ESM exports, exact runtime dependency boundary, and quality scripts.
- `package-lock.json`: reproducible dependency graph.
- `tsconfig.json`: shared strict TypeScript settings.
- `tsconfig.build.json`: declaration-producing source build.
- `tsconfig.test.json`: source and test compilation into `.test-dist`.
- `eslint.config.js`: strict type-aware typescript-eslint configuration.
- `prettier.config.js`: stable formatting configuration.
- `.prettierignore`: generated files and internal process documents excluded
  from package formatting checks.
- `.gitignore`: generated and local-only files.
- `LICENSE`: MIT license matching the rough implementation.
- `src/result.ts`: Result constructors, narrowing helpers, error schema, and error normalization.
- `src/schemas.ts`: shared Zod schemas and schema-inferred domain types.
- `src/hash.ts`: SHA-256 adapter shared with SD-JWT and key-binding verification.
- `src/parse-token.ts`: SD-JWT+KB parsing and disclosure resolution.
- `src/validate-expected-values.ts`: expected email, nonce, audience, and time validation.
- `src/verify-dns-delegation.ts`: DNS issuer discovery and normalization.
- `src/verify-issuer-signature.ts`: metadata/JWKS retrieval and EVT verification.
- `src/verify-key-binding.ts`: KB-JWT signature and `sd_hash` verification.
- `src/verify-token.ts`: full orchestration and successful result construction.
- `src/index.ts`: intentional public exports only.
- `test/helpers/token-fixture.ts`: real issuer/holder keys and valid example.com token generation.
- `test/helpers/network-fixture.ts`: typed fake DNS and Fetch boundaries.
- `test/result.test.ts`: Result behavior and error normalization.
- `test/parse-token.test.ts`: compact token, schema, and disclosure cases.
- `test/validate-expected-values.test.ts`: expected-value and time boundaries.
- `test/verify-dns-delegation.test.ts`: delegation and DNS failure cases.
- `test/verify-issuer-signature.test.ts`: metadata, JWKS, algorithm, and EVT signature cases.
- `test/verify-key-binding.test.ts`: holder signature and hash-binding cases.
- `test/verify-token.test.ts`: end-to-end flow and short-circuit behavior.
- `test/public-types.test.ts`: public surface and Result narrowing compilation.
- `README.md`: installation, API, stage, error, caching seam, and security documentation.

## Task 1: Scaffold the strict package and Result foundation

**Files:**
- Create: `package.json`
- Create: `package-lock.json`
- Create: `tsconfig.json`
- Create: `tsconfig.build.json`
- Create: `tsconfig.test.json`
- Create: `eslint.config.js`
- Create: `prettier.config.js`
- Create: `.prettierignore`
- Create: `.gitignore`
- Create: `LICENSE`
- Create: `src/result.ts`
- Create: `test/result.test.ts`

**Interfaces:**
- Produces: `Result<T, E>`, `VerificationStage`, `VerificationErrorCode`, `VerificationError`, `ok()`, `err()`, `isOk()`, `isErr()`, and `errorCause()`.

- [ ] **Step 1: Add package and compiler configuration**

Create `package.json` with this shape, letting `npm install` write the resolved versions and lockfile:

```json
{
  "name": "email-verification",
  "version": "0.1.0",
  "description": "Verify Email Verification Protocol EVT+KB tokens",
  "type": "module",
  "license": "MIT",
  "engines": { "node": ">=20" },
  "files": ["dist", "README.md", "LICENSE"],
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js"
    }
  },
  "types": "./dist/index.d.ts",
  "scripts": {
    "clean:test": "node --eval \"import('node:fs').then(({ rmSync }) => rmSync('.test-dist', { recursive: true, force: true }))\"",
    "build": "tsc -p tsconfig.build.json",
    "typecheck": "tsc -p tsconfig.test.json --noEmit",
    "test:compile": "npm run clean:test && tsc -p tsconfig.test.json",
    "test": "npm run test:compile && node --test .test-dist/test/*.test.js",
    "lint": "eslint .",
    "format": "prettier --write .",
    "format:check": "prettier --check .",
    "check": "npm run format:check && npm run typecheck && npm run lint && npm run build && npm test"
  }
}
```

Install only the approved direct runtime dependencies:

```bash
npm install zod@^4.4.3 @sd-jwt/core@^0.20.0 jose@^6.2.9
```

Install tooling as development dependencies:

```bash
npm install --save-dev typescript@^6.0.3 @types/node@^26.2.0 eslint@^10.8.1 @eslint/js@^10.0.1 typescript-eslint@^8.67.0 prettier@^3.9.6
```

Use `module` and `moduleResolution` `NodeNext`, target `ES2022`, and enable at least `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `useUnknownInCatchVariables`, `noImplicitOverride`, `noPropertyAccessFromIndexSignature`, and `verbatimModuleSyntax`. `tsconfig.build.json` includes only `src`, writes declarations, declaration maps, JavaScript, and source maps to `dist`, and uses `rootDir: "src"`. `tsconfig.test.json` includes `src` and `test`, uses `rootDir: "."`, writes to `.test-dist`, and disables declarations.

Configure ESLint with `eslint.configs.recommended`, `tseslint.configs.strictTypeChecked`, and `tseslint.configs.stylisticTypeChecked`, with project service enabled and `dist`, `.test-dist`, and `node_modules` ignored. Configure Prettier with double quotes, semicolons, trailing commas, and an 80-character print width. In `.prettierignore`, exclude `node_modules/`, `dist/`, `.test-dist/`, `package-lock.json`, and `docs/superpowers/`. In `.gitignore`, exclude dependency directories, generated output, coverage output, `.env`, and OS/editor artifacts.

- [ ] **Step 2: Write the failing Result tests**

Create `test/result.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { err, errorCause, isErr, isOk, ok } from "../src/result.js";
import type { VerificationError } from "../src/result.js";

describe("Result", () => {
  it("constructs and narrows success", () => {
    const result = ok("verified");
    assert.equal(isOk(result), true);
    assert.equal(isErr(result), false);
    assert.deepEqual(result, { ok: true, value: "verified" });
  });

  it("constructs and narrows failure", () => {
    const error: VerificationError = {
      stage: "parse",
      code: "TOKEN_MALFORMED",
      message: "The token is malformed.",
    };
    const result = err(error);
    assert.equal(isErr(result), true);
    assert.equal(isOk(result), false);
    assert.deepEqual(result, { ok: false, error });
  });

  it("normalizes Error, string, and arbitrary causes", () => {
    assert.equal(errorCause(new Error("network down")), "network down");
    assert.equal(errorCause("timeout"), "timeout");
    assert.equal(errorCause({ code: "ENOTFOUND" }), '{"code":"ENOTFOUND"}');
  });
});
```

- [ ] **Step 3: Run the test to verify RED**

Run: `npm test`

Expected: compilation fails because `src/result.ts` does not exist.

- [ ] **Step 4: Implement the minimal Result foundation**

Create `src/result.ts` with literal unions rather than enums:

```ts
import * as z from "zod";

export const VerificationStageSchema = z.enum([
  "input",
  "parse",
  "expected-values",
  "dns",
  "issuer",
  "key-binding",
]);

export const VerificationErrorCodeSchema = z.enum([
  "INVALID_INPUT",
  "TOKEN_MALFORMED",
  "DISCLOSURE_INVALID",
  "EMAIL_MISMATCH",
  "EMAIL_NOT_VERIFIED",
  "NONCE_MISMATCH",
  "AUDIENCE_MISMATCH",
  "TOKEN_EXPIRED",
  "TOKEN_NOT_YET_VALID",
  "DNS_LOOKUP_FAILED",
  "DNS_DELEGATION_MISSING",
  "DNS_DELEGATION_AMBIGUOUS",
  "ISSUER_MISMATCH",
  "METADATA_FETCH_FAILED",
  "METADATA_INVALID",
  "JWKS_FETCH_FAILED",
  "JWKS_INVALID",
  "ALGORITHM_UNSUPPORTED",
  "EVT_SIGNATURE_INVALID",
  "KB_SIGNATURE_INVALID",
  "SD_HASH_MISMATCH",
]);

export const VerificationErrorSchema = z.object({
  stage: VerificationStageSchema,
  code: VerificationErrorCodeSchema,
  message: z.string().min(1),
  cause: z.string().min(1).optional(),
});

export type VerificationStage = z.infer<typeof VerificationStageSchema>;
export type VerificationErrorCode = z.infer<
  typeof VerificationErrorCodeSchema
>;
export type VerificationError = z.infer<typeof VerificationErrorSchema>;

export type Result<T, E = VerificationError> =
  | { ok: true; value: T }
  | { ok: false; error: E };

export const ok = <T>(value: T): Result<T, never> => ({ ok: true, value });
export const err = <E>(error: E): Result<never, E> => ({ ok: false, error });
export const isOk = <T, E>(result: Result<T, E>): result is { ok: true; value: T } =>
  result.ok;
export const isErr = <T, E>(result: Result<T, E>): result is { ok: false; error: E } =>
  !result.ok;

export function errorCause(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  if (typeof cause === "string") return cause;
  try {
    return JSON.stringify(cause) ?? String(cause);
  } catch {
    try {
      return String(cause);
    } catch {
      return "Unknown error";
    }
  }
}
```

Format the multiline helpers as Prettier requires; do not weaken lint rules to accept unreadable code.

- [ ] **Step 5: Verify GREEN and the initial quality gates**

Run: `npm test && npm run typecheck && npm run lint && npm run format:check`

Expected: all commands pass with three Result tests.

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json tsconfig*.json eslint.config.js prettier.config.js .prettierignore .gitignore LICENSE src/result.ts test/result.test.ts
git commit -m "chore: scaffold strict TypeScript library"
```

## Task 2: Generate valid example tokens and parse direct or disclosed claims

**Files:**
- Create: `src/schemas.ts`
- Create: `src/hash.ts`
- Create: `src/parse-token.ts`
- Create: `test/helpers/token-fixture.ts`
- Create: `test/parse-token.test.ts`

**Interfaces:**
- Consumes: `Result`, `ok()`, `err()`, and `errorCause()` from Task 1.
- Produces: `PublicJwkSchema`, `EvtHeaderSchema`, `EvtClaimsSchema`, `KbHeaderSchema`, `KbClaimsSchema`, `ParsedTokenSchema`, corresponding inferred types, `hashFunction(data, algorithm)`, and `parseToken(token)`.

- [ ] **Step 1: Write the token fixture helper before parser implementation**

Create a fixture builder using real JOSE signatures and only reserved example identities:

```ts
import { Disclosure, uint8ArrayToBase64Url } from "@sd-jwt/core";
import {
  CompactSign,
  exportJWK,
  generateKeyPair,
  type CompactJWSHeaderParameters,
} from "jose";
import { createHash } from "node:crypto";

const encoder = new TextEncoder();
type SigningKey = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];

export type TokenFixtureOptions = {
  email?: string;
  issuer?: string;
  audience?: string;
  nonce?: string;
  evtIssuedAt?: number;
  kbIssuedAt?: number;
  discloseEmail?: boolean;
  emailVerified?: boolean;
};

export async function createTokenFixture(options: TokenFixtureOptions = {}) {
  const email = options.email ?? "user@example.com";
  const issuer = options.issuer ?? "https://accounts.example.com";
  const audience = options.audience ?? "https://rp.example.com";
  const nonce = options.nonce ?? "example-nonce";
  const evtIssuedAt = options.evtIssuedAt ?? 1_800_000_000;
  const kbIssuedAt = options.kbIssuedAt ?? evtIssuedAt;
  const issuerKeys = await generateKeyPair("Ed25519", { extractable: true });
  const holderKeys = await generateKeyPair("Ed25519", { extractable: true });
  const issuerPublicJwk = await exportJWK(issuerKeys.publicKey);
  const holderPublicJwk = await exportJWK(holderKeys.publicKey);
  issuerPublicJwk.kid = "issuer-key";
  issuerPublicJwk.alg = "EdDSA";

  const payload: Record<string, unknown> = {
    iss: issuer,
    iat: evtIssuedAt,
    cnf: { jwk: holderPublicJwk },
    email_verified: options.emailVerified ?? true,
  };
  const disclosures: string[] = [];

  if (options.discloseEmail) {
    const disclosure = new Disclosure(["example-salt", "email", email]);
    const digest = createHash("sha256")
      .update(disclosure.encode())
      .digest("base64url");
    payload._sd_alg = "sha-256";
    payload._sd = [digest];
    disclosures.push(disclosure.encode());
  } else {
    payload.email = email;
  }

  const evt = await signCompact(
    payload,
    { alg: "EdDSA", kid: "issuer-key", typ: "evt+jwt" },
    issuerKeys.privateKey,
  );
  const presentation = `${evt}~${disclosures.map((value) => `${value}~`).join("")}`;
  const sdHash = uint8ArrayToBase64Url(
    createHash("sha256").update(presentation).digest(),
  );
  const kb = await signCompact(
    { aud: audience, nonce, iat: kbIssuedAt, sd_hash: sdHash },
    { alg: "EdDSA", typ: "kb+jwt" },
    holderKeys.privateKey,
  );

  return {
    token: `${presentation}${kb}`,
    evt,
    kb,
    presentation,
    email,
    issuer,
    audience,
    nonce,
    evtIssuedAt,
    kbIssuedAt,
    issuerPublicJwk,
    holderPublicJwk,
  };
}

async function signCompact(
  payload: Record<string, unknown>,
  header: CompactJWSHeaderParameters,
  key: SigningKey,
) {
  return new CompactSign(encoder.encode(JSON.stringify(payload)))
    .setProtectedHeader(header)
    .sign(key);
}
```

- [ ] **Step 2: Write failing parser tests**

Create tests for these exact cases:

```ts
describe("parseToken", () => {
  it("parses a direct email EVT+KB token", async () => {
    const fixture = await createTokenFixture();
    const result = await parseToken(fixture.token);
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.value.evt.claims.email, "user@example.com");
    assert.deepEqual(result.value.disclosures, []);
    assert.equal(result.value.presentation, fixture.presentation);
  });

  it("resolves a selectively disclosed email", async () => {
    const fixture = await createTokenFixture({ discloseEmail: true });
    const result = await parseToken(fixture.token);
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.value.evt.claims.email, "user@example.com");
    assert.equal(result.value.disclosures.length, 1);
  });
});
```

Add table-driven failures for a non-string value passed from JavaScript, empty token, JWT without `~`, missing KB-JWT, extra empty segment, invalid base64url, invalid JSON, wrong segment count, missing or wrong `typ`, empty `alg`, missing EVT `kid`, missing claims, invalid email, noninteger `iat`, nonboolean `email_verified`, invalid/private `cnf.jwk`, missing KB claims, invalid `aud`, empty nonce, malformed disclosure, unsupported `_sd_alg`, unmatched disclosure, duplicate digest, direct-plus-disclosed email conflict, and invalid base64url `sd_hash`. Assert `result.ok === false`, the exact `stage`, and either `TOKEN_MALFORMED` or `DISCLOSURE_INVALID`.

- [ ] **Step 3: Run parser tests to verify RED**

Run: `npm run test:compile && node --test --test-name-pattern=parseToken .test-dist/test/*.test.js`

Expected: compilation fails because the schemas, hash adapter, and parser do not exist.

- [ ] **Step 4: Implement Zod schemas and hashing**

In `src/schemas.ts`, define reusable primitives and infer every type:

```ts
const base64url = z.base64url().min(1);
const nonempty = z.string().min(1);
const epochSeconds = z.number().int().nonnegative();

export const PublicJwkSchema = z
  .discriminatedUnion("kty", [
    z.looseObject({ kty: z.literal("RSA"), e: base64url, n: base64url }),
    z.looseObject({
      kty: z.literal("EC"),
      crv: nonempty,
      x: base64url,
      y: base64url,
    }),
    z.looseObject({
      kty: z.literal("OKP"),
      crv: nonempty,
      x: base64url,
    }),
  ])
  .superRefine(rejectPrivateJwkParameters);

export const EvtHeaderSchema = z.looseObject({
  alg: nonempty.refine((value) => value !== "none"),
  kid: nonempty,
  typ: z.literal("evt+jwt"),
});
export const EvtClaimsSchema = z.looseObject({
  iss: nonempty,
  iat: epochSeconds,
  cnf: z.object({ jwk: PublicJwkSchema }),
  email: z.email(),
  email_verified: z.boolean(),
});
export const KbHeaderSchema = z.looseObject({
  alg: nonempty.refine((value) => value !== "none"),
  typ: z.literal("kb+jwt"),
});
export const KbClaimsSchema = z.looseObject({
  aud: z.url(),
  nonce: nonempty,
  iat: epochSeconds,
  sd_hash: base64url,
});
```

Include common optional public JWK properties (`alg`, `kid`, `use`, `key_ops`, `ext`, `x5c`, `x5t`, `x5t#S256`, and `x5u`) and reject `d`, `dp`, `dq`, `k`, `oth`, `p`, `priv`, `q`, and `qi` through `superRefine`. Define Zod schemas for compact JWT pieces and `ParsedToken` rather than hand-writing duplicate interfaces.

In `src/hash.ts`, implement the SD-JWT `Hasher` without a cast:

```ts
import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import type { Hasher } from "@sd-jwt/core";

export const hashFunction: Hasher = (data, algorithm) => {
  const input = typeof data === "string" ? data : Buffer.from(data);
  return createHash(algorithm.replaceAll("-", "")).update(input).digest();
};
```

- [ ] **Step 5: Implement `parseToken()` minimally**

Use `splitSdJwt()`, `decodeSdJwt()`, and `unpack()` from `@sd-jwt/core`. Parse the public input first, require a KB segment, parse headers and raw payloads, resolve disclosures, and parse the resolved claims. Derive `presentation` by slicing the original token through its last tilde so the exact bytes used by `sd_hash` are retained.

Check disclosure integrity explicitly:

1. `unpack()` returns `disclosureKeymap`; compare its digest values with every decoded disclosure digest.
2. Reject any supplied disclosure that was not referenced.
3. Reject an email present both directly in the raw payload and through a disclosure.
4. Let `@sd-jwt/core` reject duplicate digests and invalid disclosure encoding.

Wrap the complete operation in `try/catch`, mapping Zod/compact-token failures to `TOKEN_MALFORMED` and disclosure failures to `DISCLOSURE_INVALID`. Never return the library's generic unchecked type; pass the final object through `ParsedTokenSchema.safeParse()`.

- [ ] **Step 6: Verify GREEN and refactor parser names**

Run: `npm run test:compile && node --test --test-name-pattern=parseToken .test-dist/test/*.test.js`

Expected: all direct, disclosed, malformed, and disclosure tests pass.

Run: `npm run typecheck && npm run lint && npm run format:check`

Expected: pass without unsafe assignments, assertions, or unused exports.

- [ ] **Step 7: Commit**

```bash
git add src/schemas.ts src/hash.ts src/parse-token.ts test/helpers/token-fixture.ts test/parse-token.test.ts
git commit -m "feat: parse email verification tokens"
```

## Task 3: Validate expected email, nonce, audience, and freshness

**Files:**
- Create: `src/validate-expected-values.ts`
- Create: `test/validate-expected-values.test.ts`
- Modify: `src/schemas.ts`

**Interfaces:**
- Consumes: `ParsedToken` from Task 2.
- Produces: `ExpectedValuesInputSchema`, `ExpectedValuesValidatedTokenSchema`, `ExpectedValuesValidatedToken`, and `validateExpectedValues(input): Result<ExpectedValuesValidatedToken>`.

- [ ] **Step 1: Write failing expected-value tests**

Use a parsed valid fixture and a fixed `now = () => 1_800_000_000_000`. Verify the default success path and case-insensitive email matching:

```ts
const result = validateExpectedValues({
  token: parsed,
  email: "USER@example.com",
  nonce: fixture.nonce,
  audience: fixture.audience,
  now: () => fixture.evtIssuedAt * 1_000,
});
assert.equal(result.ok, true);
```

Add exact-code tests for:

- invalid input objects, empty nonce, invalid email, invalid audience, negative/NaN/infinite age or tolerance, and invalid `now()` output;
- email mismatch and `email_verified` false supplied through a deliberately schema-valid parser fixture helper;
- exact nonce mismatch;
- canonical audience equality for host case and default port;
- audience mismatch for scheme, hostname, non-default port, and subdomain;
- rejection when either expected or token audience contains a path, query, fragment, userinfo, or non-HTTP(S) scheme;
- EVT and KB timestamps exactly at, one second inside, and one second outside both the old and future boundaries;
- custom age and tolerance values overriding the defaults.

- [ ] **Step 2: Run expected-value tests to verify RED**

Run: `npm run test:compile && node --test --test-name-pattern=validateExpectedValues .test-dist/test/*.test.js`

Expected: compilation fails because the validator does not exist.

- [ ] **Step 3: Implement canonical origin and time validation**

Define an input schema with `maxTokenAgeSeconds` defaulting to `300`, `clockToleranceSeconds` defaulting to `60`, and a validated function for `now`. Re-parse `token` with `ParsedTokenSchema` at the public boundary.

Use a focused helper:

```ts
function canonicalOrigin(value: string): Result<string> {
  const parsed = new URL(value);
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.href !== `${parsed.origin}/`
  ) {
    return err({
      stage: "expected-values",
      code: "AUDIENCE_MISMATCH",
      message: "Audience must be an HTTP(S) origin without credentials, path, query, or fragment.",
    });
  }
  return ok(parsed.origin);
}
```

Do not compare lowercased raw URLs. Compare canonical origins. Validate each EVT and KB timestamp independently using integer seconds derived from `Math.floor(nowMilliseconds / 1_000)`. Exact boundary values pass.

Return a Zod-parsed immutable-style object containing the parsed token, canonical expected email, canonical audience, and effective timing configuration. Do not mutate `ParsedToken`.

- [ ] **Step 4: Verify GREEN**

Run: `npm run test:compile && node --test --test-name-pattern=validateExpectedValues .test-dist/test/*.test.js`

Expected: all expected-value tests pass.

Run: `npm run typecheck && npm run lint && npm run format:check`

Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add src/schemas.ts src/validate-expected-values.ts test/validate-expected-values.test.ts
git commit -m "feat: validate expected token values"
```

## Task 4: Verify DNS delegation without throwing

**Files:**
- Create: `src/verify-dns-delegation.ts`
- Create: `test/helpers/network-fixture.ts`
- Create: `test/verify-dns-delegation.test.ts`
- Modify: `src/schemas.ts`

**Interfaces:**
- Consumes: `ExpectedValuesValidatedToken` from Task 3.
- Produces: `DnsVerifiedTokenSchema`, `DnsVerifiedToken`, `ResolveTxt`, `canonicalIssuer()`, and `verifyDnsDelegation(input): Promise<Result<DnsVerifiedToken>>`.

- [ ] **Step 1: Write failing DNS tests**

The fake resolver records targets and returns `string[][]`:

```ts
it("joins TXT chunks and verifies the sole issuer", async () => {
  const calls: string[] = [];
  const result = await verifyDnsDelegation({
    token: validated,
    resolveTxt: async (target) => {
      calls.push(target);
      return [["iss=accounts.", "example.com"]];
    },
  });
  assert.equal(result.ok, true);
  assert.deepEqual(calls, ["_email-verification.example.com"]);
  if (result.ok) assert.equal(result.value.issuer, "accounts.example.com");
});
```

Add tests for hostname and HTTPS URL issuer claim compatibility, host case and trailing-dot normalization, same-domain issuers still requiring DNS, no records, more than one record, empty record, missing `iss=`, multiple `iss=` values, whitespace or path injection, insecure URL-form issuer, URL userinfo/query/fragment/port, DNS/EVT mismatch, label-boundary mismatch, `ENOTFOUND`, `ENODATA`, `ETIMEOUT`, rejected strings, and rejected arbitrary objects. Assert no case throws.

- [ ] **Step 2: Run DNS tests to verify RED**

Run: `npm run test:compile && node --test --test-name-pattern=verifyDnsDelegation .test-dist/test/*.test.js`

Expected: compilation fails because the DNS stage does not exist.

- [ ] **Step 3: Implement issuer normalization and DNS verification**

Use `resolveTxt` from `node:dns/promises` as the default. Parse optional resolver functions through a Zod custom predicate before calling them.

`canonicalIssuer(value)` accepts:

- a DNS hostname, optionally with one final dot; or
- an HTTPS URL with no userinfo, non-default port, query, fragment, or path other than `/`.

Return a lowercase hostname without a trailing dot. Validate hostname labels rather than accepting arbitrary URL strings.

Derive the email domain from the validated email, query exactly `_email-verification.<domain>`, concatenate each TXT record's chunks, require exactly one record with exactly one `iss=` prefix, normalize it, and compare it exactly with the normalized EVT issuer. Catch all resolver failures and return `DNS_LOOKUP_FAILED` with `errorCause()`.

- [ ] **Step 4: Verify GREEN**

Run: `npm run test:compile && node --test --test-name-pattern=verifyDnsDelegation .test-dist/test/*.test.js`

Expected: all DNS and issuer normalization tests pass.

Run: `npm run typecheck && npm run lint && npm run format:check`

Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add src/schemas.ts src/verify-dns-delegation.ts test/helpers/network-fixture.ts test/verify-dns-delegation.test.ts
git commit -m "feat: verify issuer DNS delegation"
```

## Task 5: Discover issuer keys and verify the EVT signature

**Files:**
- Create: `src/verify-issuer-signature.ts`
- Create: `test/verify-issuer-signature.test.ts`
- Modify: `src/schemas.ts`
- Modify: `test/helpers/network-fixture.ts`
- Modify: `test/helpers/token-fixture.ts`

**Interfaces:**
- Consumes: `DnsVerifiedToken` from Task 4.
- Produces: `IssuerMetadataSchema`, `JsonWebKeySetSchema`, `IssuerVerifiedTokenSchema`, `IssuerVerifiedToken`, and `verifyIssuerSignature(input): Promise<Result<IssuerVerifiedToken>>`.

- [ ] **Step 1: Extend fixtures for metadata and JWKS responses**

Add a Fetch fixture that maps exact URLs to `Response` objects and records calls:

```ts
export function createFetchFixture(routes: Readonly<Record<string, Response>>) {
  const calls: string[] = [];
  const fetch: typeof globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push(url);
    return routes[url] ?? new Response("not found", { status: 404 });
  };
  return { fetch, calls };
}
```

Use a fresh `Response` per call when body reuse matters. Extend the token fixture with a method that re-signs a mutated EVT and rebuilds the KB hash/signature, plus access to the issuer private key only inside test helpers.

- [ ] **Step 2: Write failing issuer verification tests**

The valid path must fetch in this order:

1. `https://accounts.example.com/.well-known/email-verification`
2. the validated `jwks_uri`

Metadata is:

```json
{
  "issuance_endpoint": "https://accounts.example.com/email-verification/issue",
  "jwks_uri": "https://keys.accounts.example.com/email-verification/jwks",
  "signing_alg_values_supported": ["EdDSA"]
}
```

The JWKS is `{ "keys": [fixture.issuerPublicJwk] }`. Assert valid issuer verification succeeds.

Add exact failure tests for:

- metadata Fetch rejection, non-2xx status, JSON rejection, non-object JSON, missing properties, invalid URL, HTTP URL, cross-issuer host, suffix-confusion host, unsafe redirect response URL, empty algorithm list, `none`, and algorithm mismatch;
- absent algorithm list defaulting to `EdDSA`;
- JWKS Fetch rejection, non-2xx status, JSON rejection, empty keys, more than 20 keys, private JWK, no matching `kid`, incompatible `alg`/key type, duplicate ambiguous candidates, and more than 10 matching candidates;
- tampered EVT payload, signature, header `kid`, and header `alg`;
- arbitrary thrown values from Fetch and `Response.json()`;
- no JWKS request after metadata failure and no signature attempt after JWKS failure.

- [ ] **Step 3: Run issuer tests to verify RED**

Run: `npm run test:compile && node --test --test-name-pattern=verifyIssuerSignature .test-dist/test/*.test.js`

Expected: compilation fails because issuer schemas and verification do not exist.

- [ ] **Step 4: Implement metadata and JWKS schemas**

Parse metadata with:

```ts
export const IssuerMetadataSchema = z.looseObject({
  issuance_endpoint: z.url(),
  jwks_uri: z.url(),
  signing_alg_values_supported: z
    .array(z.string().min(1).refine((value) => value !== "none"))
    .min(1)
    .default(["EdDSA"]),
});

export const JsonWebKeySetSchema = z.object({
  keys: z.array(PublicJwkSchema).min(1).max(20),
});
```

Add a hostname-bound URL helper that parses with `URL`, requires HTTPS, and accepts only `host === issuer` or `host.endsWith(`.${issuer}`)`. Apply it to both metadata endpoint fields and nonempty `Response.url` values.

- [ ] **Step 5: Implement Fetch handling and EVT verification**

Fetch and parse metadata and JWKS in separate focused helpers that return `Result`, distinguish metadata from JWKS errors, and never include response bodies in errors.

Verify the exact EVT compact string from `ParsedToken` with `compactVerify()` and a local JWK set. Restrict JOSE to `[token.evt.header.alg]` only after confirming metadata advertises it. Require selection by the header's `kid`.

Handle `errors.JWKSMultipleMatchingKeys` using the rough implementation's bounded iteration: try at most 10 candidates; continue only after `JWSSignatureVerificationFailed`; return an ambiguity/excess error for more candidates or non-signature failures. Do not silently accept an unrelated JOSE error.

Return a Zod-parsed `IssuerVerifiedToken` containing the DNS-verified token and parsed metadata, but not private or mutable key material.

- [ ] **Step 6: Verify GREEN**

Run: `npm run test:compile && node --test --test-name-pattern=verifyIssuerSignature .test-dist/test/*.test.js`

Expected: all issuer, metadata, JWKS, and EVT signature tests pass.

Run: `npm run typecheck && npm run lint && npm run format:check`

Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add src/schemas.ts src/verify-issuer-signature.ts test/helpers/network-fixture.ts test/helpers/token-fixture.ts test/verify-issuer-signature.test.ts
git commit -m "feat: verify issuer signatures"
```

## Task 6: Verify authenticated key binding and SD-JWT hash

**Files:**
- Create: `src/verify-key-binding.ts`
- Create: `test/verify-key-binding.test.ts`
- Modify: `src/schemas.ts`
- Modify: `test/helpers/token-fixture.ts`

**Interfaces:**
- Consumes: `IssuerVerifiedToken` from Task 5 and `hashFunction()` from Task 2.
- Produces: `KeyBindingVerifiedTokenSchema`, `KeyBindingVerifiedToken`, and `verifyKeyBinding(input): Promise<Result<KeyBindingVerifiedToken>>`.

- [ ] **Step 1: Write failing key-binding tests**

Create an issuer-verified valid fixture without bypassing the real EVT signature stage. Assert `verifyKeyBinding()` succeeds for both direct and selectively disclosed email tokens.

Add separate tests for:

- mutated KB payload with original signature;
- KB signed by an unrelated holder key;
- malformed or unsupported holder JWK;
- KB header `alg: "none"` and an algorithm incompatible with the holder key;
- `sd_hash` for another EVT;
- `sd_hash` calculated without the trailing tilde;
- selectively disclosed presentation hash calculated without its disclosure;
- valid hash but invalid KB signature;
- invalid signature but valid-looking hash;
- a JOSE implementation failure becoming `KB_SIGNATURE_INVALID` rather than throwing.

Assert bad signatures and bad hashes use distinct codes.

- [ ] **Step 2: Run key-binding tests to verify RED**

Run: `npm run test:compile && node --test --test-name-pattern=verifyKeyBinding .test-dist/test/*.test.js`

Expected: compilation fails because key-binding verification does not exist.

- [ ] **Step 3: Implement holder verification and exact presentation hashing**

Re-parse the public input with `IssuerVerifiedTokenSchema`. Import the authenticated `cnf.jwk` and verify the exact compact KB-JWT with `compactVerify()`, restricted to the KB header algorithm. Catch import and signature failures as `KB_SIGNATURE_INVALID`.

Compute SHA-256 over `parsedToken.presentation`, which already ends at the final tilde before the KB-JWT and includes all presented disclosures in exact order:

```ts
const expectedHash = createHash("sha256")
  .update(parsedToken.presentation)
  .digest("base64url");
```

Use `timingSafeEqual` only after comparing decoded byte lengths, or use JOSE/SD-JWT's validated constant-time utility if available. Do not compare secrets with a home-grown loop. A mismatch returns `SD_HASH_MISMATCH`.

Return a Zod-parsed stage value and do not re-run issuer verification.

- [ ] **Step 4: Verify GREEN**

Run: `npm run test:compile && node --test --test-name-pattern=verifyKeyBinding .test-dist/test/*.test.js`

Expected: all holder signature and hash tests pass for direct and disclosed tokens.

Run: `npm run typecheck && npm run lint && npm run format:check`

Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add src/schemas.ts src/verify-key-binding.ts test/helpers/token-fixture.ts test/verify-key-binding.test.ts
git commit -m "feat: verify token key binding"
```

## Task 7: Compose `verifyEmailToken()` and prove short-circuiting

**Files:**
- Create: `src/verify-token.ts`
- Create: `src/index.ts`
- Create: `test/verify-token.test.ts`
- Create: `test/public-types.test.ts`
- Modify: `src/schemas.ts`

**Interfaces:**
- Consumes: all five stage functions and intermediate types.
- Produces: `VerifyEmailTokenInputSchema`, `VerifyEmailTokenInput`, `VerifiedEmailSchema`, `VerifiedEmail`, and `verifyEmailToken(input): Promise<Result<VerifiedEmail>>`; public stage exports from `src/index.ts`.

- [ ] **Step 1: Write failing end-to-end tests**

Create one valid direct and one valid selectively disclosed end-to-end case with injected DNS, Fetch, and clock. Assert the result shape exactly:

```ts
assert.deepEqual(result, {
  ok: true,
  value: {
    email: "user@example.com",
    issuer: "accounts.example.com",
    audience: "https://rp.example.com",
    issuedAt: {
      evt: fixture.evtIssuedAt,
      keyBinding: fixture.kbIssuedAt,
    },
    claims: expectedAuthenticatedClaims,
  },
});
```

Add end-to-end failure assertions for every stage code. Track dependency calls to prove:

- parse and expected-value failures call neither DNS nor Fetch;
- DNS failure calls no Fetch;
- metadata failure calls no JWKS endpoint;
- EVT signature failure never reports key-binding success;
- KB failure returns only after DNS, metadata, JWKS, and EVT verification;
- rejected DNS/Fetch callbacks and throwing `now()` never escape;
- the parsed options retain the documented default dependency functions when callers omit overrides, without performing live network requests in the test suite.

- [ ] **Step 2: Write the failing public type test**

Import only from `../src/index.js` and compile this narrowing:

```ts
const result = await verifyEmailToken(input);
if (result.ok) {
  const email: string = result.value.email;
  const issuer: string = result.value.issuer;
  void email;
  void issuer;
} else {
  const code: VerificationErrorCode = result.error.code;
  void code;
}
```

Import every intended stage and public schema/type. Add `@ts-expect-error` checks for an invalid success/error access and for an internal helper that must not be exported.

- [ ] **Step 3: Run orchestration tests to verify RED**

Run: `npm run test:compile && node --test --test-name-pattern='verifyEmailToken|public API' .test-dist/test/*.test.js`

Expected: compilation fails because the orchestrator and public entry point do not exist.

- [ ] **Step 4: Implement input and success schemas**

The input schema requires token, nonce, email, and audience; defaults timing options; validates optional Fetch, resolver, and clock functions; and passes only parsed values into stages. `VerifiedEmailSchema` contains authenticated email, canonical issuer and audience, the two integer timestamps, and resolved authenticated EVT claims.

- [ ] **Step 5: Implement the readable staged composition**

Write one explicit block per stage:

```ts
const parsedInput = VerifyEmailTokenInputSchema.safeParse(input);
if (!parsedInput.success) {
  return err({
    stage: "input",
    code: "INVALID_INPUT",
    message: "Email token verification input is invalid.",
    cause: z.prettifyError(parsedInput.error),
  });
}

const parsed = await parseToken(parsedInput.data.token);
if (!parsed.ok) return parsed;

const expected = validateExpectedValues({
  token: parsed.value,
  email: parsedInput.data.email,
  nonce: parsedInput.data.nonce,
  audience: parsedInput.data.audience,
  maxTokenAgeSeconds: parsedInput.data.maxTokenAgeSeconds,
  clockToleranceSeconds: parsedInput.data.clockToleranceSeconds,
  now: parsedInput.data.now,
});
if (!expected.ok) return expected;

const delegated = await verifyDnsDelegation({
  token: expected.value,
  resolveTxt: parsedInput.data.resolveTxt,
});
if (!delegated.ok) return delegated;

const issuerVerified = await verifyIssuerSignature({
  token: delegated.value,
  fetch: parsedInput.data.fetch,
});
if (!issuerVerified.ok) return issuerVerified;

const keyBound = await verifyKeyBinding({ token: issuerVerified.value });
if (!keyBound.ok) return keyBound;
```

Do not introduce a generic async pipeline abstraction. Construct the final value from `keyBound.value`, parse it with `VerifiedEmailSchema`, and return `ok(value)`. Wrap input parsing and unexpected dependency behavior so the public function cannot throw.

Export only the documented function, five stages, Result utilities, public schemas needed for validation/integration, and their inferred types from `src/index.ts`. Do not export internal URL, issuer, Fetch, JOSE, or error-construction helpers.

- [ ] **Step 6: Verify GREEN and the full suite**

Run: `npm test`

Expected: all unit, end-to-end, and public type tests pass.

Run: `npm run typecheck && npm run lint && npm run format:check && npm run build`

Expected: all pass and `dist/index.js`, `dist/index.d.ts`, their maps, and focused module outputs exist.

- [ ] **Step 7: Commit**

```bash
git add src/schemas.ts src/verify-token.ts src/index.ts test/verify-token.test.ts test/public-types.test.ts
git commit -m "feat: compose email token verification"
```

## Task 8: Document the library and perform release-shape verification

**Files:**
- Create: `README.md`
- Modify: `package.json`
- Test: all `test/*.test.ts`

**Interfaces:**
- Consumes: the final public API from Task 7.
- Produces: documented installation and usage, package-ready ESM/declaration output, and verified quality evidence.

- [ ] **Step 1: Write README examples against the real public API**

Document:

1. The experimental protocol status and exactly what is verified.
2. Installation with `npm install email-verification`.
3. A high-level `verifyEmailToken()` example that handles both Result branches.
4. Required arguments and the 300/60-second defaults.
5. The five stages and their trust order, emphasizing that `cnf.jwk` is trusted only after EVT verification.
6. Stable error `stage`, `code`, `message`, and optional `cause` handling.
7. Injecting `fetch`, `resolveTxt`, and `now`.
8. A memoized wrapper example showing that caching is supplied externally in this release and warning that cache lifetimes must respect DNS TTL and HTTP cache semantics.
9. Application responsibilities: cryptographic nonce generation, session binding, one-time nonce consumption, fallback email verification, and not treating EVP as deliverability proof.
10. Individual stage examples without exposing internal helpers.

Use only `user@example.com`, `accounts.example.com`, and `https://rp.example.com` in examples.

- [ ] **Step 2: Add a packed-artifact smoke test**

Run:

```bash
npm pack --dry-run
```

Expected: output includes `dist`, `README.md`, `LICENSE`, and package metadata; it excludes `src`, `test`, `.test-dist`, design documents, and local environment files.

Inspect direct production dependencies:

```bash
npm pkg get dependencies
```

Expected: exactly `@sd-jwt/core`, `jose`, and `zod`.

- [ ] **Step 3: Run complete verification from a clean generated-output state**

Run:

```bash
npm run clean:test
npm run check
```

Expected: formatting check, strict type checking, ESLint, declaration build, and all Node tests pass with no warnings or skipped tests.

Run:

```bash
git status --short
```

Expected: only the intentional README/package changes remain before the final commit; generated output is ignored.

- [ ] **Step 4: Commit**

```bash
git add README.md package.json package-lock.json
git commit -m "docs: document email token verification"
```

- [ ] **Step 5: Final verification evidence**

Run: `npm run check && npm pack --dry-run && git status --short`

Expected: every quality gate passes, the tarball shape is correct, and the worktree is clean.

Record the final test count, commands, and commit hashes in the handoff. Do not publish, tag, push, or create a release without separate explicit authorization.
