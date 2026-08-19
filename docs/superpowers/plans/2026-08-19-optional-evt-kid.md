# Optional EVT `kid` Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Accept observed EVT tokens that omit `kid` while retaining exact key-ID matching when `kid` is present and keeping no-`kid` JWKS selection safely bounded.

**Architecture:** Make `kid` optional only in the EVT header schema, then centralize the compatibility behavior in the existing issuer-key matching predicate. The parser and all later stages continue to carry the protected header parsed from the exact compact token; issuer verification either filters by the supplied `kid` or, when absent, considers at most ten algorithm-compatible public keys.

**Tech Stack:** TypeScript 6, Zod 4, JOSE 6, `@sd-jwt/core`, Node.js test runner, typescript-eslint, Prettier.

## Global Constraints

- Keep the package ESM-only and continue emitting TypeScript declarations.
- Keep exactly three direct runtime dependencies: `zod`, `@sd-jwt/core`, and `jose`.
- Every public boundary remains Zod-parsed and every public function returns `Result` rather than throwing.
- Preserve strict exact-key matching whenever an EVT supplies `kid`.
- Without `kid`, consider only algorithm/key-type/curve/use/key-operations-compatible JWKs and reject more than ten candidates before accepting a signature.
- Keep the compatibility workaround isolated so returning to strict draft behavior requires changing the header schema and key-matcher parameter, not the pipeline or public API.

---

### Task 1: Support EVT headers with and without `kid`

**Files:**
- Modify: `test/helpers/token-fixture.ts`
- Modify: `test/parse-token.test.ts`
- Modify: `test/verify-issuer-signature.test.ts`
- Modify: `test/verify-token.test.ts`
- Modify: `src/schemas.ts`
- Modify: `src/verify-issuer-signature.ts`
- Modify: `README.md`

**Interfaces:**
- Consumes: `createTokenFixture(options)`, `EvtHeaderSchema`, `verifyIssuerSignature(input)`, and `verifyEmailToken(input)`.
- Produces: `EvtHeader` with `kid?: string`; fixture option `includeEvtKid?: boolean`; issuer-key matching with `keyId: string | undefined`.

- [ ] **Step 1: Extend the test fixture without changing its default**

Add the option:

```ts
export interface TokenFixtureOptions {
  // existing options remain unchanged
  includeEvtKid?: boolean;
}
```

Build the default protected header conditionally while leaving current tests on the strict path:

```ts
const defaultEvtHeader: CompactJWSHeaderParameters = {
  alg: "EdDSA",
  ...(options.includeEvtKid === false ? {} : { kid: "issuer-key" }),
  typ: "evt+jwt",
};
```

The issuer public JWK continues to contain `kid: "issuer-key"`; a no-`kid` EVT must be able to select a JWK that does have a key ID.

- [ ] **Step 2: Write parser regressions first**

Replace the existing “rejects a missing EVT kid” malformed-table case with a success test using a correctly signed token:

```ts
void it("parses an EVT without kid", async () => {
  const fixture = await createTokenFixture({ includeEvtKid: false });

  const result = await parseToken(fixture.token);

  assert.equal(result.ok, true);
  assert.equal(result.value.evt.header.kid, undefined);
});
```

Keep separate malformed cases for `kid: ""` and `kid: 123`:

```ts
{
  name: "rejects an empty EVT kid",
  token: async () =>
    mutateEvtJson(await tokenFixture(), "header", (header) => {
      header["kid"] = "";
    }),
},
{
  name: "rejects a non-string EVT kid",
  token: async () =>
    mutateEvtJson(await tokenFixture(), "header", (header) => {
      header["kid"] = 123;
    }),
},
```

The existing malformed-case loop must continue to assert `parse` / `TOKEN_MALFORMED` for both.

- [ ] **Step 3: Write issuer-selection regressions first**

Use a correctly signed no-`kid` fixture:

```ts
const { fixture, token } = await createDnsVerifiedFixture({
  includeEvtKid: false,
});
```

Add focused tests proving:

- one compatible JWK verifies even when that JWK has a `kid`;
- several compatible wrong keys followed by the valid key are tried successfully;
- eleven compatible keys return `JWKS_INVALID` before verification;
- different JWK `kid` values do not affect candidate matching when the EVT has no `kid`;
- incompatible RSA keys do not consume the EdDSA candidate limit;
- an EVT that does contain `kid` still rejects a differently identified otherwise-compatible JWK with `EVT_SIGNATURE_INVALID`.

Use real `generateKeyPair("Ed25519", { extractable: true })`, `exportJWK()`, and `PublicJwkSchema.parse()` as the existing bounded-key tests do; do not mock JOSE verification.

- [ ] **Step 4: Write end-to-end regressions first**

Extend the direct/selectively-disclosed matrix with `includeEvtKid`:

```ts
for (const discloseEmail of [false, true]) {
  for (const includeEvtKid of [true, false]) {
    const fixture = await createTokenFixture({
      discloseEmail,
      includeEvtKid,
    });
    const { input, dnsCalls, fetchCalls } = validInput(fixture);
    const parsed = await parseToken(fixture.token);
    assert.equal(parsed.ok, true);

    const result = await verifyEmailToken(input);

    assert.equal(result.ok, true);
    assert.deepEqual(result.value, {
      email: "user@example.com",
      issuer: "accounts.example.com",
      audience: "https://rp.example.com",
      issuedAt: {
        evt: fixture.evtIssuedAt,
        keyBinding: fixture.kbIssuedAt,
      },
      claims: parsed.value.evt.claims,
    });
    assert.deepEqual(dnsCalls, ["_email-verification.example.com"]);
    assert.deepEqual(fetchCalls, [metadataUrl, jwksUrl]);
  }
}
```

- [ ] **Step 5: Run the focused tests and verify RED**

Run:

```bash
npm run test:compile && node --test --test-name-pattern='kid|key id|end to end' .test-dist/test/*.test.js
```

Expected: the new signed no-`kid` parser and end-to-end cases fail with `TOKEN_MALFORMED`; issuer-stage no-`kid` cases cannot reach successful signature verification. Existing `kid` cases remain green.

- [ ] **Step 6: Make `kid` optional at the Zod boundary**

Change only the EVT header schema:

```ts
export const EvtHeaderSchema = z.looseObject({
  alg: nonempty.refine((value) => value !== "none"),
  kid: nonempty.optional(),
  typ: z.literal("evt+jwt"),
});
```

Do not loosen `alg`, `typ`, JWK structure, or any KB-JWT header requirement.

- [ ] **Step 7: Implement bounded no-`kid` key matching**

Change the private signatures to accept the inferred optional value:

```ts
async function verifyEvtSignature(
  compactEvt: string,
  algorithm: string,
  keyId: string | undefined,
  jwks: JsonWebKeySet,
): Promise<Result<true>>;

function matchesEvtHeader(
  jwk: PublicJwk,
  algorithm: string,
  keyId: string | undefined,
): boolean {
  return (
    isAlgorithmCompatibleJwk(jwk, algorithm) &&
    (keyId === undefined || jwk.kid === keyId) &&
    (jwk.alg === undefined || jwk.alg === algorithm) &&
    (jwk.use === undefined || jwk.use === "sig") &&
    (jwk.key_ops === undefined || jwk.key_ops.includes("verify"))
  );
}
```

Do not change the existing count-before-import, import-all-before-verify, ten-candidate maximum, or error classifications.

- [ ] **Step 8: Run focused GREEN and all static gates**

Run:

```bash
npm run test:compile && node --test --test-name-pattern='kid|key id|end to end' .test-dist/test/*.test.js
npm run typecheck
npm run lint
npm run format:check
```

Expected: all focused tests and static gates pass with no warnings.

- [ ] **Step 9: Document the compatibility behavior**

Add a short README note near token verification/trust order:

```md
Draft-01 requires an EVT `kid`, but some origin-trial tokens omit it. For
interoperability this release accepts both forms. When `kid` is present it must
match exactly; when absent, verification considers at most ten otherwise
compatible issuer keys.
```

Do not describe missing `kid` as standards-compliant; label it as temporary interoperability behavior.

- [ ] **Step 10: Run full verification and package checks**

Run:

```bash
npm run clean:test
npm run check
npm pack --dry-run --json --cache /private/tmp/email-verification-npm-cache
npm pkg get dependencies
git diff --check
git status --short
```

Expected: formatting, strict typecheck, lint, declarations, and all Node tests pass; the tarball contains only the documented package files; dependencies remain exactly `@sd-jwt/core`, `jose`, and `zod`; only intentional source/test/README/plan changes are present before commit.

- [ ] **Step 11: Commit the implementation**

```bash
git add README.md src/schemas.ts src/verify-issuer-signature.ts test/helpers/token-fixture.ts test/parse-token.test.ts test/verify-issuer-signature.test.ts test/verify-token.test.ts
git commit -m "fix: support EVT tokens without kid"
```

- [ ] **Step 12: Request an independent review**

Ask the reviewer to verify both modes, the ten-key cap, strict filtering when `kid` exists, real signature coverage, generated declarations, README wording, and the absence of unrelated public API changes. Apply actionable findings TDD-first, then rerun the full verification commands.
