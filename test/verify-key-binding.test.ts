import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { generateKeyPair } from "jose";
import { parseToken } from "../src/parse-token.js";
import type { Result, VerificationErrorCode } from "../src/result.js";
import type { IssuerVerifiedToken, PublicJwk } from "../src/schemas.js";
import { validateExpectedValues } from "../src/validate-expected-values.js";
import { verifyDnsDelegation } from "../src/verify-dns-delegation.js";
import { verifyIssuerSignature } from "../src/verify-issuer-signature.js";
import { verifyKeyBinding } from "../src/verify-key-binding.js";
import { createFetchFixture } from "./helpers/network-fixture.js";
import { createTokenFixture } from "./helpers/token-fixture.js";

const nowEpochSeconds = 1_800_000_000;
const metadataUrl =
  "https://accounts.example.com/.well-known/email-verification";
const jwksUrl = "https://keys.accounts.example.com/email-verification/jwks";

type TokenFixture = Awaited<ReturnType<typeof createTokenFixture>>;

function expectedKeyBindingValue(token: IssuerVerifiedToken) {
  const parsedToken = token.token.token.token;
  return {
    email: parsedToken.evt.claims.email,
    issuer: "accounts.example.com",
    audience: parsedToken.kb.claims.aud,
    issuedAt: {
      evt: parsedToken.evt.claims.iat,
      keyBinding: parsedToken.kb.claims.iat,
    },
    claims: parsedToken.evt.claims,
  };
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
  });
}

function metadata(): Record<string, unknown> {
  return {
    issuance_endpoint: "https://accounts.example.com/email-verification/issue",
    jwks_uri: jwksUrl,
    signing_alg_values_supported: ["EdDSA"],
  };
}

async function createIssuerVerifiedToken(
  compactToken: string,
  fixture: TokenFixture,
): Promise<IssuerVerifiedToken> {
  const parsed = await parseToken(compactToken);
  assert.equal(parsed.ok, true);

  const validated = validateExpectedValues({
    token: parsed.value,
    email: fixture.email,
    nonce: fixture.nonce,
    audience: fixture.audience,
    now: () => nowEpochSeconds * 1_000,
  });
  assert.equal(validated.ok, true);

  const delegated = await verifyDnsDelegation({
    token: validated.value,
    resolveTxt: () => Promise.resolve([["iss=accounts.example.com"]]),
  });
  assert.equal(delegated.ok, true);

  const network = createFetchFixture({
    [metadataUrl]: () => jsonResponse(metadata()),
    [jwksUrl]: () => jsonResponse({ keys: [fixture.issuerPublicJwk] }),
  });
  const issuerVerified = await verifyIssuerSignature({
    token: delegated.value,
    fetch: network.fetch,
  });
  assert.equal(issuerVerified.ok, true);
  return issuerVerified.value;
}

function assertKeyBindingError(
  result: Result<unknown>,
  code: VerificationErrorCode,
): void {
  assert.equal(result.ok, false);
  assert.equal(result.error.stage, "key-binding");
  assert.equal(result.error.code, code);
}

function replaceCompactPart(
  compact: string,
  partIndex: number,
  replacement: string,
): string {
  const parts = compact.split(".");
  assert.equal(parts.length, 3);
  parts[partIndex] = replacement;
  return parts.join(".");
}

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function withKb(fixture: TokenFixture, kb: string): string {
  return `${fixture.presentation}${kb}`;
}

function mutateSignature(signature: string): string {
  const first = signature[0];
  assert.notEqual(first, undefined);
  return `${first === "A" ? "B" : "A"}${signature.slice(1)}`;
}

void describe("verifyKeyBinding", () => {
  for (const discloseEmail of [false, true]) {
    void it(`verifies a ${discloseEmail ? "selectively disclosed" : "direct"} email token`, async () => {
      const fixture = await createTokenFixture({ discloseEmail });
      const issuerVerified = await createIssuerVerifiedToken(
        fixture.token,
        fixture,
      );

      const result = await verifyKeyBinding({ token: issuerVerified });

      assert.equal(result.ok, true);
      assert.deepEqual(result.value, expectedKeyBindingValue(issuerVerified));
      const holderJwk = result.value.claims.cnf.jwk;
      assert.equal("d" in holderJwk, false);
      assert.equal("k" in holderJwk, false);
    });
  }

  const predecessorMutations: readonly {
    name: string;
    mutate: (token: IssuerVerifiedToken) => void;
  }[] = [
    {
      name: "expected email",
      mutate: (token) => {
        token.token.token.email = "attacker@example.com";
      },
    },
    {
      name: "expected audience",
      mutate: (token) => {
        token.token.token.audience = "https://attacker.example.com";
      },
    },
    {
      name: "DNS issuer",
      mutate: (token) => {
        token.token.issuer = "attacker.example.com";
      },
    },
    {
      name: "maximum token age",
      mutate: (token) => {
        token.token.token.maxTokenAgeSeconds += 1;
      },
    },
    {
      name: "clock tolerance",
      mutate: (token) => {
        token.token.token.clockToleranceSeconds += 1;
      },
    },
    {
      name: "validation clock",
      mutate: (token) => {
        token.token.token.nowEpochSeconds += 1;
      },
    },
    {
      name: "metadata issuance endpoint",
      mutate: (token) => {
        token.metadata.issuance_endpoint = "https://attacker.example.com/issue";
      },
    },
    {
      name: "metadata JWKS endpoint",
      mutate: (token) => {
        token.metadata.jwks_uri = "https://attacker.example.com/jwks";
      },
    },
  ];

  for (const predecessorMutation of predecessorMutations) {
    void it(`does not propagate a mutated predecessor ${predecessorMutation.name}`, async () => {
      const fixture = await createTokenFixture();
      const issuerVerified = await createIssuerVerifiedToken(
        fixture.token,
        fixture,
      );
      const expected = expectedKeyBindingValue(issuerVerified);
      predecessorMutation.mutate(issuerVerified);

      const result = await verifyKeyBinding({ token: issuerVerified });

      assert.equal(result.ok, true);
      assert.deepEqual(result.value, expected);
    });
  }

  void it("rejects malformed and hostile public input without throwing", async () => {
    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error("hostile getter");
        },
      },
    );

    for (const input of [
      undefined,
      null,
      "token",
      {},
      { token: {} },
      hostile,
    ]) {
      const result = await verifyKeyBinding(input);
      assertKeyBindingError(result, "INVALID_INPUT");
    }
  });

  void it("rejects staged claims that do not match the exact compact token", async () => {
    const fixture = await createTokenFixture();
    const issuerVerified = await createIssuerVerifiedToken(
      fixture.token,
      fixture,
    );
    const altered = structuredClone(issuerVerified);
    altered.token.token.token.evt.claims.cnf.jwk.x = "AA";

    const result = await verifyKeyBinding({ token: altered });

    assertKeyBindingError(result, "INVALID_INPUT");
  });

  void it("rejects a private holder JWK at the public boundary", async () => {
    const fixture = await createTokenFixture();
    const issuerVerified = await createIssuerVerifiedToken(
      fixture.token,
      fixture,
    );
    const altered = structuredClone(issuerVerified);
    altered.token.token.token.evt.claims.cnf.jwk["d"] = "cHJpdmF0ZQ";

    const result = await verifyKeyBinding({ token: altered });

    assertKeyBindingError(result, "INVALID_INPUT");
  });

  void it("rejects a mutated KB payload with its original signature", async () => {
    const fixture = await createTokenFixture();
    const tamperedKb = replaceCompactPart(
      fixture.kb,
      1,
      encodeJson({
        aud: fixture.audience,
        nonce: fixture.nonce,
        iat: fixture.kbIssuedAt,
        sd_hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      }),
    );
    const compactToken = withKb(fixture, tamperedKb);
    const issuerVerified = await createIssuerVerifiedToken(
      compactToken,
      fixture,
    );

    const result = await verifyKeyBinding({ token: issuerVerified });

    assertKeyBindingError(result, "KB_SIGNATURE_INVALID");
  });

  void it("rejects a KB signed by an unrelated holder", async () => {
    const fixture = await createTokenFixture();
    const unrelatedHolder = await generateKeyPair("Ed25519");
    const rebuilt = await fixture.rebuildToken({
      kbSigningKey: unrelatedHolder.privateKey,
    });
    const issuerVerified = await createIssuerVerifiedToken(
      rebuilt.token,
      fixture,
    );

    const result = await verifyKeyBinding({ token: issuerVerified });

    assertKeyBindingError(result, "KB_SIGNATURE_INVALID");
  });

  void it("rejects malformed cryptographic holder key material", async () => {
    const fixture = await createTokenFixture();
    const malformedHolder: PublicJwk = {
      ...fixture.holderPublicJwk,
      x: "AA",
    };
    const rebuilt = await fixture.rebuildToken({
      evtPayload: {
        ...fixture.evtPayload,
        cnf: { jwk: malformedHolder },
      },
    });
    const issuerVerified = await createIssuerVerifiedToken(
      rebuilt.token,
      fixture,
    );

    const result = await verifyKeyBinding({ token: issuerVerified });

    assertKeyBindingError(result, "KB_SIGNATURE_INVALID");
  });

  void it("rejects an unsupported holder key type for the KB algorithm", async () => {
    const fixture = await createTokenFixture();
    const unsupportedHolder: PublicJwk = {
      ...fixture.holderPublicJwk,
      crv: "X25519",
    };
    const rebuilt = await fixture.rebuildToken({
      evtPayload: {
        ...fixture.evtPayload,
        cnf: { jwk: unsupportedHolder },
      },
    });
    const issuerVerified = await createIssuerVerifiedToken(
      rebuilt.token,
      fixture,
    );

    const result = await verifyKeyBinding({ token: issuerVerified });

    assertKeyBindingError(result, "KB_SIGNATURE_INVALID");
  });

  void it("rejects an unsecured KB algorithm at the public boundary", async () => {
    const fixture = await createTokenFixture();
    const issuerVerified = await createIssuerVerifiedToken(
      fixture.token,
      fixture,
    );
    const altered = structuredClone(issuerVerified);
    altered.token.token.token.kb.header.alg = "none";

    const result = await verifyKeyBinding({ token: altered });

    assertKeyBindingError(result, "INVALID_INPUT");
  });

  for (const algorithm of ["ES256", "ExampleUnsupported"] as const) {
    void it(`rejects the ${algorithm} KB algorithm with an Ed25519 holder key`, async () => {
      const fixture = await createTokenFixture();
      const incompatibleKb = replaceCompactPart(
        fixture.kb,
        0,
        encodeJson({ alg: algorithm, typ: "kb+jwt" }),
      );
      const compactToken = withKb(fixture, incompatibleKb);
      const issuerVerified = await createIssuerVerifiedToken(
        compactToken,
        fixture,
      );

      const result = await verifyKeyBinding({ token: issuerVerified });

      assertKeyBindingError(result, "KB_SIGNATURE_INVALID");
    });
  }

  void it("rejects an sd_hash for another EVT presentation", async () => {
    const fixture = await createTokenFixture();
    const other = await createTokenFixture();
    const rebuilt = await fixture.rebuildToken({
      sdHashPresentation: other.presentation,
    });
    const issuerVerified = await createIssuerVerifiedToken(
      rebuilt.token,
      fixture,
    );

    const result = await verifyKeyBinding({ token: issuerVerified });

    assertKeyBindingError(result, "SD_HASH_MISMATCH");
  });

  void it("includes the trailing tilde in the presentation hash", async () => {
    const fixture = await createTokenFixture();
    const rebuilt = await fixture.rebuildToken({
      sdHashPresentation: fixture.presentation.slice(0, -1),
    });
    const issuerVerified = await createIssuerVerifiedToken(
      rebuilt.token,
      fixture,
    );

    const result = await verifyKeyBinding({ token: issuerVerified });

    assertKeyBindingError(result, "SD_HASH_MISMATCH");
  });

  void it("includes every presented disclosure in the presentation hash", async () => {
    const fixture = await createTokenFixture({ discloseEmail: true });
    const rebuilt = await fixture.rebuildToken({
      sdHashPresentation: `${fixture.evt}~`,
    });
    const issuerVerified = await createIssuerVerifiedToken(
      rebuilt.token,
      fixture,
    );

    const result = await verifyKeyBinding({ token: issuerVerified });

    assertKeyBindingError(result, "SD_HASH_MISMATCH");
  });

  void it("rejects an invalid signature even when sd_hash is valid", async () => {
    const fixture = await createTokenFixture();
    const signature = fixture.kb.split(".")[2];
    if (signature === undefined) assert.fail("KB signature is missing.");
    const invalidKb = replaceCompactPart(
      fixture.kb,
      2,
      mutateSignature(signature),
    );
    const compactToken = withKb(fixture, invalidKb);
    const issuerVerified = await createIssuerVerifiedToken(
      compactToken,
      fixture,
    );

    const result = await verifyKeyBinding({ token: issuerVerified });

    assertKeyBindingError(result, "KB_SIGNATURE_INVALID");
  });
});
