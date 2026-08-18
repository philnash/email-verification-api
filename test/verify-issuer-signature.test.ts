import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { generateKeyPair, exportJWK } from "jose";
import { parseToken } from "../src/parse-token.js";
import type { Result, VerificationErrorCode } from "../src/result.js";
import type { DnsVerifiedToken, PublicJwk } from "../src/schemas.js";
import { PublicJwkSchema } from "../src/schemas.js";
import { validateExpectedValues } from "../src/validate-expected-values.js";
import { verifyDnsDelegation } from "../src/verify-dns-delegation.js";
import { verifyIssuerSignature } from "../src/verify-issuer-signature.js";
import { createFetchFixture } from "./helpers/network-fixture.js";
import {
  createTokenFixture,
  type TokenFixtureOptions,
} from "./helpers/token-fixture.js";

const nowEpochSeconds = 1_800_000_000;
const metadataUrl =
  "https://accounts.example.com/.well-known/email-verification";
const jwksUrl = "https://keys.accounts.example.com/email-verification/jwks";

function metadata(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    issuance_endpoint: "https://accounts.example.com/email-verification/issue",
    jwks_uri: jwksUrl,
    signing_alg_values_supported: ["EdDSA"],
    ...overrides,
  };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function responseWithUrl(value: unknown, url: string): Response {
  const response = jsonResponse(value);
  Object.defineProperty(response, "url", { value: url });
  return response;
}

async function createDnsVerifiedFixture(options: TokenFixtureOptions = {}) {
  const fixture = await createTokenFixture(options);
  const token = await createDnsVerifiedToken(fixture.token, {
    email: fixture.email,
    nonce: fixture.nonce,
    audience: fixture.audience,
  });
  return { fixture, token };
}

async function createDnsVerifiedToken(
  compactToken: string,
  expected: { email: string; nonce: string; audience: string },
): Promise<DnsVerifiedToken> {
  const parsed = await parseToken(compactToken);
  assert.equal(parsed.ok, true);
  const validated = validateExpectedValues({
    ...expected,
    token: parsed.value,
    now: () => nowEpochSeconds * 1_000,
  });
  assert.equal(validated.ok, true);
  const delegated = await verifyDnsDelegation({
    token: validated.value,
    resolveTxt: () => Promise.resolve([["iss=accounts.example.com"]]),
  });
  assert.equal(delegated.ok, true);
  return delegated.value;
}

function validRoutes(issuerPublicJwk: PublicJwk) {
  return {
    [metadataUrl]: () => jsonResponse(metadata()),
    [jwksUrl]: () => jsonResponse({ keys: [issuerPublicJwk] }),
  };
}

function assertIssuerError(
  result: Result<unknown>,
  code: VerificationErrorCode,
): void {
  assert.equal(result.ok, false);
  assert.equal(result.error.stage, "issuer");
  assert.equal(result.error.code, code);
}

function mutateCompactPart(
  compact: string,
  partIndex: number,
  mutate: (value: string) => string,
): string {
  const parts = compact.split(".");
  const part = parts[partIndex];
  if (part === undefined) assert.fail("Compact token part is missing.");
  parts[partIndex] = mutate(part);
  return parts.join(".");
}

function replaceEvt(token: string, oldEvt: string, newEvt: string): string {
  assert.equal(token.startsWith(oldEvt), true);
  return `${newEvt}${token.slice(oldEvt.length)}`;
}

function rejectWith(reason: unknown) {
  return {
    then(_resolve: unknown, reject: (rejection: unknown) => void) {
      reject(reason);
    },
  };
}

void describe("verifyIssuerSignature", () => {
  void it("fetches metadata then JWKS and verifies the EVT signature", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const network = createFetchFixture(validRoutes(fixture.issuerPublicJwk));

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assert.equal(result.ok, true);
    assert.deepEqual(network.calls, [metadataUrl, jwksUrl]);
    assert.deepEqual(result.value.token, token);
    assert.deepEqual(result.value.metadata, metadata());
  });

  void it("defaults an absent algorithm list to EdDSA", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const network = createFetchFixture({
      [metadataUrl]: () =>
        jsonResponse(metadata({ signing_alg_values_supported: undefined })),
      [jwksUrl]: () => jsonResponse({ keys: [fixture.issuerPublicJwk] }),
    });

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assert.equal(result.ok, true);
    assert.deepEqual(result.value.metadata.signing_alg_values_supported, [
      "EdDSA",
    ]);
  });

  void it("contains metadata fetch rejections and malformed responses", async () => {
    const { token } = await createDnsVerifiedFixture();
    const failures: unknown[] = [
      new Error("offline"),
      "network rejected",
      { code: "ECONNRESET" },
    ];

    for (const failure of failures) {
      const result = await verifyIssuerSignature({
        token,
        fetch: () => rejectWith(failure),
      });
      assertIssuerError(result, "METADATA_FETCH_FAILED");
    }

    for (const response of [undefined, null, "response", {}]) {
      const result = await verifyIssuerSignature({
        token,
        fetch: () => Promise.resolve(response),
      });
      assertIssuerError(result, "METADATA_FETCH_FAILED");
    }
  });

  void it("rejects a non-success metadata status without requesting JWKS", async () => {
    const { token } = await createDnsVerifiedFixture();
    const network = createFetchFixture({
      [metadataUrl]: () => new Response("DO_NOT_LEAK", { status: 503 }),
    });

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assertIssuerError(result, "METADATA_FETCH_FAILED");
    assert.deepEqual(network.calls, [metadataUrl]);
    if (!result.ok) {
      assert.equal(JSON.stringify(result.error).includes("DO_NOT_LEAK"), false);
    }
  });

  void it("turns metadata JSON failures into body-safe errors", async () => {
    const { token } = await createDnsVerifiedFixture();
    const body = "DO_NOT_LEAK_METADATA_BODY";

    for (const response of [
      new Response(body),
      {
        ok: true,
        status: 200,
        url: "",
        json: () => Promise.reject(new Error(body)),
      },
    ]) {
      const result = await verifyIssuerSignature({
        token,
        fetch: () => Promise.resolve(response),
      });
      assertIssuerError(result, "METADATA_INVALID");
      if (!result.ok) {
        assert.equal(JSON.stringify(result.error).includes(body), false);
      }
    }
  });

  void it("rejects malformed metadata", async () => {
    const { token } = await createDnsVerifiedFixture();
    const invalidMetadata: unknown[] = [
      null,
      [],
      "metadata",
      {},
      { issuance_endpoint: "https://accounts.example.com/issue" },
      { jwks_uri: jwksUrl },
      metadata({ issuance_endpoint: "not a URL" }),
      metadata({ jwks_uri: "not a URL" }),
      metadata({ signing_alg_values_supported: [] }),
      metadata({ signing_alg_values_supported: ["none"] }),
    ];

    for (const value of invalidMetadata) {
      const network = createFetchFixture({
        [metadataUrl]: () => jsonResponse(value),
      });
      const result = await verifyIssuerSignature({
        token,
        fetch: network.fetch,
      });
      assertIssuerError(result, "METADATA_INVALID");
      assert.deepEqual(network.calls, [metadataUrl]);
    }
  });

  void it("requires issuer-bound HTTPS metadata endpoints", async () => {
    const { token } = await createDnsVerifiedFixture();
    const invalidEndpoints = [
      "http://accounts.example.com/endpoint",
      "https://attacker.test/endpoint",
      "https://accounts.example.com.attacker.test/endpoint",
      "https://user@accounts.example.com/endpoint",
      "https://accounts.example.com:8443/endpoint",
    ];

    for (const endpoint of invalidEndpoints) {
      for (const property of ["issuance_endpoint", "jwks_uri"]) {
        const network = createFetchFixture({
          [metadataUrl]: () => jsonResponse(metadata({ [property]: endpoint })),
        });
        const result = await verifyIssuerSignature({
          token,
          fetch: network.fetch,
        });
        assertIssuerError(result, "METADATA_INVALID");
        assert.deepEqual(network.calls, [metadataUrl]);
      }
    }
  });

  void it("accepts issuer subdomain metadata endpoints", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const network = createFetchFixture(validRoutes(fixture.issuerPublicJwk));

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assert.equal(result.ok, true);
  });

  void it("rejects unsafe metadata redirect response URLs", async () => {
    const { token } = await createDnsVerifiedFixture();
    const unsafeUrls = [
      "http://accounts.example.com/.well-known/email-verification",
      "https://attacker.test/.well-known/email-verification",
      "https://accounts.example.com.attacker.test/.well-known/email-verification",
      "https://user@accounts.example.com/.well-known/email-verification",
      "https://accounts.example.com:8443/.well-known/email-verification",
    ];

    for (const url of unsafeUrls) {
      const result = await verifyIssuerSignature({
        token,
        fetch: () => Promise.resolve(responseWithUrl(metadata(), url)),
      });
      assertIssuerError(result, "METADATA_INVALID");
    }
  });

  void it("rejects an EVT algorithm not advertised by metadata", async () => {
    const { token } = await createDnsVerifiedFixture();
    const network = createFetchFixture({
      [metadataUrl]: () =>
        jsonResponse(metadata({ signing_alg_values_supported: ["ES256"] })),
    });

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assertIssuerError(result, "ALGORITHM_UNSUPPORTED");
    assert.deepEqual(network.calls, [metadataUrl]);
  });

  void it("contains JWKS fetch rejections and malformed responses", async () => {
    const { token } = await createDnsVerifiedFixture();

    for (const failure of [new Error("offline"), "rejected", { code: 1 }]) {
      const calls: string[] = [];
      const result = await verifyIssuerSignature({
        token,
        fetch: (input: unknown) => {
          if (typeof input !== "string") {
            assert.fail("Expected issuer verification to fetch string URLs.");
          }
          calls.push(input);
          return input === metadataUrl
            ? Promise.resolve(jsonResponse(metadata()))
            : rejectWith(failure);
        },
      });
      assertIssuerError(result, "JWKS_FETCH_FAILED");
      assert.deepEqual(calls, [metadataUrl, jwksUrl]);
    }

    const result = await verifyIssuerSignature({
      token,
      fetch: (input: unknown) => {
        if (input === metadataUrl)
          return Promise.resolve(jsonResponse(metadata()));
        return Promise.resolve({ unexpected: true });
      },
    });
    assertIssuerError(result, "JWKS_FETCH_FAILED");
  });

  void it("rejects a non-success JWKS status without parsing its body", async () => {
    const { token } = await createDnsVerifiedFixture();
    const network = createFetchFixture({
      [metadataUrl]: () => jsonResponse(metadata()),
      [jwksUrl]: () => new Response("DO_NOT_LEAK", { status: 404 }),
    });

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assertIssuerError(result, "JWKS_FETCH_FAILED");
    if (!result.ok) {
      assert.equal(JSON.stringify(result.error).includes("DO_NOT_LEAK"), false);
    }
  });

  void it("turns JWKS JSON failures into body-safe errors", async () => {
    const { token } = await createDnsVerifiedFixture();
    const body = "DO_NOT_LEAK_JWKS_BODY";
    const network = createFetchFixture({
      [metadataUrl]: () => jsonResponse(metadata()),
      [jwksUrl]: () => new Response(body),
    });

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assertIssuerError(result, "JWKS_INVALID");
    if (!result.ok) {
      assert.equal(JSON.stringify(result.error).includes(body), false);
    }
  });

  void it("rejects invalid and unbounded JWKS documents", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const privateKey = { ...fixture.issuerPublicJwk, d: "private" };
    const invalidJwks: unknown[] = [
      null,
      [],
      {},
      { keys: [] },
      { keys: Array.from({ length: 21 }, () => fixture.issuerPublicJwk) },
      { keys: [privateKey] },
    ];

    for (const jwks of invalidJwks) {
      const network = createFetchFixture({
        [metadataUrl]: () => jsonResponse(metadata()),
        [jwksUrl]: () => jsonResponse(jwks),
      });
      const result = await verifyIssuerSignature({
        token,
        fetch: network.fetch,
      });
      assertIssuerError(result, "JWKS_INVALID");
    }
  });

  void it("rejects unsafe JWKS redirect response URLs", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const response = responseWithUrl(
      { keys: [fixture.issuerPublicJwk] },
      "https://keys.accounts.example.com.attacker.test/jwks",
    );
    const network = createFetchFixture({
      [metadataUrl]: () => jsonResponse(metadata()),
      [jwksUrl]: response,
    });

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assertIssuerError(result, "JWKS_INVALID");
  });

  void it("rejects a missing key id and an incompatible key", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const incompatibleKeys: PublicJwk[] = [
      { ...fixture.issuerPublicJwk, kid: "another-key" },
      { ...fixture.issuerPublicJwk, alg: "ES256" },
    ];

    for (const key of incompatibleKeys) {
      const network = createFetchFixture({
        [metadataUrl]: () => jsonResponse(metadata()),
        [jwksUrl]: () => jsonResponse({ keys: [key] }),
      });
      const result = await verifyIssuerSignature({
        token,
        fetch: network.fetch,
      });
      assertIssuerError(result, "EVT_SIGNATURE_INVALID");
    }
  });

  void it("tries bounded matching keys until one verifies", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const wrongKeys: PublicJwk[] = [];
    for (let index = 0; index < 4; index += 1) {
      const pair = await generateKeyPair("Ed25519", { extractable: true });
      const jwk = await exportJWK(pair.publicKey);
      wrongKeys.push(
        PublicJwkSchema.parse({
          ...jwk,
          alg: "EdDSA",
          kid: "issuer-key",
        }),
      );
    }
    const network = createFetchFixture({
      [metadataUrl]: () => jsonResponse(metadata()),
      [jwksUrl]: () =>
        jsonResponse({ keys: [...wrongKeys, fixture.issuerPublicJwk] }),
    });

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assert.equal(result.ok, true);
  });

  void it("rejects ambiguous matching keys when none verifies", async () => {
    const { token } = await createDnsVerifiedFixture();
    const wrongKeys: PublicJwk[] = [];
    for (let index = 0; index < 2; index += 1) {
      const pair = await generateKeyPair("Ed25519", { extractable: true });
      const jwk = await exportJWK(pair.publicKey);
      wrongKeys.push(
        PublicJwkSchema.parse({
          ...jwk,
          alg: "EdDSA",
          kid: "issuer-key",
        }),
      );
    }
    const network = createFetchFixture({
      [metadataUrl]: () => jsonResponse(metadata()),
      [jwksUrl]: () => jsonResponse({ keys: wrongKeys }),
    });

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assertIssuerError(result, "EVT_SIGNATURE_INVALID");
  });

  void it("refuses to try more than ten matching keys", async () => {
    const { token } = await createDnsVerifiedFixture();
    const wrongKeys: PublicJwk[] = [];
    for (let index = 0; index < 11; index += 1) {
      const pair = await generateKeyPair("Ed25519", { extractable: true });
      const jwk = await exportJWK(pair.publicKey);
      wrongKeys.push(
        PublicJwkSchema.parse({
          ...jwk,
          alg: "EdDSA",
          kid: "issuer-key",
        }),
      );
    }
    const network = createFetchFixture({
      [metadataUrl]: () => jsonResponse(metadata()),
      [jwksUrl]: () => jsonResponse({ keys: wrongKeys }),
    });

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assertIssuerError(result, "JWKS_INVALID");
  });

  void it("rejects eleven duplicate matching keys before verification", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const network = createFetchFixture({
      [metadataUrl]: () => jsonResponse(metadata()),
      [jwksUrl]: () =>
        jsonResponse({
          keys: Array.from({ length: 11 }, () => fixture.issuerPublicJwk),
        }),
    });

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assertIssuerError(result, "JWKS_INVALID");
  });

  void it("counts malformed matching keys before JOSE can skip imports", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const malformedKey = { ...fixture.issuerPublicJwk, x: "AA" };
    const network = createFetchFixture({
      [metadataUrl]: () => jsonResponse(metadata()),
      [jwksUrl]: () =>
        jsonResponse({
          keys: [
            fixture.issuerPublicJwk,
            ...Array.from({ length: 10 }, () => malformedKey),
          ],
        }),
    });

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assertIssuerError(result, "JWKS_INVALID");
  });

  void it("does not count same-kid keys incompatible with the EVT algorithm", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const incompatibleKey = {
      kty: "RSA",
      kid: "issuer-key",
      e: "AQAB",
      n: "AQ",
    };
    const network = createFetchFixture({
      [metadataUrl]: () => jsonResponse(metadata()),
      [jwksUrl]: () =>
        jsonResponse({
          keys: [
            fixture.issuerPublicJwk,
            ...Array.from({ length: 10 }, () => incompatibleKey),
          ],
        }),
    });

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assert.equal(result.ok, true);
  });

  void it("classifies cryptographically invalid matching keys as invalid JWKS", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const malformedKey = { ...fixture.issuerPublicJwk, x: "AA" };
    const network = createFetchFixture({
      [metadataUrl]: () => jsonResponse(metadata()),
      [jwksUrl]: () => jsonResponse({ keys: [malformedKey] }),
    });

    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });

    assertIssuerError(result, "JWKS_INVALID");
  });

  void it("rejects tampered EVT payloads and signatures", async () => {
    const fixture = await createTokenFixture();
    const tamperedPayload = Buffer.from(
      JSON.stringify({
        iss: fixture.issuer,
        iat: fixture.evtIssuedAt,
        cnf: { jwk: fixture.holderPublicJwk },
        email: fixture.email,
        email_verified: true,
        tampered: true,
      }),
    ).toString("base64url");
    const tamperedEvts = [
      mutateCompactPart(fixture.evt, 1, () => tamperedPayload),
      mutateCompactPart(
        fixture.evt,
        2,
        (value) => `${value.startsWith("A") ? "B" : "A"}${value.slice(1)}`,
      ),
    ];

    for (const evt of tamperedEvts) {
      const compactToken = replaceEvt(fixture.token, fixture.evt, evt);
      const token = await createDnsVerifiedToken(compactToken, fixture);
      const network = createFetchFixture(validRoutes(fixture.issuerPublicJwk));
      const result = await verifyIssuerSignature({
        token,
        fetch: network.fetch,
      });
      assertIssuerError(result, "EVT_SIGNATURE_INVALID");
    }
  });

  void it("rejects tampered EVT kid and algorithm headers", async () => {
    const fixture = await createTokenFixture();
    const encodeHeader = (value: Record<string, unknown>) =>
      Buffer.from(JSON.stringify(value)).toString("base64url");
    const cases: {
      header: Record<string, unknown>;
      code: VerificationErrorCode;
    }[] = [
      {
        header: { alg: "EdDSA", kid: "unknown-key", typ: "evt+jwt" },
        code: "EVT_SIGNATURE_INVALID",
      },
      {
        header: { alg: "ES256", kid: "issuer-key", typ: "evt+jwt" },
        code: "ALGORITHM_UNSUPPORTED",
      },
    ];

    for (const testCase of cases) {
      const evt = mutateCompactPart(fixture.evt, 0, () =>
        encodeHeader(testCase.header),
      );
      const compactToken = replaceEvt(fixture.token, fixture.evt, evt);
      const token = await createDnsVerifiedToken(compactToken, fixture);
      const network = createFetchFixture(validRoutes(fixture.issuerPublicJwk));
      const result = await verifyIssuerSignature({
        token,
        fetch: network.fetch,
      });
      assertIssuerError(result, testCase.code);
    }
  });

  void it("accepts a freshly re-signed EVT and rebuilt key binding", async () => {
    const fixture = await createTokenFixture();
    const rebuilt = await fixture.rebuildToken({
      evtPayload: {
        iss: fixture.issuer,
        iat: fixture.evtIssuedAt,
        cnf: { jwk: fixture.holderPublicJwk },
        email: fixture.email,
        email_verified: true,
        example_claim: "preserved",
      },
    });
    const token = await createDnsVerifiedToken(rebuilt.token, fixture);
    const network = createFetchFixture(validRoutes(fixture.issuerPublicJwk));

    const result = await verifyIssuerSignature({ token, fetch: network.fetch });

    assert.equal(result.ok, true);
    assert.equal(
      result.value.token.token.token.evt.claims["example_claim"],
      "preserved",
    );
  });

  void it("never throws for hostile public input and dependency values", async () => {
    const { token } = await createDnsVerifiedFixture();
    const hostileInput = new Proxy(
      {},
      {
        get() {
          throw new Error("input unavailable");
        },
      },
    );
    const hostileResponse = new Proxy(
      {},
      {
        get() {
          throw new Error("response unavailable");
        },
      },
    );
    const hostileMetadata = new Proxy(
      {},
      {
        get() {
          throw new Error("metadata unavailable");
        },
      },
    );

    const results = [
      await verifyIssuerSignature(hostileInput),
      await verifyIssuerSignature({ token, fetch: () => hostileResponse }),
      await verifyIssuerSignature({
        token,
        fetch: () =>
          Promise.resolve({
            ok: true,
            status: 200,
            url: "",
            json: () => Promise.resolve(hostileMetadata),
          }),
      }),
    ];

    for (const result of results) assert.equal(result.ok, false);
  });

  void it("rejects caller-supplied parsed claims that differ from the compact EVT", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const network = createFetchFixture(validRoutes(fixture.issuerPublicJwk));
    const fabricatedToken = {
      ...token,
      token: {
        ...token.token,
        token: {
          ...token.token.token,
          evt: {
            ...token.token.token.evt,
            claims: {
              ...token.token.token.evt.claims,
              email: "attacker@example.com",
            },
          },
        },
      },
    };

    const result = await verifyIssuerSignature({
      token: fabricatedToken,
      fetch: network.fetch,
    });

    assertIssuerError(result, "INVALID_INPUT");
    assert.deepEqual(network.calls, []);
  });

  void it("rejects a caller-supplied holder key that differs from the compact EVT", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const unrelatedFixture = await createTokenFixture();
    const network = createFetchFixture(validRoutes(fixture.issuerPublicJwk));
    const fabricatedClaims = {
      ...token.token.token.evt.claims,
      cnf: { jwk: unrelatedFixture.holderPublicJwk },
    };
    const fabricatedToken = {
      ...token,
      token: {
        ...token.token,
        token: {
          ...token.token.token,
          evt: {
            ...token.token.token.evt,
            rawClaims: fabricatedClaims,
            claims: fabricatedClaims,
          },
        },
      },
    };

    const result = await verifyIssuerSignature({
      token: fabricatedToken,
      fetch: network.fetch,
    });

    assertIssuerError(result, "INVALID_INPUT");
    assert.deepEqual(network.calls, []);
  });

  void it("preserves expected-value and DNS invariants after reparsing", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const fabricatedTokens = [
      {
        ...token,
        token: { ...token.token, email: "attacker@example.com" },
      },
      { ...token, issuer: "attacker.example.com" },
    ];

    for (const fabricatedToken of fabricatedTokens) {
      const network = createFetchFixture(validRoutes(fixture.issuerPublicJwk));
      const result = await verifyIssuerSignature({
        token: fabricatedToken,
        fetch: network.fetch,
      });
      assertIssuerError(result, "INVALID_INPUT");
      assert.deepEqual(network.calls, []);
    }
  });

  void it("rejects raw ASCII whitespace and controls in metadata URLs", async () => {
    const { token } = await createDnsVerifiedFixture();
    const unsafeUrls = [
      "https://accounts.exam\tple.com/endpoint",
      "https://accounts.exam\nple.com/endpoint",
      "https://accounts.exam\rple.com/endpoint",
    ];

    for (const url of unsafeUrls) {
      for (const property of ["issuance_endpoint", "jwks_uri"]) {
        const network = createFetchFixture({
          [metadataUrl]: () => jsonResponse(metadata({ [property]: url })),
        });
        const result = await verifyIssuerSignature({
          token,
          fetch: network.fetch,
        });
        assertIssuerError(result, "METADATA_INVALID");
        assert.deepEqual(network.calls, [metadataUrl]);
      }
    }
  });

  void it("rejects raw ASCII whitespace and controls in response URLs", async () => {
    const { fixture, token } = await createDnsVerifiedFixture();
    const unsafeMetadataResponseUrls = [
      "https://accounts.exam\tple.com/.well-known/email-verification",
      "https://accounts.exam\nple.com/.well-known/email-verification",
      "https://accounts.exam\rple.com/.well-known/email-verification",
    ];

    for (const responseUrl of unsafeMetadataResponseUrls) {
      const result = await verifyIssuerSignature({
        token,
        fetch: (input: unknown) =>
          Promise.resolve(
            input === metadataUrl
              ? responseWithUrl(metadata(), responseUrl)
              : jsonResponse({ keys: [fixture.issuerPublicJwk] }),
          ),
      });
      assertIssuerError(result, "METADATA_INVALID");
    }

    const unsafeJwksResponseUrl =
      "https://keys.accounts.exam\tple.com/email-verification/jwks";
    const network = createFetchFixture({
      [metadataUrl]: () => jsonResponse(metadata()),
      [jwksUrl]: () =>
        responseWithUrl(
          { keys: [fixture.issuerPublicJwk] },
          unsafeJwksResponseUrl,
        ),
    });
    const result = await verifyIssuerSignature({
      token,
      fetch: network.fetch,
    });
    assertIssuerError(result, "JWKS_INVALID");
  });

  void it("rejects a fabricated non-canonical issuer before Fetch", async () => {
    const { token } = await createDnsVerifiedFixture();
    const calls: string[] = [];

    const result = await verifyIssuerSignature({
      token: { ...token, issuer: "accounts.example.com@attacker.test" },
      fetch: (input: unknown) => {
        calls.push(String(input));
        return Promise.resolve(jsonResponse(metadata()));
      },
    });

    assertIssuerError(result, "INVALID_INPUT");
    assert.deepEqual(calls, []);
  });
});
