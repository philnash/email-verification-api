import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseToken } from "../src/parse-token.js";
import type { Result, VerificationErrorCode } from "../src/result.js";
import type { ParsedToken } from "../src/schemas.js";
import { validateExpectedValues } from "../src/validate-expected-values.js";
import {
  createTokenFixture,
  type TokenFixtureOptions,
} from "./helpers/token-fixture.js";

const nowEpochSeconds = 1_800_000_000;
const now = () => nowEpochSeconds * 1_000;
const normalizationAcceptedAsciiControls = ["\t", "\r", "\n"];

async function createParsedToken(options: TokenFixtureOptions = {}): Promise<{
  parsed: ParsedToken;
  email: string;
  nonce: string;
  audience: string;
}> {
  const fixture = await createTokenFixture(options);
  const result = await parseToken(fixture.token);
  assert.equal(result.ok, true);
  return { parsed: result.value, ...fixture };
}

function expectedInput(fixture: Awaited<ReturnType<typeof createParsedToken>>) {
  return {
    token: fixture.parsed,
    email: fixture.email,
    nonce: fixture.nonce,
    audience: fixture.audience,
    now,
  };
}

function assertErrorCode(result: Result<unknown>, code: VerificationErrorCode) {
  assert.equal(result.ok, false);
  assert.equal(result.error.code, code);
  assert.equal(result.error.stage, "expected-values");
}

function withIssuedAt(
  token: ParsedToken,
  target: "evt" | "kb",
  issuedAt: number,
): ParsedToken {
  if (target === "evt") {
    return {
      ...token,
      evt: {
        ...token.evt,
        rawClaims: { ...token.evt.rawClaims, iat: issuedAt },
        claims: { ...token.evt.claims, iat: issuedAt },
      },
    };
  }

  return {
    ...token,
    kb: {
      ...token.kb,
      claims: { ...token.kb.claims, iat: issuedAt },
    },
  };
}

void describe("validateExpectedValues", () => {
  void it("accepts valid values using the default timing configuration", async () => {
    const fixture = await createParsedToken();
    const result = validateExpectedValues({
      ...expectedInput(fixture),
      email: "USER@example.com",
    });

    assert.equal(result.ok, true);
    assert.equal(result.value.email, "user@example.com");
    assert.equal(result.value.audience, "https://rp.example.com");
    assert.equal(result.value.maxTokenAgeSeconds, 300);
    assert.equal(result.value.clockToleranceSeconds, 60);
    assert.equal(result.value.nowEpochSeconds, nowEpochSeconds);
    assert.deepEqual(result.value.token, fixture.parsed);
  });

  void it("rejects invalid public input without throwing", async () => {
    const fixture = await createParsedToken();
    const invalidInputs: unknown[] = [
      undefined,
      null,
      {},
      { ...expectedInput(fixture), token: null },
      { ...expectedInput(fixture), nonce: "" },
      { ...expectedInput(fixture), email: "not-an-email" },
      { ...expectedInput(fixture), audience: "not-a-url" },
      { ...expectedInput(fixture), maxTokenAgeSeconds: -1 },
      { ...expectedInput(fixture), maxTokenAgeSeconds: Number.NaN },
      {
        ...expectedInput(fixture),
        maxTokenAgeSeconds: Number.POSITIVE_INFINITY,
      },
      { ...expectedInput(fixture), clockToleranceSeconds: -1 },
      { ...expectedInput(fixture), clockToleranceSeconds: Number.NaN },
      {
        ...expectedInput(fixture),
        clockToleranceSeconds: Number.POSITIVE_INFINITY,
      },
      { ...expectedInput(fixture), now: "not-a-function" },
    ];

    for (const input of invalidInputs) {
      assert.doesNotThrow(() => {
        assertErrorCode(validateExpectedValues(input), "INVALID_INPUT");
      });
    }
  });

  void it("returns invalid input when reading an input property throws", async () => {
    const fixture = await createParsedToken();
    const input = Object.defineProperty(expectedInput(fixture), "now", {
      enumerable: true,
      get() {
        throw new Error("input unavailable");
      },
    });

    assert.doesNotThrow(() => {
      assertErrorCode(validateExpectedValues(input), "INVALID_INPUT");
    });
  });

  void it("rejects invalid clock results and clock failures without throwing", async () => {
    const fixture = await createParsedToken();
    const invalidClocks: (() => unknown)[] = [
      () => "not-a-number",
      () => Number.NaN,
      () => Number.POSITIVE_INFINITY,
      () => -1,
      () => {
        throw new Error("clock unavailable");
      },
    ];

    for (const invalidNow of invalidClocks) {
      assert.doesNotThrow(() => {
        const result = validateExpectedValues({
          ...expectedInput(fixture),
          now: invalidNow,
        });
        assertErrorCode(result, "INVALID_INPUT");
      });
    }
  });

  void it("rejects an email mismatch", async () => {
    const fixture = await createParsedToken();
    const result = validateExpectedValues({
      ...expectedInput(fixture),
      email: "other@example.com",
    });

    assertErrorCode(result, "EMAIL_MISMATCH");
  });

  void it("rejects a schema-valid unverified email claim", async () => {
    const fixture = await createParsedToken({ emailVerified: false });
    const result = validateExpectedValues(expectedInput(fixture));

    assertErrorCode(result, "EMAIL_NOT_VERIFIED");
  });

  void it("compares the nonce exactly", async () => {
    const fixture = await createParsedToken();
    const result = validateExpectedValues({
      ...expectedInput(fixture),
      nonce: "EXAMPLE-NONCE",
    });

    assertErrorCode(result, "NONCE_MISMATCH");
  });

  void it("canonicalizes audience host casing and default ports", async () => {
    const fixture = await createParsedToken({
      audience: "https://RP.Example.com:443",
    });
    const result = validateExpectedValues({
      ...expectedInput(fixture),
      audience: "https://rp.example.com",
    });

    assert.equal(result.ok, true);
    assert.equal(result.value.audience, "https://rp.example.com");
  });

  void it("rejects audience origin mismatches", async () => {
    const fixture = await createParsedToken();
    const mismatches = [
      "http://rp.example.com",
      "https://other.example.com",
      "https://rp.example.com:8443",
      "https://subdomain.rp.example.com",
    ];

    for (const audience of mismatches) {
      assertErrorCode(
        validateExpectedValues({ ...expectedInput(fixture), audience }),
        "AUDIENCE_MISMATCH",
      );
    }
  });

  void it("rejects invalid expected audience forms", async () => {
    const fixture = await createParsedToken();
    const invalidAudiences = [
      "https://rp.example.com/path",
      "https://rp.example.com?query=value",
      "https://rp.example.com#fragment",
      "https://user:password@rp.example.com",
      "ftp://rp.example.com",
    ];

    for (const audience of invalidAudiences) {
      assertErrorCode(
        validateExpectedValues({ ...expectedInput(fixture), audience }),
        "AUDIENCE_MISMATCH",
      );
    }
  });

  void it("rejects invalid token audience forms", async () => {
    const invalidAudiences = [
      "https://rp.example.com/path",
      "https://rp.example.com?query=value",
      "https://rp.example.com#fragment",
      "https://user:password@rp.example.com",
      "ftp://rp.example.com",
    ];

    for (const audience of invalidAudiences) {
      const fixture = await createParsedToken({ audience });
      assertErrorCode(
        validateExpectedValues({
          ...expectedInput(fixture),
          audience: "https://rp.example.com",
        }),
        "AUDIENCE_MISMATCH",
      );
    }
  });

  void it("rejects raw ASCII whitespace and controls in the expected audience", async () => {
    const fixture = await createParsedToken();

    for (const character of normalizationAcceptedAsciiControls) {
      const result = validateExpectedValues({
        ...expectedInput(fixture),
        audience: `https://rp.example${character}.com`,
      });

      assertErrorCode(result, "AUDIENCE_MISMATCH");
    }
  });

  void it("rejects raw ASCII whitespace and controls in the KB audience", async () => {
    for (const character of normalizationAcceptedAsciiControls) {
      const fixture = await createParsedToken({
        audience: `https://rp.example${character}.com`,
      });
      const result = validateExpectedValues({
        ...expectedInput(fixture),
        audience: "https://rp.example.com",
      });

      assertErrorCode(result, "AUDIENCE_MISMATCH");
    }
  });

  const timestampTargets: readonly ("evt" | "kb")[] = ["evt", "kb"];
  for (const target of timestampTargets) {
    void it(`accepts ${target.toUpperCase()} timestamps at and inside the old boundary`, async () => {
      const fixture = await createParsedToken();

      for (const issuedAt of [nowEpochSeconds - 360, nowEpochSeconds - 359]) {
        const token = withIssuedAt(fixture.parsed, target, issuedAt);
        const result = validateExpectedValues({
          ...expectedInput(fixture),
          token,
        });
        assert.equal(result.ok, true);
      }
    });

    void it(`rejects ${target.toUpperCase()} timestamps one second outside the old boundary`, async () => {
      const fixture = await createParsedToken();
      const token = withIssuedAt(fixture.parsed, target, nowEpochSeconds - 361);
      const result = validateExpectedValues({
        ...expectedInput(fixture),
        token,
      });

      assertErrorCode(result, "TOKEN_EXPIRED");
    });

    void it(`accepts ${target.toUpperCase()} timestamps at and inside the future boundary`, async () => {
      const fixture = await createParsedToken();

      for (const issuedAt of [nowEpochSeconds + 60, nowEpochSeconds + 59]) {
        const token = withIssuedAt(fixture.parsed, target, issuedAt);
        const result = validateExpectedValues({
          ...expectedInput(fixture),
          token,
        });
        assert.equal(result.ok, true);
      }
    });

    void it(`rejects ${target.toUpperCase()} timestamps one second outside the future boundary`, async () => {
      const fixture = await createParsedToken();
      const token = withIssuedAt(fixture.parsed, target, nowEpochSeconds + 61);
      const result = validateExpectedValues({
        ...expectedInput(fixture),
        token,
      });

      assertErrorCode(result, "TOKEN_NOT_YET_VALID");
    });
  }

  void it("uses custom maximum age and clock tolerance values", async () => {
    const fixture = await createParsedToken();
    const evtAtCustomOldBoundary = withIssuedAt(
      fixture.parsed,
      "evt",
      nowEpochSeconds - 25,
    );
    const token = withIssuedAt(
      evtAtCustomOldBoundary,
      "kb",
      nowEpochSeconds + 5,
    );
    const result = validateExpectedValues({
      ...expectedInput(fixture),
      token,
      maxTokenAgeSeconds: 20,
      clockToleranceSeconds: 5,
    });

    assert.equal(result.ok, true);
    assert.equal(result.value.maxTokenAgeSeconds, 20);
    assert.equal(result.value.clockToleranceSeconds, 5);
  });

  void it("applies custom boundaries instead of the defaults", async () => {
    const fixture = await createParsedToken();
    const token = withIssuedAt(fixture.parsed, "evt", nowEpochSeconds - 26);
    const result = validateExpectedValues({
      ...expectedInput(fixture),
      token,
      maxTokenAgeSeconds: 20,
      clockToleranceSeconds: 5,
    });

    assertErrorCode(result, "TOKEN_EXPIRED");
  });

  for (const target of timestampTargets) {
    void it(`applies the custom future boundary to the ${target.toUpperCase()} timestamp`, async () => {
      const fixture = await createParsedToken();
      const token = withIssuedAt(fixture.parsed, target, nowEpochSeconds + 6);
      const result = validateExpectedValues({
        ...expectedInput(fixture),
        token,
        maxTokenAgeSeconds: 20,
        clockToleranceSeconds: 5,
      });

      assertErrorCode(result, "TOKEN_NOT_YET_VALID");
    });
  }
});
