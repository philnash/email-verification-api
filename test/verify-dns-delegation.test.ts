import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseToken } from "../src/parse-token.js";
import type { Result, VerificationErrorCode } from "../src/result.js";
import type { ExpectedValuesValidatedToken } from "../src/schemas.js";
import { validateExpectedValues } from "../src/validate-expected-values.js";
import {
  canonicalIssuer,
  verifyDnsDelegation,
} from "../src/verify-dns-delegation.js";
import { createResolveTxtFixture } from "./helpers/network-fixture.js";
import {
  createTokenFixture,
  type TokenFixtureOptions,
} from "./helpers/token-fixture.js";

const nowEpochSeconds = 1_800_000_000;

async function createValidatedToken(
  options: TokenFixtureOptions = {},
): Promise<ExpectedValuesValidatedToken> {
  const fixture = await createTokenFixture(options);
  const parsed = await parseToken(fixture.token);
  assert.equal(parsed.ok, true);

  const validated = validateExpectedValues({
    token: parsed.value,
    email: fixture.email,
    nonce: fixture.nonce,
    audience: fixture.audience,
    now: () => nowEpochSeconds * 1_000,
  });
  assert.equal(validated.ok, true);
  return validated.value;
}

function assertErrorCode(
  result: Result<unknown>,
  code: VerificationErrorCode,
): void {
  assert.equal(result.ok, false);
  assert.equal(result.error.code, code);
  assert.equal(result.error.stage, "dns");
}

void describe("verifyDnsDelegation", () => {
  void it("joins TXT chunks and verifies the sole issuer", async () => {
    const validated = await createValidatedToken();
    const resolver = createResolveTxtFixture([
      ["iss=accounts.", "example.com"],
    ]);

    const result = await verifyDnsDelegation({
      token: validated,
      resolveTxt: resolver.resolveTxt,
    });

    assert.equal(result.ok, true);
    assert.deepEqual(resolver.calls, ["_email-verification.example.com"]);
    assert.equal(result.value.issuer, "accounts.example.com");
    assert.deepEqual(result.value.token, validated);
  });

  void it("accepts hostname and strict HTTPS issuer forms", async () => {
    const cases = [
      {
        claimedIssuer: "accounts.example.com",
        delegatedIssuer: "https://accounts.example.com/",
      },
      {
        claimedIssuer: "https://accounts.example.com",
        delegatedIssuer: "accounts.example.com",
      },
    ];

    for (const testCase of cases) {
      const validated = await createValidatedToken({
        issuer: testCase.claimedIssuer,
      });
      const result = await verifyDnsDelegation({
        token: validated,
        resolveTxt: () =>
          Promise.resolve([[`iss=${testCase.delegatedIssuer}`]]),
      });

      assert.equal(result.ok, true);
      assert.equal(result.value.issuer, "accounts.example.com");
    }
  });

  void it("normalizes host casing and one trailing dot", async () => {
    const validated = await createValidatedToken({
      issuer: "https://ACCOUNTS.Example.COM./",
    });
    const result = await verifyDnsDelegation({
      token: validated,
      resolveTxt: () => Promise.resolve([["iss=Accounts.Example.Com."]]),
    });

    assert.equal(result.ok, true);
    assert.equal(result.value.issuer, "accounts.example.com");
  });

  void it("queries DNS even when the issuer equals the email domain", async () => {
    const validated = await createValidatedToken({
      issuer: "example.com",
    });
    const resolver = createResolveTxtFixture([["iss=example.com"]]);

    const result = await verifyDnsDelegation({
      token: validated,
      resolveTxt: resolver.resolveTxt,
    });

    assert.equal(result.ok, true);
    assert.deepEqual(resolver.calls, ["_email-verification.example.com"]);
  });

  void it("rejects absent or malformed delegation records", async () => {
    const validated = await createValidatedToken();
    const recordSets = [[], [[]], [["v=unrelated"]], [["iss="]]];

    for (const records of recordSets) {
      const result = await verifyDnsDelegation({
        token: validated,
        resolveTxt: () => Promise.resolve(records),
      });

      assertErrorCode(result, "DNS_DELEGATION_MISSING");
    }
  });

  void it("rejects more than one TXT record as ambiguous", async () => {
    const validated = await createValidatedToken();
    const result = await verifyDnsDelegation({
      token: validated,
      resolveTxt: () =>
        Promise.resolve([["iss=accounts.example.com"], ["v=unrelated"]]),
    });

    assertErrorCode(result, "DNS_DELEGATION_AMBIGUOUS");
  });

  void it("rejects multiple issuer values as ambiguous", async () => {
    const validated = await createValidatedToken();
    const recordSets = [
      [["iss=accounts.example.com"], ["iss=backup.example.com"]],
      [["iss=accounts.example.com iss=backup.example.com"]],
    ];

    for (const records of recordSets) {
      const result = await verifyDnsDelegation({
        token: validated,
        resolveTxt: () => Promise.resolve(records),
      });

      assertErrorCode(result, "DNS_DELEGATION_AMBIGUOUS");
    }
  });

  void it("rejects issuer values containing injected URL components", async () => {
    const validated = await createValidatedToken();
    const invalidIssuers = [
      " accounts.example.com",
      "accounts.example.com ",
      "accounts.example.com/path",
      "http://accounts.example.com",
      "https://user@accounts.example.com",
      "https://accounts.example.com/path",
      "https://accounts.example.com?query=value",
      "https://accounts.example.com#fragment",
      "https://accounts.example.com:8443",
    ];

    for (const issuer of invalidIssuers) {
      const result = await verifyDnsDelegation({
        token: validated,
        resolveTxt: () => Promise.resolve([[`iss=${issuer}`]]),
      });

      assertErrorCode(result, "DNS_DELEGATION_MISSING");
    }
  });

  void it("requires an exact match rather than a hostname suffix match", async () => {
    const validated = await createValidatedToken();
    const mismatches = [
      "other.example.com",
      "evilaccounts.example.com",
      "accounts.example.com.evil.test",
    ];

    for (const issuer of mismatches) {
      const result = await verifyDnsDelegation({
        token: validated,
        resolveTxt: () => Promise.resolve([[`iss=${issuer}`]]),
      });

      assertErrorCode(result, "ISSUER_MISMATCH");
    }
  });

  void it("rejects an invalid claimed issuer", async () => {
    const invalidIssuers = [
      "http://accounts.example.com",
      "https://accounts.example.com/path",
      "https://accounts.example.com:8443",
      "accounts.example.com/path",
    ];

    for (const issuer of invalidIssuers) {
      const validated = await createValidatedToken({ issuer });
      const result = await verifyDnsDelegation({
        token: validated,
        resolveTxt: () => Promise.resolve([["iss=accounts.example.com"]]),
      });

      assertErrorCode(result, "ISSUER_MISMATCH");
    }
  });

  void it("turns DNS errors and arbitrary rejections into failures", async () => {
    const validated = await createValidatedToken();
    const failures: unknown[] = [
      Object.assign(new Error("name not found"), { code: "ENOTFOUND" }),
      Object.assign(new Error("no records"), { code: "ENODATA" }),
      Object.assign(new Error("lookup timed out"), { code: "ETIMEOUT" }),
      "resolver rejected",
      { problem: "offline" },
    ];

    for (const failure of failures) {
      const result = await verifyDnsDelegation({
        token: validated,
        resolveTxt: () => ({
          then(_resolve: unknown, reject: (reason: unknown) => void) {
            reject(failure);
          },
        }),
      });

      assertErrorCode(result, "DNS_LOOKUP_FAILED");
      if (result.ok) assert.fail("Expected DNS lookup to fail.");
      assert.equal(typeof result.error.cause, "string");
    }
  });

  void it("contains hostile resolver rejection values", async () => {
    const validated = await createValidatedToken();
    const throwingPrototype = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error("prototype unavailable");
        },
      },
    );
    const throwingMessage = new Proxy(new Error("network down"), {
      get(target, property, receiver) {
        if (property === "message") throw new Error("message unavailable");
        const value: unknown = Reflect.get(target, property, receiver);
        return value;
      },
    });

    for (const failure of [throwingPrototype, throwingMessage]) {
      const result = await verifyDnsDelegation({
        token: validated,
        resolveTxt: () => ({
          then(_resolve: unknown, reject: (reason: unknown) => void) {
            reject(failure);
          },
        }),
      });

      assertErrorCode(result, "DNS_LOOKUP_FAILED");
      if (result.ok) assert.fail("Expected DNS lookup to fail.");
      assert.equal(result.error.cause, "Unknown error");
    }
  });

  void it("rejects malformed resolver output without throwing", async () => {
    const validated = await createValidatedToken();
    const hostileRecords = new Proxy(
      {},
      {
        get() {
          throw new Error("records unavailable");
        },
      },
    );
    const outputs: unknown[] = [
      null,
      "iss=accounts.example.com",
      hostileRecords,
    ];

    for (const output of outputs) {
      const result = await verifyDnsDelegation({
        token: validated,
        resolveTxt: () => Promise.resolve(output),
      });

      assertErrorCode(result, "DNS_LOOKUP_FAILED");
    }
  });

  void it("rejects invalid and hostile public input without throwing", async () => {
    const validated = await createValidatedToken();
    const getterInput = Object.defineProperty(
      { token: validated },
      "resolveTxt",
      {
        enumerable: true,
        get() {
          throw new Error("resolver unavailable");
        },
      },
    );
    const proxyInput = new Proxy(
      {},
      {
        get() {
          throw new Error("input unavailable");
        },
      },
    );
    const inputs: unknown[] = [
      undefined,
      null,
      {},
      { token: validated, resolveTxt: "not a function" },
      getterInput,
      proxyInput,
    ];

    for (const input of inputs) {
      const result = await verifyDnsDelegation(input);
      assertErrorCode(result, "INVALID_INPUT");
    }
  });

  void it("rejects a throwing token getter without invoking DNS", async () => {
    let resolverCalled = false;
    const token = Object.defineProperty({}, "email", {
      enumerable: true,
      get() {
        throw new Error("email unavailable");
      },
    });

    const result = await verifyDnsDelegation({
      token,
      resolveTxt: () => {
        resolverCalled = true;
        return Promise.resolve([["iss=accounts.example.com"]]);
      },
    });

    assertErrorCode(result, "INVALID_INPUT");
    assert.equal(resolverCalled, false);
  });

  void it("rejects ASCII whitespace and controls in a delegated HTTPS authority", async () => {
    const validated = await createValidatedToken();
    const invalidIssuers = [
      "https://accounts.\texample.com",
      "https://accounts.\rexample.com",
      "https://accounts.\nexample.com",
      "https://accounts.\u000bexample.com",
      "https://accounts. example.com",
      "https://accounts.\u007fexample.com",
    ];

    for (const issuer of invalidIssuers) {
      const result = await verifyDnsDelegation({
        token: validated,
        resolveTxt: () => Promise.resolve([[`iss=${issuer}`]]),
      });

      assertErrorCode(result, "DNS_DELEGATION_MISSING");
    }
  });

  void it("rejects ASCII whitespace and controls in a claimed HTTPS authority", async () => {
    const invalidIssuers = [
      "https://accounts.\texample.com",
      "https://accounts.\rexample.com",
      "https://accounts.\nexample.com",
    ];

    for (const issuer of invalidIssuers) {
      const validated = await createValidatedToken({ issuer });
      const result = await verifyDnsDelegation({
        token: validated,
        resolveTxt: () => Promise.resolve([["iss=accounts.example.com"]]),
      });

      assertErrorCode(result, "ISSUER_MISMATCH");
    }
  });

  void it("canonicalizes only valid DNS hostnames and strict HTTPS URLs", () => {
    const validCases = [
      ["Accounts.Example.COM", "accounts.example.com"],
      ["accounts.example.com.", "accounts.example.com"],
      ["https://Accounts.Example.COM/", "accounts.example.com"],
      ["https://accounts.example.com:443", "accounts.example.com"],
    ];

    for (const [input, expected] of validCases) {
      const result = canonicalIssuer(input);
      assert.equal(result.ok, true);
      assert.equal(result.value, expected);
    }

    const invalidCases: unknown[] = [
      "",
      " accounts.example.com",
      "accounts..example.com",
      "-accounts.example.com",
      "accounts.example.com-",
      "accounts.example.com/path",
      "http://accounts.example.com",
      "https://user:pass@accounts.example.com",
      "https://accounts.example.com:8443",
      "https://accounts.example.com/path",
      "https://accounts.example.com?query=value",
      "https://accounts.example.com#fragment",
      "https://accounts.\texample.com",
      "https://accounts.\rexample.com",
      "https://accounts.\nexample.com",
      "https://accounts.\u000bexample.com",
      "https://accounts. example.com",
      "https://accounts.\u007fexample.com",
      42,
      null,
    ];

    for (const input of invalidCases) {
      assert.equal(canonicalIssuer(input).ok, false);
    }
  });
});
