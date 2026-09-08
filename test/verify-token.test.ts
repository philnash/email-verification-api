import assert from "node:assert/strict";
import { resolveTxt as defaultResolveTxt } from "node:dns/promises";
import { describe, it } from "node:test";
import { generateKeyPair } from "jose";
import { parseToken } from "../src/parse-token.js";
import type { Result, VerificationErrorCode } from "../src/result.js";
import {
  IssuerVerifiedTokenSchema,
  KeyBindingVerifiedTokenSchema,
  VerifiedEmailSchema,
  VerifyEmailTokenInputSchema,
  type VerifiedEmail,
} from "../src/schemas.js";
import { verifyEmailToken } from "../src/verify-token.js";
import { createFetchFixture } from "./helpers/network-fixture.js";
import { createTokenFixture } from "./helpers/token-fixture.js";

const nowEpochSeconds = 1_800_000_000;
const metadataUrl =
  "https://accounts.example.com/.well-known/email-verification";
const jwksUrl = "https://keys.accounts.example.com/email-verification/jwks";
const normalizationAcceptedAsciiControls = ["\t", "\r", "\n"];

function publicResolveHost(): Promise<
  readonly { address: string; family: 4 | 6 }[]
> {
  return Promise.resolve([{ address: "8.8.8.8", family: 4 }]);
}

type TokenFixture = Awaited<ReturnType<typeof createTokenFixture>>;

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function metadata(overrides: Record<string, unknown> = {}) {
  return {
    issuer: "https://accounts.example.com",
    issuance_endpoint: "https://accounts.example.com/email-verification/issue",
    jwks_uri: jwksUrl,
    signing_alg_values_supported: ["EdDSA"],
    ...overrides,
  };
}

function validRoutes(fixture: TokenFixture) {
  return {
    [metadataUrl]: () => jsonResponse(metadata()),
    [jwksUrl]: () => jsonResponse({ keys: [fixture.issuerPublicJwk] }),
  };
}

function validInput(
  fixture: TokenFixture,
  overrides: Record<string, unknown> = {},
) {
  const network = createFetchFixture(validRoutes(fixture));
  const dnsCalls: string[] = [];
  return {
    input: {
      token: fixture.token,
      nonce: fixture.nonce,
      email: fixture.email,
      audience: fixture.audience,
      now: () => nowEpochSeconds * 1_000,
      resolveTxt: (hostname: string) => {
        dnsCalls.push(hostname);
        return Promise.resolve([["iss=accounts.example.com"]]);
      },
      resolveHost: publicResolveHost,
      fetch: network.fetch,
      ...overrides,
    },
    dnsCalls,
    fetchCalls: network.calls,
  };
}

function assertFailure(
  result: Result<VerifiedEmail>,
  stage: string,
  code: VerificationErrorCode,
): void {
  assert.equal(result.ok, false);
  assert.equal(result.error.stage, stage);
  assert.equal(result.error.code, code);
}

function replaceEvt(token: string, oldEvt: string, newEvt: string): string {
  assert.equal(token.startsWith(oldEvt), true);
  return `${newEvt}${token.slice(oldEvt.length)}`;
}

function mutateSignature(compact: string): string {
  const parts = compact.split(".");
  const signature = parts[2];
  if (signature === undefined) assert.fail("Compact signature is missing.");
  const first = signature[0];
  if (first === undefined) assert.fail("Compact signature is empty.");
  parts[2] = `${first === "A" ? "B" : "A"}${signature.slice(1)}`;
  return parts.join(".");
}

void describe("verifyEmailToken", () => {
  for (const discloseEmail of [false, true]) {
    for (const includeEvtKid of [true, false]) {
      void it(`verifies a ${discloseEmail ? "selectively disclosed" : "direct"} email token ${includeEvtKid ? "with" : "without"} kid end to end`, async () => {
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
      });
    }
  }

  void it("calls DNS, metadata, and JWKS in protocol trust order", async () => {
    const fixture = await createTokenFixture();
    const events: string[] = [];
    const network = createFetchFixture(validRoutes(fixture));

    const result = await verifyEmailToken({
      token: fixture.token,
      nonce: fixture.nonce,
      email: fixture.email,
      audience: fixture.audience,
      now: () => nowEpochSeconds * 1_000,
      resolveTxt: (hostname) => {
        events.push(hostname);
        return Promise.resolve([["iss=accounts.example.com"]]);
      },
      resolveHost: (hostname) => {
        events.push(`resolve:${hostname}`);
        return publicResolveHost();
      },
      fetch: async (input) => {
        const url =
          typeof input === "string"
            ? input
            : input instanceof URL
              ? input.href
              : input.url;
        events.push(url);
        return network.fetch(input);
      },
    });

    assert.equal(result.ok, true);
    assert.deepEqual(events, [
      "_email-verification.example.com",
      "resolve:accounts.example.com",
      metadataUrl,
      "resolve:keys.accounts.example.com",
      jwksUrl,
    ]);
  });

  void it("parses documented defaults without making network requests", () => {
    const parsed = VerifyEmailTokenInputSchema.parse({
      token: "not-run",
      nonce: "example-nonce",
      email: "user@example.com",
      audience: "https://rp.example.com",
    });

    assert.equal(parsed.maxTokenAgeSeconds, 300);
    assert.equal(parsed.clockToleranceSeconds, 60);
    assert.equal(parsed.fetch, globalThis.fetch);
    assert.equal(parsed.resolveTxt, defaultResolveTxt);
    assert.equal(typeof parsed.resolveHost, "function");
    assert.equal(typeof parsed.now, "function");
    assert.equal(parsed.signal, undefined);
    assert.equal(parsed.timeoutMs, null);
    assert.deepEqual(parsed.timeouts, {
      resolveTxtMs: null,
      resolveHostMs: null,
      metadataFetchMs: null,
      jwksFetchMs: null,
    });
  });

  void it("returns an aborted input result before dependencies run", async () => {
    const fixture = await createTokenFixture();
    const controller = new AbortController();
    controller.abort("DO_NOT_EXPOSE");
    const { input, dnsCalls, fetchCalls } = validInput(fixture, {
      signal: controller.signal,
    });

    const result = await verifyEmailToken(input);

    assertFailure(result, "input", "REQUEST_ABORTED");
    assert.deepEqual(dnsCalls, []);
    assert.deepEqual(fetchCalls, []);
    assert.equal(JSON.stringify(result).includes("DO_NOT_EXPOSE"), false);
  });

  void it("applies the overall deadline when operation limits are null", async () => {
    const fixture = await createTokenFixture();
    const { input, fetchCalls } = validInput(fixture, {
      timeoutMs: 100,
      timeouts: null,
      resolveTxt: () => new Promise<string[][]>(() => undefined),
    });

    const result = await verifyEmailToken(input);

    assertFailure(result, "dns", "REQUEST_TIMEOUT");
    assert.deepEqual(fetchCalls, []);
  });

  void it("applies every nested timeout to its named external operation", async () => {
    const fixture = await createTokenFixture();
    const cases: readonly [
      string,
      Record<string, unknown>,
      "dns" | "issuer",
      readonly string[],
    ][] = [
      [
        "resolveTxtMs",
        {
          resolveTxt: () => new Promise<string[][]>(() => undefined),
          timeouts: { resolveTxtMs: 1 },
        },
        "dns",
        [],
      ],
      [
        "resolveHostMs",
        {
          resolveHost: () =>
            new Promise<readonly { address: string; family: 4 | 6 }[]>(
              () => undefined,
            ),
          timeouts: { resolveHostMs: 1 },
        },
        "issuer",
        [],
      ],
      [
        "metadataFetchMs",
        {
          fetch: () => new Promise<Response>(() => undefined),
          timeouts: { metadataFetchMs: 1 },
        },
        "issuer",
        [metadataUrl],
      ],
      [
        "jwksFetchMs",
        {
          fetch: (input: string | URL | Request) => {
            const url =
              typeof input === "string"
                ? input
                : input instanceof URL
                  ? input.href
                  : input.url;
            return url === metadataUrl
              ? Promise.resolve(jsonResponse(metadata()))
              : new Promise<Response>(() => undefined);
          },
          timeouts: { jwksFetchMs: 1 },
        },
        "issuer",
        [metadataUrl, jwksUrl],
      ],
    ];

    for (const [name, overrides, stage, expectedFetchCalls] of cases) {
      const fetchCalls: string[] = [];
      const overrideFetch = overrides["fetch"];
      const typedFetch = overrideFetch as (
        request: string | URL | Request,
        init?: RequestInit,
      ) => Promise<Response>;
      const { input } = validInput(fixture, {
        ...overrides,
        ...(typeof overrideFetch === "function"
          ? {
              fetch: (request: string | URL | Request, init?: RequestInit) => {
                const url =
                  typeof request === "string"
                    ? request
                    : request instanceof URL
                      ? request.href
                      : request.url;
                fetchCalls.push(url);
                return typedFetch(request, init);
              },
            }
          : {}),
      });

      const result = await verifyEmailToken(input);

      assertFailure(result, stage, "REQUEST_TIMEOUT");
      assert.deepEqual(fetchCalls, expectedFetchCalls, name);
    }
  });

  void it("leaves omitted timeout defaults unbounded", async () => {
    const fixture = await createTokenFixture();
    const { input } = validInput(fixture, {
      resolveTxt: async () => {
        await new Promise<void>((resolve) => setTimeout(resolve, 5));
        return [["iss=accounts.example.com"]];
      },
    });

    const result = await verifyEmailToken(input);

    assert.equal(result.ok, true);
  });

  void it("cancels during DNS and does not expose the abort reason or continue", async () => {
    const fixture = await createTokenFixture();
    const controller = new AbortController();
    const { input, fetchCalls } = validInput(fixture, {
      signal: controller.signal,
      resolveTxt: () => {
        controller.abort("DO_NOT_EXPOSE");
        return new Promise<string[][]>(() => undefined);
      },
    });

    const result = await verifyEmailToken(input);

    assertFailure(result, "dns", "REQUEST_ABORTED");
    assert.deepEqual(fetchCalls, []);
    assert.equal(JSON.stringify(result).includes("DO_NOT_EXPOSE"), false);
  });

  void it("checks the overall deadline after DNS semantic processing", async () => {
    const fixture = await createTokenFixture();
    const records = Array.from({ length: 300_000 }, () => [
      "iss=accounts.example.com",
    ]);
    const { input, fetchCalls } = validInput(fixture, {
      timeoutMs: 10,
      resolveTxt: () => Promise.resolve(records),
    });

    const result = await verifyEmailToken(input);

    assertFailure(result, "dns", "REQUEST_TIMEOUT");
    assert.deepEqual(fetchCalls, []);
  });

  void it("prefers caller cancellation after DNS semantic processing", async () => {
    const fixture = await createTokenFixture();
    const controller = new AbortController();
    const hostileRecords = new Proxy([["iss=accounts.example.com"]], {
      get(target, property, receiver) {
        if (property === "length") {
          controller.abort("DO_NOT_EXPOSE");
          throw new Error("records unavailable");
        }
        const value: unknown = Reflect.get(target, property, receiver);
        return value;
      },
    });
    const { input, fetchCalls } = validInput(fixture, {
      signal: controller.signal,
      resolveTxt: () => Promise.resolve(hostileRecords),
    });

    const result = await verifyEmailToken(input);

    assertFailure(result, "dns", "REQUEST_ABORTED");
    assert.deepEqual(fetchCalls, []);
    assert.equal(JSON.stringify(result).includes("DO_NOT_EXPOSE"), false);
  });

  void it("checks cancellation after issuer verification before key binding", async () => {
    const fixture = await createTokenFixture();
    const controller = new AbortController();
    const originalSafeParse = IssuerVerifiedTokenSchema.safeParse.bind(
      IssuerVerifiedTokenSchema,
    );
    IssuerVerifiedTokenSchema.safeParse = (value: unknown) => {
      const parsed = originalSafeParse(value);
      queueMicrotask(() => {
        controller.abort("DO_NOT_EXPOSE");
      });
      return parsed;
    };

    try {
      const result = await verifyEmailToken({
        ...validInput(fixture).input,
        signal: controller.signal,
      });

      assertFailure(result, "issuer", "REQUEST_ABORTED");
      assert.equal(JSON.stringify(result).includes("DO_NOT_EXPOSE"), false);
    } finally {
      IssuerVerifiedTokenSchema.safeParse = originalSafeParse;
    }
  });

  void it("checks cancellation after token parsing before starting DNS", async () => {
    const fixture = await createTokenFixture({ discloseEmail: true });
    const controller = new AbortController();
    const { input, dnsCalls, fetchCalls } = validInput(fixture, {
      signal: controller.signal,
    });
    queueMicrotask(() => {
      controller.abort("DO_NOT_EXPOSE");
    });

    const result = await verifyEmailToken(input);

    assertFailure(result, "parse", "REQUEST_ABORTED");
    assert.deepEqual(dnsCalls, []);
    assert.deepEqual(fetchCalls, []);
  });

  void it("checks cancellation after expected-values validation", async () => {
    const fixture = await createTokenFixture();
    const controller = new AbortController();
    const { input, dnsCalls, fetchCalls } = validInput(fixture, {
      signal: controller.signal,
      now: () => {
        controller.abort("DO_NOT_EXPOSE");
        return nowEpochSeconds * 1_000;
      },
    });

    const result = await verifyEmailToken(input);

    assertFailure(result, "expected-values", "REQUEST_ABORTED");
    assert.deepEqual(dnsCalls, []);
    assert.deepEqual(fetchCalls, []);
  });

  void it("checks cancellation after asynchronous key-binding work", async () => {
    const fixture = await createTokenFixture();
    const controller = new AbortController();
    const originalSafeParse = KeyBindingVerifiedTokenSchema.safeParse.bind(
      KeyBindingVerifiedTokenSchema,
    );
    KeyBindingVerifiedTokenSchema.safeParse = (value: unknown) => {
      const parsed = originalSafeParse(value);
      controller.abort("DO_NOT_EXPOSE");
      return parsed;
    };

    try {
      const result = await verifyEmailToken({
        ...validInput(fixture).input,
        signal: controller.signal,
      });

      assertFailure(result, "key-binding", "REQUEST_ABORTED");
      assert.equal(JSON.stringify(result).includes("DO_NOT_EXPOSE"), false);
    } finally {
      KeyBindingVerifiedTokenSchema.safeParse = originalSafeParse;
    }
  });

  void it("performs a final interruption checkpoint before success", async () => {
    const fixture = await createTokenFixture();
    const controller = new AbortController();
    const originalSafeParse =
      VerifiedEmailSchema.safeParse.bind(VerifiedEmailSchema);
    let parseCalls = 0;
    VerifiedEmailSchema.safeParse = (value: unknown) => {
      parseCalls += 1;
      const parsed = originalSafeParse(value);
      if (parseCalls === 2) controller.abort("DO_NOT_EXPOSE");
      return parsed;
    };

    try {
      const result = await verifyEmailToken({
        ...validInput(fixture).input,
        signal: controller.signal,
      });

      assertFailure(result, "key-binding", "REQUEST_ABORTED");
      assert.equal(parseCalls, 2);
      assert.equal(JSON.stringify(result).includes("DO_NOT_EXPOSE"), false);
    } finally {
      VerifiedEmailSchema.safeParse = originalSafeParse;
    }
  });

  void it("passes resolveHost failures through the issuer stage", async () => {
    const fixture = await createTokenFixture();
    let resolveCalls = 0;
    const { input, fetchCalls } = validInput(fixture, {
      resolveHost: () => {
        resolveCalls += 1;
        return Promise.reject(new Error("lookup failed"));
      },
    });

    const result = await verifyEmailToken(input);

    assertFailure(result, "issuer", "METADATA_FETCH_FAILED");
    assert.equal(resolveCalls, 1);
    assert.deepEqual(fetchCalls, []);
  });

  void it("returns input failures for malformed and hostile input", async () => {
    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error("hostile getter");
        },
      },
    );

    for (const input of [undefined, null, {}, hostile]) {
      // @ts-expect-error Exercise the runtime boundary with invalid JS input.
      const result = await verifyEmailToken(input);
      assertFailure(result, "input", "INVALID_INPUT");
    }
  });

  void it("rejects raw ASCII whitespace and controls in the caller audience before dependencies run", async () => {
    const fixture = await createTokenFixture();

    for (const character of normalizationAcceptedAsciiControls) {
      const { input, dnsCalls, fetchCalls } = validInput(fixture, {
        audience: `https://rp.example${character}.com`,
      });
      const result = await verifyEmailToken(input);

      assertFailure(result, "expected-values", "AUDIENCE_MISMATCH");
      assert.deepEqual(dnsCalls, []);
      assert.deepEqual(fetchCalls, []);
    }
  });

  void it("rejects raw ASCII whitespace and controls in a signed KB audience before dependencies run", async () => {
    for (const character of normalizationAcceptedAsciiControls) {
      const fixture = await createTokenFixture({
        audience: `https://rp.example${character}.com`,
      });
      const { input, dnsCalls, fetchCalls } = validInput(fixture, {
        audience: "https://rp.example.com",
      });
      const result = await verifyEmailToken(input);

      assertFailure(result, "expected-values", "AUDIENCE_MISMATCH");
      assert.deepEqual(dnsCalls, []);
      assert.deepEqual(fetchCalls, []);
    }
  });

  void it("propagates every parse and expected-values error code before dependencies run", async () => {
    const fixture = await createTokenFixture();
    const unmatchedDisclosure = Buffer.from(
      JSON.stringify(["salt", "other", "value"]),
    ).toString("base64url");
    const disclosureToken = `${fixture.evt}~${unmatchedDisclosure}~${fixture.kb}`;
    const unverifiedFixture = await createTokenFixture({
      emailVerified: false,
    });
    const expiredFixture = await createTokenFixture({
      evtIssuedAt: nowEpochSeconds - 361,
      kbIssuedAt: nowEpochSeconds - 361,
    });
    const futureFixture = await createTokenFixture({
      evtIssuedAt: nowEpochSeconds + 61,
      kbIssuedAt: nowEpochSeconds + 61,
    });
    const cases: readonly [
      Record<string, unknown>,
      string,
      VerificationErrorCode,
    ][] = [
      [
        { ...validInput(fixture).input, token: "malformed" },
        "parse",
        "TOKEN_MALFORMED",
      ],
      [
        { ...validInput(fixture).input, token: disclosureToken },
        "parse",
        "DISCLOSURE_INVALID",
      ],
      [
        { ...validInput(fixture).input, email: "other@example.com" },
        "expected-values",
        "EMAIL_MISMATCH",
      ],
      [
        validInput(unverifiedFixture).input,
        "expected-values",
        "EMAIL_NOT_VERIFIED",
      ],
      [
        { ...validInput(fixture).input, nonce: "wrong-nonce" },
        "expected-values",
        "NONCE_MISMATCH",
      ],
      [
        { ...validInput(fixture).input, audience: "https://other.example.com" },
        "expected-values",
        "AUDIENCE_MISMATCH",
      ],
      [validInput(expiredFixture).input, "expected-values", "TOKEN_EXPIRED"],
      [
        validInput(futureFixture).input,
        "expected-values",
        "TOKEN_NOT_YET_VALID",
      ],
      [
        {
          ...validInput(fixture).input,
          now: () => {
            throw new Error("clock failed");
          },
        },
        "expected-values",
        "INVALID_INPUT",
      ],
    ];

    for (const [input, stage, code] of cases) {
      let dnsCalls = 0;
      let fetchCalls = 0;
      // @ts-expect-error Exercise staged runtime failures from a dynamic input.
      const result = await verifyEmailToken({
        ...input,
        resolveTxt: () => {
          dnsCalls += 1;
          throw new Error("DNS must not run");
        },
        fetch: () => {
          fetchCalls += 1;
          throw new Error("Fetch must not run");
        },
      });
      assertFailure(result, stage, code);
      assert.equal(dnsCalls, 0);
      assert.equal(fetchCalls, 0);
    }
  });

  void it("propagates every DNS error code and never fetches after DNS failure", async () => {
    const fixture = await createTokenFixture();
    const cases: readonly [() => Promise<string[][]>, VerificationErrorCode][] =
      [
        [() => Promise.reject(new Error("offline")), "DNS_LOOKUP_FAILED"],
        [() => Promise.resolve([]), "DNS_DELEGATION_MISSING"],
        [
          () =>
            Promise.resolve([
              ["iss=accounts.example.com"],
              ["iss=backup.example.com"],
            ]),
          "DNS_DELEGATION_AMBIGUOUS",
        ],
        [() => Promise.resolve([["iss=other.example.com"]]), "ISSUER_MISMATCH"],
      ];

    for (const [resolveTxt, code] of cases) {
      let fetchCalls = 0;
      const result = await verifyEmailToken({
        ...validInput(fixture).input,
        resolveTxt,
        fetch: () => {
          fetchCalls += 1;
          throw new Error("Fetch must not run");
        },
      });
      assertFailure(result, "dns", code);
      assert.equal(fetchCalls, 0);
    }
  });

  void it("propagates every issuer error code with ordered, bounded Fetch calls", async () => {
    const fixture = await createTokenFixture();
    const invalidEvt = replaceEvt(
      fixture.token,
      fixture.evt,
      mutateSignature(fixture.evt),
    );
    const cases: readonly [
      string,
      Record<string, Response | (() => Response | Promise<Response>)>,
      VerificationErrorCode,
      readonly string[],
    ][] = [
      [
        fixture.token,
        { [metadataUrl]: () => new Response("DO_NOT_LEAK", { status: 503 }) },
        "METADATA_FETCH_FAILED",
        [metadataUrl],
      ],
      [
        fixture.token,
        { [metadataUrl]: () => jsonResponse({}) },
        "METADATA_INVALID",
        [metadataUrl],
      ],
      [
        fixture.token,
        {
          [metadataUrl]: () => jsonResponse(metadata()),
          [jwksUrl]: () => new Response("DO_NOT_LEAK", { status: 503 }),
        },
        "JWKS_FETCH_FAILED",
        [metadataUrl, jwksUrl],
      ],
      [
        fixture.token,
        {
          [metadataUrl]: () => jsonResponse(metadata()),
          [jwksUrl]: () => jsonResponse({ keys: [] }),
        },
        "JWKS_INVALID",
        [metadataUrl, jwksUrl],
      ],
      [
        fixture.token,
        {
          [metadataUrl]: () =>
            jsonResponse(metadata({ signing_alg_values_supported: ["ES256"] })),
        },
        "ALGORITHM_UNSUPPORTED",
        [metadataUrl],
      ],
      [
        invalidEvt,
        validRoutes(fixture),
        "EVT_SIGNATURE_INVALID",
        [metadataUrl, jwksUrl],
      ],
    ];

    for (const [token, routes, code, expectedCalls] of cases) {
      const network = createFetchFixture(routes);
      const result = await verifyEmailToken({
        ...validInput(fixture).input,
        token,
        fetch: network.fetch,
      });
      assertFailure(result, "issuer", code);
      assert.deepEqual(network.calls, expectedCalls);
      assert.equal(JSON.stringify(result).includes("DO_NOT_LEAK"), false);
    }
  });

  void it("contains rejected Fetch callbacks", async () => {
    const fixture = await createTokenFixture();
    const result = await verifyEmailToken({
      ...validInput(fixture).input,
      fetch: () => Promise.reject(new Error("offline")),
    });

    assertFailure(result, "issuer", "METADATA_FETCH_FAILED");
  });

  void it("propagates both key-binding errors only after DNS and issuer verification", async () => {
    const fixture = await createTokenFixture();
    const unrelatedHolder = await generateKeyPair("Ed25519");
    const badSignature = await fixture.rebuildToken({
      kbSigningKey: unrelatedHolder.privateKey,
    });
    const badHash = await fixture.rebuildToken({
      sdHashPresentation: "different-presentation~",
    });

    for (const [token, code] of [
      [badSignature.token, "KB_SIGNATURE_INVALID"],
      [badHash.token, "SD_HASH_MISMATCH"],
    ] as const) {
      const { input, dnsCalls, fetchCalls } = validInput(fixture, { token });
      const result = await verifyEmailToken(input);

      assertFailure(result, "key-binding", code);
      assert.deepEqual(dnsCalls, ["_email-verification.example.com"]);
      assert.deepEqual(fetchCalls, [metadataUrl, jwksUrl]);
    }
  });
});
