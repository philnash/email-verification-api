import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import { parseToken } from "../src/parse-token.js";
import { createTokenFixture } from "./helpers/token-fixture.js";

type JsonObject = Record<string, unknown>;

void describe("parseToken", () => {
  void it("parses a direct email EVT+KB token", async () => {
    const fixture = await createTokenFixture();
    const result = await parseToken(fixture.token);

    assert.equal(result.ok, true);
    assert.equal(result.value.evt.claims.email, "user@example.com");
    assert.deepEqual(result.value.disclosures, []);
    assert.equal(result.value.presentation, fixture.presentation);
  });

  void it("resolves a selectively disclosed email", async () => {
    const fixture = await createTokenFixture({ discloseEmail: true });
    const result = await parseToken(fixture.token);

    assert.equal(result.ok, true);
    assert.equal(result.value.evt.claims.email, "user@example.com");
    assert.equal(result.value.disclosures.length, 1);
  });

  const malformedCases: readonly {
    name: string;
    token: () => Promise<unknown>;
  }[] = [
    {
      name: "rejects a non-string input",
      token: () => Promise.resolve({ token: "not-a-string" }),
    },
    { name: "rejects an empty token", token: () => Promise.resolve("") },
    {
      name: "rejects a JWT without an SD-JWT separator",
      token: async () => (await createTokenFixture()).evt,
    },
    {
      name: "rejects a token without a KB-JWT",
      token: async () => `${(await createTokenFixture()).evt}~`,
    },
    {
      name: "rejects an extra empty disclosure segment",
      token: async () => {
        const fixture = await createTokenFixture();
        return `${fixture.evt}~~${fixture.kb}`;
      },
    },
    {
      name: "rejects invalid base64url in an EVT header",
      token: async () =>
        mutateEvt(await tokenFixture(), (jwt) => replacePart(jwt, 0, "%")),
    },
    {
      name: "rejects invalid JSON in an EVT payload",
      token: async () =>
        mutateEvt(await tokenFixture(), (jwt) =>
          replacePart(jwt, 1, Buffer.from("not json").toString("base64url")),
        ),
    },
    {
      name: "rejects an EVT with the wrong compact segment count",
      token: async () =>
        mutateEvt(await tokenFixture(), (jwt) => `${jwt}.extra`),
    },
    {
      name: "rejects a missing EVT typ",
      token: async () =>
        mutateEvtJson(await tokenFixture(), "header", (header) => {
          delete header["typ"];
        }),
    },
    {
      name: "rejects a wrong EVT typ",
      token: async () =>
        mutateEvtJson(await tokenFixture(), "header", (header) => {
          header["typ"] = "JWT";
        }),
    },
    {
      name: "rejects an empty EVT alg",
      token: async () =>
        mutateEvtJson(await tokenFixture(), "header", (header) => {
          header["alg"] = "";
        }),
    },
    {
      name: "rejects an unsecured EVT algorithm",
      token: async () =>
        mutateEvtJson(await tokenFixture(), "header", (header) => {
          header["alg"] = "none";
        }),
    },
    {
      name: "rejects a missing EVT kid",
      token: async () =>
        mutateEvtJson(await tokenFixture(), "header", (header) => {
          delete header["kid"];
        }),
    },
    ...["iss", "iat", "cnf", "email", "email_verified"].map((claim) => ({
      name: `rejects a missing EVT ${claim} claim`,
      token: async () =>
        mutateEvtJson(await tokenFixture(), "payload", (payload) => {
          Reflect.deleteProperty(payload, claim);
        }),
    })),
    {
      name: "rejects an invalid email claim",
      token: async () =>
        mutateEvtJson(await tokenFixture(), "payload", (payload) => {
          payload["email"] = "not-an-email";
        }),
    },
    {
      name: "rejects a noninteger EVT iat",
      token: async () =>
        mutateEvtJson(await tokenFixture(), "payload", (payload) => {
          payload["iat"] = 1.5;
        }),
    },
    {
      name: "rejects a nonboolean email_verified claim",
      token: async () =>
        mutateEvtJson(await tokenFixture(), "payload", (payload) => {
          payload["email_verified"] = "true";
        }),
    },
    {
      name: "rejects an invalid holder JWK",
      token: async () =>
        mutateEvtJson(await tokenFixture(), "payload", (payload) => {
          payload["cnf"] = { jwk: { kty: "OKP", crv: "Ed25519" } };
        }),
    },
    {
      name: "rejects a private holder JWK",
      token: async () =>
        mutateEvtJson(await tokenFixture(), "payload", (payload) => {
          const cnf = readObject(payload["cnf"]);
          const jwk = readObject(cnf["jwk"]);
          jwk["d"] = "cHJpdmF0ZQ";
          cnf["jwk"] = jwk;
          payload["cnf"] = cnf;
        }),
    },
    {
      name: "rejects a missing KB typ",
      token: async () =>
        mutateKbJson(await tokenFixture(), "header", (header) => {
          delete header["typ"];
        }),
    },
    {
      name: "rejects an empty KB alg",
      token: async () =>
        mutateKbJson(await tokenFixture(), "header", (header) => {
          header["alg"] = "";
        }),
    },
    ...["aud", "nonce", "iat", "sd_hash"].map((claim) => ({
      name: `rejects a missing KB ${claim} claim`,
      token: async () =>
        mutateKbJson(await tokenFixture(), "payload", (payload) => {
          Reflect.deleteProperty(payload, claim);
        }),
    })),
    {
      name: "rejects an invalid KB audience",
      token: async () =>
        mutateKbJson(await tokenFixture(), "payload", (payload) => {
          payload["aud"] = "not a URL";
        }),
    },
    {
      name: "rejects an empty KB nonce",
      token: async () =>
        mutateKbJson(await tokenFixture(), "payload", (payload) => {
          payload["nonce"] = "";
        }),
    },
    {
      name: "rejects invalid base64url in sd_hash",
      token: async () =>
        mutateKbJson(await tokenFixture(), "payload", (payload) => {
          payload["sd_hash"] = "%";
        }),
    },
  ];

  for (const malformedCase of malformedCases) {
    void it(malformedCase.name, async () => {
      const result = await parseToken(await malformedCase.token());
      assertParseError(result, "TOKEN_MALFORMED");
    });
  }

  const disclosureCases: readonly {
    name: string;
    token: () => Promise<string>;
  }[] = [
    {
      name: "rejects a malformed disclosure",
      token: async () => {
        const fixture = await createTokenFixture();
        return `${fixture.evt}~not-a-disclosure~${fixture.kb}`;
      },
    },
    {
      name: "rejects a disclosure with a non-string salt",
      token: async () =>
        replaceEmailDisclosure(await tokenFixture({ discloseEmail: true }), [
          123,
          "email",
          "user@example.com",
        ]),
    },
    {
      name: "rejects a disclosure with a non-string claim name",
      token: async () =>
        replaceEmailDisclosure(await tokenFixture({ discloseEmail: true }), [
          "salt",
          ["email"],
          "user@example.com",
        ]),
    },
    {
      name: "rejects an unsupported disclosure hash algorithm",
      token: async () =>
        mutateEvtJson(
          await tokenFixture({ discloseEmail: true }),
          "payload",
          (payload) => {
            payload["_sd_alg"] = "unsupported";
          },
        ),
    },
    {
      name: "rejects an unmatched disclosure",
      token: async () =>
        mutateEvtJson(
          await tokenFixture({ discloseEmail: true }),
          "payload",
          (payload) => {
            payload["_sd"] = ["dW5tYXRjaGVk"];
          },
        ),
    },
    {
      name: "rejects a duplicate disclosure digest",
      token: async () =>
        mutateEvtJson(
          await tokenFixture({ discloseEmail: true }),
          "payload",
          (payload) => {
            const digests = Array.isArray(payload["_sd"]) ? payload["_sd"] : [];
            payload["_sd"] = [digests[0], digests[0]];
          },
        ),
    },
    {
      name: "rejects a direct and disclosed email conflict",
      token: async () =>
        mutateEvtJson(
          await tokenFixture({ discloseEmail: true }),
          "payload",
          (payload) => {
            payload["email"] = "other@example.com";
          },
        ),
    },
  ];

  for (const disclosureCase of disclosureCases) {
    void it(disclosureCase.name, async () => {
      const result = await parseToken(await disclosureCase.token());
      assertParseError(result, "DISCLOSURE_INVALID");
    });
  }
});

async function tokenFixture(options?: { discloseEmail?: boolean }) {
  return createTokenFixture(options);
}

function assertParseError(
  result: Awaited<ReturnType<typeof parseToken>>,
  code: "TOKEN_MALFORMED" | "DISCLOSURE_INVALID",
) {
  assert.equal(result.ok, false);
  assert.equal(result.error.stage, "parse");
  assert.equal(result.error.code, code);
}

function mutateEvt(
  fixture: Awaited<ReturnType<typeof createTokenFixture>>,
  mutate: (jwt: string) => string,
) {
  return fixture.token.replace(fixture.evt, mutate(fixture.evt));
}

function mutateKb(
  fixture: Awaited<ReturnType<typeof createTokenFixture>>,
  mutate: (jwt: string) => string,
) {
  return fixture.token.replace(fixture.kb, mutate(fixture.kb));
}

function mutateEvtJson(
  fixture: Awaited<ReturnType<typeof createTokenFixture>>,
  part: "header" | "payload",
  mutate: (value: JsonObject) => void,
) {
  return mutateEvt(fixture, (jwt) => mutateJwtJson(jwt, part, mutate));
}

function mutateKbJson(
  fixture: Awaited<ReturnType<typeof createTokenFixture>>,
  part: "header" | "payload",
  mutate: (value: JsonObject) => void,
) {
  return mutateKb(fixture, (jwt) => mutateJwtJson(jwt, part, mutate));
}

function mutateJwtJson(
  jwt: string,
  part: "header" | "payload",
  mutate: (value: JsonObject) => void,
) {
  const index = part === "header" ? 0 : 1;
  const encoded = jwt.split(".")[index] ?? "";
  const value: unknown = JSON.parse(
    Buffer.from(encoded, "base64url").toString("utf8"),
  );
  const object = readObject(value);
  mutate(object);
  return replacePart(
    jwt,
    index,
    Buffer.from(JSON.stringify(object)).toString("base64url"),
  );
}

function replaceEmailDisclosure(
  fixture: Awaited<ReturnType<typeof createTokenFixture>>,
  disclosureTuple: unknown[],
) {
  const originalDisclosure = fixture.presentation.split("~")[1];
  if (originalDisclosure === undefined) {
    throw new TypeError("Expected a disclosed email fixture");
  }
  const encodedDisclosure = Buffer.from(
    JSON.stringify(disclosureTuple),
  ).toString("base64url");
  const digest = createHash("sha256")
    .update(encodedDisclosure)
    .digest("base64url");
  const tokenWithDigest = mutateEvtJson(fixture, "payload", (payload) => {
    payload["_sd"] = [digest];
  });
  return tokenWithDigest.replace(originalDisclosure, encodedDisclosure);
}

function replacePart(jwt: string, index: number, replacement: string) {
  const parts = jwt.split(".");
  parts[index] = replacement;
  return parts.join(".");
}

function readObject(value: unknown): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Expected a JSON object");
  }
  return Object.fromEntries(Object.entries(value));
}
