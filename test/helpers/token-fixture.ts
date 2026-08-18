import { createHash } from "node:crypto";
import { Disclosure, uint8ArrayToBase64Url } from "@sd-jwt/core";
import {
  CompactSign,
  exportJWK,
  generateKeyPair,
  type CompactJWSHeaderParameters,
} from "jose";
import { PublicJwkSchema } from "../../src/schemas.js";

const encoder = new TextEncoder();
type SigningKey = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];

export interface TokenFixtureOptions {
  email?: string;
  issuer?: string;
  audience?: string;
  nonce?: string;
  evtIssuedAt?: number;
  kbIssuedAt?: number;
  discloseEmail?: boolean;
  emailVerified?: boolean;
}

export interface RebuildTokenOptions {
  evtPayload?: Record<string, unknown>;
  evtHeader?: CompactJWSHeaderParameters;
  kbPayload?: Record<string, unknown>;
  kbHeader?: CompactJWSHeaderParameters;
  kbSigningKey?: SigningKey;
  sdHashPresentation?: string;
}

export async function createTokenFixture(options: TokenFixtureOptions = {}) {
  const email = options.email ?? "user@example.com";
  const issuer = options.issuer ?? "https://accounts.example.com";
  const audience = options.audience ?? "https://rp.example.com";
  const nonce = options.nonce ?? "example-nonce";
  const evtIssuedAt = options.evtIssuedAt ?? 1_800_000_000;
  const kbIssuedAt = options.kbIssuedAt ?? evtIssuedAt;
  const issuerKeys = await generateKeyPair("Ed25519", { extractable: true });
  const holderKeys = await generateKeyPair("Ed25519", { extractable: true });
  const issuerPublicJwk = PublicJwkSchema.parse({
    ...(await exportJWK(issuerKeys.publicKey)),
    kid: "issuer-key",
    alg: "EdDSA",
  });
  const holderPublicJwk = PublicJwkSchema.parse(
    await exportJWK(holderKeys.publicKey),
  );

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
    payload["_sd_alg"] = "sha-256";
    payload["_sd"] = [digest];
    disclosures.push(disclosure.encode());
  } else {
    payload["email"] = email;
  }

  const defaultEvtHeader = {
    alg: "EdDSA",
    kid: "issuer-key",
    typ: "evt+jwt",
  };

  const rebuildToken = async (rebuildOptions: RebuildTokenOptions = {}) => {
    const evt = await signCompact(
      rebuildOptions.evtPayload ?? payload,
      rebuildOptions.evtHeader ?? defaultEvtHeader,
      issuerKeys.privateKey,
    );
    const encodedDisclosures = disclosures.map((value) => `${value}~`).join("");
    const presentation = `${evt}~${encodedDisclosures}`;
    const sdHash = uint8ArrayToBase64Url(
      createHash("sha256")
        .update(rebuildOptions.sdHashPresentation ?? presentation)
        .digest(),
    );
    const kb = await signCompact(
      rebuildOptions.kbPayload ?? {
        aud: audience,
        nonce,
        iat: kbIssuedAt,
        sd_hash: sdHash,
      },
      rebuildOptions.kbHeader ?? { alg: "EdDSA", typ: "kb+jwt" },
      rebuildOptions.kbSigningKey ?? holderKeys.privateKey,
    );

    return {
      token: `${presentation}${kb}`,
      evt,
      kb,
      presentation,
    };
  };

  const compactToken = await rebuildToken();

  return {
    ...compactToken,
    email,
    issuer,
    audience,
    nonce,
    evtIssuedAt,
    kbIssuedAt,
    issuerPublicJwk,
    holderPublicJwk,
    evtPayload: payload,
    rebuildToken,
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
