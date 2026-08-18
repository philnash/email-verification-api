import { createHash } from "node:crypto";
import { Disclosure, uint8ArrayToBase64Url } from "@sd-jwt/core";
import {
  CompactSign,
  exportJWK,
  generateKeyPair,
  type CompactJWSHeaderParameters,
} from "jose";

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
    payload["_sd_alg"] = "sha-256";
    payload["_sd"] = [digest];
    disclosures.push(disclosure.encode());
  } else {
    payload["email"] = email;
  }

  const evt = await signCompact(
    payload,
    { alg: "EdDSA", kid: "issuer-key", typ: "evt+jwt" },
    issuerKeys.privateKey,
  );
  const encodedDisclosures = disclosures.map((value) => `${value}~`).join("");
  const presentation = `${evt}~${encodedDisclosures}`;
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
