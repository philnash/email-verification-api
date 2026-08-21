import { SignJWT, jwtVerify } from "jose";

// Note: no `server-only` guard here — this module is imported from
// `proxy.ts`, which runs outside the normal server/client component graph
// that `server-only` polices. Every caller (proxy, the route handler, and
// the page Server Component) is already server-side.

const SESSION_COOKIE_NAME = "session";
const SESSION_DURATION_SECONDS = 10 * 60; // 10 minutes: long enough to fill in a form, short enough to keep the nonce fresh

function getSecretKey() {
  const secret = process.env.SESSION_SECRET;
  if (!secret) {
    throw new Error("SESSION_SECRET environment variable is not set");
  }
  return new TextEncoder().encode(secret);
}

export type SessionPayload = {
  nonce: string;
};

/**
 * Encrypts a session payload (currently just the verification nonce) into a
 * signed JWT suitable for storing in a cookie.
 */
export async function encryptSession(payload: SessionPayload) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(`${SESSION_DURATION_SECONDS}s`)
    .sign(getSecretKey());
}

/**
 * Verifies and decodes a session cookie value. Returns null if the cookie is
 * missing, expired, or has been tampered with.
 */
export async function decryptSession(
  sessionCookieValue: string | undefined
): Promise<SessionPayload | null> {
  if (!sessionCookieValue) {
    return null;
  }

  try {
    const { payload } = await jwtVerify(sessionCookieValue, getSecretKey(), {
      algorithms: ["HS256"],
    });
    if (typeof payload.nonce !== "string") {
      return null;
    }
    return { nonce: payload.nonce };
  } catch {
    return null;
  }
}

export { SESSION_COOKIE_NAME, SESSION_DURATION_SECONDS };
