import * as jwt from "jsonwebtoken";

const ALGORITHM = "HS256";

export function signVerificationToken(
  iss: string,
  sub: string,
  secret: string,
): string {
  const payload = {
    iss,
    sub,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 600, // Token expires in 10 minutes
  };
  return jwt.sign(payload, secret, { algorithm: ALGORITHM });
}

export function verifyToken(
  token: string,
  secret: string,
  url: string,
): jwt.JwtPayload | null {
  try {
    const decoded = jwt.verify(token, secret, {
      algorithms: [ALGORITHM],
      issuer: url,
    }) as jwt.JwtPayload | string;
    if (typeof decoded === "object" && decoded !== null) {
      return decoded as jwt.JwtPayload;
    }
    return null;
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      console.error("Token verification failed:", error.message);
    }
    return null;
  }
}
