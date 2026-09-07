import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import {
  encryptSession,
  SESSION_COOKIE_NAME,
  SESSION_DURATION_SECONDS,
} from "@/app/lib/session";

// Runs on every load of the home page: mints a fresh nonce and stores it in
// a signed session cookie. Setting the cookie on the *request* (not just the
// response) means the page's Server Component can read the new value back
// via `cookies()` during the very same render.
export async function proxy(request: NextRequest) {
  const nonce = randomUUID();
  const session = await encryptSession({ nonce });

  request.cookies.set(SESSION_COOKIE_NAME, session);
  const response = NextResponse.next({ request });

  response.cookies.set(SESSION_COOKIE_NAME, session, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_DURATION_SECONDS,
  });

  return response;
}

export const config = {
  matcher: "/",
};
