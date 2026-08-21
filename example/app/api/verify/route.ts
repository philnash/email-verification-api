import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { decryptSession, SESSION_COOKIE_NAME } from "@/app/lib/session";
import { verifyEmailToken } from "email-verification-api";

export async function POST(request: Request) {
  const formData = await request.formData();
  const email = formData.get("email");
  const token = formData.get("token");

  if (typeof email !== "string" || !email) {
    return NextResponse.json(
      { verified: false, reason: "Missing email address." },
      { status: 400 },
    );
  }

  if (typeof token !== "string" || !token) {
    return NextResponse.json({
      verified: false,
      reason:
        "No verification token was provided by the browser. You should fallback to verifying the email with an OTP code or magic link.",
    });
  }

  const cookieStore = await cookies();
  const session = await decryptSession(
    cookieStore.get(SESSION_COOKIE_NAME)?.value,
  );
  const nonce = session?.nonce;

  if (!session || !nonce) {
    return NextResponse.json({
      verified: false,
      reason: "Your session has expired. Please reload the page and try again.",
    });
  }

  const requestUrl = new URL(request.url);
  const audience = `${requestUrl.protocol}//${requestUrl.host}`;
  const result = await verifyEmailToken({ email, token, audience, nonce });
  if (!result.ok) {
    return NextResponse.json({
      verified: false,
      reason: result.error.message,
    });
  } else {
    return NextResponse.json({
      verified: true,
    });
  }
}
