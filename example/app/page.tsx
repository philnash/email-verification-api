import { cookies } from "next/headers";
import { decryptSession, SESSION_COOKIE_NAME } from "@/app/lib/session";
import { VerifyForm } from "@/app/verify-form";

export default async function Home() {
  const cookieStore = await cookies();
  const session = await decryptSession(
    cookieStore.get(SESSION_COOKIE_NAME)?.value,
  );

  // `proxy.ts` sets a fresh session cookie on every request to this page, so
  // in normal operation `session` is always present. Fall back to an empty
  // nonce only if something upstream prevented that (e.g. proxy disabled).
  const nonce = session?.nonce ?? "";

  return (
    <div className="page">
      <main>
        <h1>Email Verification API</h1>

        <p>
          This is an example of the{" "}
          <a href="https://developer.chrome.com/blog/email-verification-protocol-origin-trial">
            Email Verification API
          </a>{" "}
          built with Next.js.
        </p>

        <VerifyForm nonce={nonce} />

        <h2>How does it work?</h2>
        <p>
          When you enter an email address from a supported mailbox provider, the
          browser interfaces with the mailbox to work out if you are logged in
          and therefore own the email address. A token is then set on a hidden{" "}
          <code>&lt;input&gt;</code> element. On submission, the server can
          verify the token and validates the user owns the email address.
        </p>

        <p>
          In this project, the verification is handled by the{" "}
          <a href="https://github.com/philnash/email-verification-api">
            email-verification-api package
          </a>
          .
        </p>

        <h2>Browser support</h2>
        <p>
          The Email Verification API is currently supported in Chrome as an
          origin trial.
        </p>
        <h2>Email provider support</h2>
        <p>
          Gmail currently implements support for the protocol. You can also sign
          in to{" "}
          <a href="https://rowan.fyi/made/email-provider/">
            this demo provider
          </a>{" "}
          and the demo email will verify correctly.
        </p>
      </main>
      <footer>
        Demo created by <a href="https://philna.sh/">Phil Nash</a> and{" "}
        <a href="https://resend.com">Resend</a>
      </footer>
    </div>
  );
}
