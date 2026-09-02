import { redirect, RedirectType } from "next/navigation";
import { verifyToken } from "../lib/tokens";
import { jwtSecret } from "../lib/config";
import { headers } from "next/headers";

export default async function Verfiy({
  searchParams,
  params,
}: {
  searchParams: { token?: string };
  params: { [key: string]: string | string[] | undefined };
}) {
  const { token } = await searchParams;
  const headersList = await headers();
  const url = `${headersList.get("x-forwarded-proto")}://${headersList.get("host")}`;

  if (!token) {
    redirect("/", RedirectType.replace);
  }

  try {
    const result = await verifyToken(token, jwtSecret, url);
    if (result) {
      return (
        <>
          <p>Verified your email as {result.sub}</p>
          <p>
            Don't you wish it was{" "}
            <a href="https://resend.com/blog/email-verification-api">
              easier though
            </a>
            ?
          </p>
        </>
      );
    }
  } catch (error) {
    console.error("Error verifying token:", error);
  }
  return (
    <p>
      Invalid or expired token. <a href="/">Please try verifying again</a>.
    </p>
  );
}
