import { Resend } from "resend";
import { resendApiKey, fromEmail, jwtSecret } from "./config";
import { signVerificationToken } from "./tokens";
import { confirmationEmailHtml, confirmationEmailText } from "./templates";

const resend = new Resend(resendApiKey);

export async function sendVerificationEmail(to: string, url: string) {
  const token = signVerificationToken(url, to, jwtSecret);
  const verificationUrl = new URL(`/verify?token=${token}`, url).toString();

  await resend.emails.send({
    from: fromEmail,
    to: to,
    subject: "Confirm your email address",
    html: confirmationEmailHtml({ confirmUrl: verificationUrl }),
    text: confirmationEmailText({ confirmUrl: verificationUrl }),
  });
}
