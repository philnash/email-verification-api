type ConfirmationEmailProps = {
  /** The link the recipient should click to confirm their email address. */
  confirmUrl: string;
};

export function confirmationEmailHtml({
  confirmUrl,
}: ConfirmationEmailProps): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Confirm your email address</title>
  </head>
  <body style="margin:0; padding:0; background-color:#f4f4f5; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f5; padding:32px 16px;">
      <tr>
        <td align="center">
          <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px; width:100%; background-color:#ffffff; border-radius:8px; overflow:hidden;">
            <tr>
              <td style="padding:32px 32px 16px 32px;">
                <h1 style="margin:0; font-size:20px; line-height:28px; color:#18181b;">
                  Confirm your email address
                </h1>
              </td>
            </tr>
            <tr>
              <td style="padding:0 32px 24px 32px;">
                <p style="margin:0 0 16px 0; font-size:15px; line-height:24px; color:#3f3f46;">
                  Thanks for signing up. Click the button below to confirm this
                  is your email address.
                </p>
                <table role="presentation" cellpadding="0" cellspacing="0">
                  <tr>
                    <td style="border-radius:6px; background-color:#18181b;">
                      <a
                        href="${confirmUrl}"
                        style="display:inline-block; padding:12px 24px; font-size:15px; font-weight:600; color:#ffffff; text-decoration:none;"
                      >
                        Confirm email address
                      </a>
                    </td>
                  </tr>
                </table>
                <p style="margin:24px 0 0 0; font-size:13px; line-height:20px; color:#71717a;">
                  If the button doesn't work, copy and paste this link into
                  your browser:
                  <br />
                  <a href="${confirmUrl}" style="color:#3f3f46; word-break:break-all;">${confirmUrl}</a>
                </p>
              </td>
            </tr>
            <tr>
              <td style="padding:16px 32px 32px 32px; border-top:1px solid #e4e4e7;">
                <p style="margin:16px 0 0 0; font-size:12px; line-height:18px; color:#a1a1aa;">
                  If you didn't request this email, you can safely ignore it.
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;
}

export function confirmationEmailText({
  confirmUrl,
}: ConfirmationEmailProps): string {
  return `Confirm your email address

Thanks for signing up. Visit the link below to confirm this is your email address.

${confirmUrl}

If you didn't request this email, you can safely ignore it.`;
}
