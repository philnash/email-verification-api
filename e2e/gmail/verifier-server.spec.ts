import { expect, test } from "@playwright/test";

import { startVerifierServer } from "./verifier-server.js";

test("serves a nonce-bound form and captures invalid input", async () => {
  const server = await startVerifierServer(4174);

  try {
    const formResponse = await fetch(server.origin);
    const formHtml = await formResponse.text();
    const sessionCookie = formResponse.headers
      .get("set-cookie")
      ?.split(";", 1)[0];
    const nonce = /name="token" nonce="([^"]+)"/.exec(formHtml)?.[1];

    expect(formResponse.status).toBe(200);
    expect(sessionCookie).toBeTruthy();
    expect(nonce).toBeTruthy();
    expect(formHtml).toContain('autocomplete="email-verification-token"');

    const verifyResponse = await fetch(`${server.origin}/verify`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: sessionCookie ?? "",
      },
      body: new URLSearchParams({ email: "", token: "" }),
    });
    const resultHtml = await verifyResponse.text();
    const submission = await server.submission;

    expect(verifyResponse.status).toBe(200);
    expect(resultHtml).toContain('data-status="error"');
    expect(submission).toMatchObject({
      submittedEmail: "",
      result: {
        ok: false,
        error: {
          stage: "input",
          code: "INVALID_INPUT",
        },
      },
    });
  } finally {
    await server.close();
  }
});
