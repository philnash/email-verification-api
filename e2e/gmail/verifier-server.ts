import { randomUUID } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";

import { verifyEmailToken } from "../../dist/index.js";

type VerificationResult = Awaited<ReturnType<typeof verifyEmailToken>>;

export interface VerificationSubmission {
  submittedEmail: string;
  completedAt: string;
  result: VerificationResult;
}

export interface VerifierServer {
  origin: string;
  submission: Promise<VerificationSubmission>;
  close: () => Promise<void>;
}

const host = "127.0.0.1";

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function safeJson(value: unknown): string {
  return JSON.stringify(value, undefined, 2).replaceAll("<", "\u003c");
}

function renderForm(nonce: string): string {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><link rel="icon" href="data:,"><title>Gmail Email Verification E2E</title></head>
  <body>
    <main>
      <h1>Gmail Email Verification E2E</h1>
      <ol>
        <li>If needed, open Gmail in another tab and sign in using this dedicated Chrome profile.</li>
        <li>Return here and enter the Gmail address you want to verify.</li>
        <li>Handle Chrome's permission prompt and wait for its completion indicator.</li>
        <li>Submit the form. The test runner will inspect the library result.</li>
      </ol>
      <p><a href="https://mail.google.com/" target="_blank" rel="noreferrer">Open Gmail in another tab</a></p>
      <form action="/verify" method="post">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" autocomplete="email" required>
        <input type="hidden" name="token" nonce="${escapeHtml(nonce)}" autocomplete="email-verification-token">
        <button type="submit">Verify email</button>
      </form>
      <script id="verification-result" type="application/json" data-status="pending">null</script>
    </main>
  </body>
</html>`;
}

function renderResult(submission: VerificationSubmission): string {
  const status = submission.result.ok ? "ok" : "error";
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><link rel="icon" href="data:,"><title>Email verification result</title></head>
  <body>
    <main>
      <h1>Email verification ${status}</h1>
      <pre>${escapeHtml(safeJson(submission))}</pre>
      <script id="verification-result" type="application/json" data-status="${status}">${safeJson(submission)}</script>
    </main>
  </body>
</html>`;
}

function readSessionId(request: IncomingMessage): string | undefined {
  const cookies = request.headers.cookie?.split(";") ?? [];
  for (const cookie of cookies) {
    const [name, ...value] = cookie.trim().split("=");
    if (name === "evp-e2e-session") {
      return value.join("=");
    }
  }
  return undefined;
}

async function readBody(request: IncomingMessage): Promise<string> {
  let body = "";
  for await (const chunk of request) {
    body += String(chunk);
    if (body.length > 1024 * 1024) {
      throw new Error("Form submission exceeded one megabyte");
    }
  }
  return body;
}

function sendHtml(
  response: ServerResponse,
  statusCode: number,
  html: string,
): void {
  response.writeHead(statusCode, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(html);
}

export async function startVerifierServer(
  port = 4173,
): Promise<VerifierServer> {
  const origin = `http://${host}:${String(port)}`;
  const sessions = new Map<string, string>();
  let resolveSubmission!: (value: VerificationSubmission) => void;
  let rejectSubmission!: (reason: unknown) => void;
  const submission = new Promise<VerificationSubmission>((resolve, reject) => {
    resolveSubmission = resolve;
    rejectSubmission = reject;
  });

  const server = createServer((request, response) => {
    void (async () => {
      const url = new URL(request.url ?? "/", origin);

      if (request.method === "GET" && url.pathname === "/") {
        const sessionId = randomUUID();
        const nonce = randomUUID();
        sessions.set(sessionId, nonce);
        response.setHeader(
          "set-cookie",
          `evp-e2e-session=${sessionId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600`,
        );
        sendHtml(response, 200, renderForm(nonce));
        return;
      }

      if (request.method === "POST" && url.pathname === "/verify") {
        const form = new URLSearchParams(await readBody(request));
        const submittedEmail = form.get("email") ?? "";
        const token = form.get("token") ?? "";
        const sessionId = readSessionId(request);
        const nonce =
          sessionId === undefined ? "" : (sessions.get(sessionId) ?? "");
        if (sessionId !== undefined) {
          sessions.delete(sessionId);
        }

        const result = await verifyEmailToken({
          email: submittedEmail,
          token,
          nonce,
          audience: origin,
        });
        const completedSubmission = {
          submittedEmail,
          completedAt: new Date().toISOString(),
          result,
        } satisfies VerificationSubmission;
        resolveSubmission(completedSubmission);
        sendHtml(response, 200, renderResult(completedSubmission));
        return;
      }

      sendHtml(response, 404, "<h1>Not found</h1>");
    })().catch((error: unknown) => {
      rejectSubmission(error);
      sendHtml(response, 500, "<h1>Verifier fixture failed</h1>");
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      resolve();
    });
  });

  return {
    origin,
    submission,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error === undefined) resolve();
          else reject(error);
        });
      }),
  };
}
