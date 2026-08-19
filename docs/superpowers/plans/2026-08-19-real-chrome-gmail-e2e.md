# Real Chrome Gmail End-to-End Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in guided Playwright test that validates the built package with desktop Chrome's current Email Verification Protocol implementation and a real Gmail session.

**Architecture:** A minimal Node HTTP fixture serves a nonce-bound verifier form and calls `verifyEmailToken()` from `dist/index.js`. Playwright launches the installed Chrome channel with `EmailVerificationProtocol` enabled and an ignored persistent profile, waits for human interaction, captures the complete structured result plus safe browser diagnostics, and asserts the verified Gmail presentation.

**Tech Stack:** TypeScript 6, Node.js HTTP APIs, Playwright Test, installed desktop Google Chrome, existing `email-verification` package API

## Global Constraints

- Keep the Gmail E2E outside `npm test`, `npm run check`, and CI.
- Launch headed installed Chrome with `--enable-features=EmailVerificationProtocol`.
- Store Chrome state only beneath ignored `.e2e/chrome-profile`.
- Import `verifyEmailToken()` from a freshly built `dist/index.js`.
- Leave Google authentication, Chrome permission prompts, email entry, and form submission under human control.
- Record the complete verification result and safe browser diagnostics in ignored `.e2e/results/latest.json` before asserting.
- Do not log, render, trace, or persist the raw presentation token.
- Do not modify the sibling `email-verification-impl` repository.
- Preserve the existing uncommitted change in `src/verify-issuer-signature.ts` without staging it.

---

## File Structure

- Modify `package.json`: add Playwright, E2E typecheck, harness-smoke, and guided Gmail commands.
- Modify `package-lock.json`: lock the Playwright development dependency.
- Modify `.gitignore`: exclude all persistent profile and diagnostic data under `.e2e/`.
- Create `e2e/tsconfig.json`: typecheck E2E sources separately from ordinary tests.
- Create `e2e/gmail/playwright.config.ts`: isolate the guided suite to one worker, a long timeout, and ignored output.
- Create `e2e/gmail/verifier-server.spec.ts`: deterministic smoke coverage for the nonce-bound fixture and structured invalid-input result.
- Create `e2e/gmail/verifier-server.ts`: serve the form, bind the nonce to an in-memory session, call the built library, and expose the submission result to Playwright.
- Create `e2e/gmail/gmail.spec.ts`: launch persistent Chrome, guide the user, capture diagnostics, and assert the real Gmail result.

### Task 1: Add the isolated Playwright E2E runner

**Files:**
- Modify: `package.json`
- Modify: `package-lock.json`
- Modify: `.gitignore`
- Create: `e2e/tsconfig.json`
- Create: `e2e/gmail/playwright.config.ts`

**Interfaces:**
- Consumes: installed desktop Chrome and the repository's existing build output.
- Produces: `npm run typecheck:e2e:gmail`, `npm run test:e2e:gmail:harness`, and `npm run test:e2e:gmail` commands plus a single-worker Playwright configuration.

- [ ] **Step 1: Install Playwright Test without installing a bundled browser**

Run:

```bash
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install --save-dev @playwright/test
```

Expected: `package.json` and `package-lock.json` add `@playwright/test`; no Playwright browser download runs because the test uses installed Chrome.

- [ ] **Step 2: Add explicit E2E scripts**

Add these entries to `scripts` in `package.json`:

```json
"typecheck:e2e:gmail": "tsc -p e2e/tsconfig.json --noEmit",
"test:e2e:gmail:harness": "npm run build && npm run typecheck:e2e:gmail && playwright test verifier-server.spec.ts --config e2e/gmail/playwright.config.ts",
"test:e2e:gmail": "npm run build && npm run typecheck:e2e:gmail && playwright test gmail.spec.ts --config e2e/gmail/playwright.config.ts"
```

Do not add either E2E command to `test` or `check`.

- [ ] **Step 3: Ignore all generated browser state and diagnostics**

Append to `.gitignore`:

```gitignore
.e2e/
```

- [ ] **Step 4: Add the separate E2E TypeScript project**

Create `e2e/tsconfig.json`:

```json
{
  "extends": "../tsconfig.json",
  "compilerOptions": {
    "noEmit": true,
    "types": ["node", "@playwright/test"]
  },
  "include": ["gmail/**/*.ts"]
}
```

- [ ] **Step 5: Add the scoped Playwright configuration**

Create `e2e/gmail/playwright.config.ts`:

```ts
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  fullyParallel: false,
  workers: 1,
  timeout: 15 * 60 * 1000,
  reporter: "line",
  outputDir: "../../.e2e/playwright",
  use: {
    trace: "off",
    screenshot: "off",
    video: "off",
  },
});
```

- [ ] **Step 6: Verify configuration without running a browser test**

Run:

```bash
npm run typecheck:e2e:gmail
npx playwright test --config e2e/gmail/playwright.config.ts --list
```

Expected: type checking exits successfully and Playwright reports zero discovered tests without launching a browser.

- [ ] **Step 7: Commit runner setup**

```bash
git add package.json package-lock.json .gitignore e2e/tsconfig.json e2e/gmail/playwright.config.ts
git commit -m "test: configure guided Gmail E2E runner"
```

### Task 2: Build and smoke-test the verifier fixture

**Files:**
- Create: `e2e/gmail/verifier-server.spec.ts`
- Create: `e2e/gmail/verifier-server.ts`

**Interfaces:**
- Consumes: `verifyEmailToken()` and its result types from `dist/index.js`.
- Produces: `startVerifierServer(port?: number): Promise<VerifierServer>`, where `VerifierServer` exposes `origin`, `submission`, and `close()`.

- [ ] **Step 1: Write the failing fixture smoke test**

Create `e2e/gmail/verifier-server.spec.ts`:

```ts
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
    const nonce = formHtml.match(/name="token" nonce="([^"]+)"/)?.[1];

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
```

- [ ] **Step 2: Run the smoke test to verify RED**

Run:

```bash
npm run build
npx playwright test verifier-server.spec.ts --config e2e/gmail/playwright.config.ts
```

Expected: FAIL because `e2e/gmail/verifier-server.ts` does not exist.

- [ ] **Step 3: Implement the minimal nonce-bound verifier server**

Create `e2e/gmail/verifier-server.ts`:

```ts
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { verifyEmailToken } from "../../dist/index.js";

type VerificationResult = Awaited<ReturnType<typeof verifyEmailToken>>;

export type VerificationSubmission = {
  submittedEmail: string;
  completedAt: string;
  result: VerificationResult;
};

export type VerifierServer = {
  origin: string;
  submission: Promise<VerificationSubmission>;
  close: () => Promise<void>;
};

const host = "127.0.0.1";

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function safeJson(value: unknown): string {
  return JSON.stringify(value, undefined, 2).replaceAll("<", "\\u003c");
}

function renderForm(nonce: string): string {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Gmail Email Verification E2E</title></head>
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
  <head><meta charset="utf-8"><title>Email verification result</title></head>
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

function sendHtml(response: ServerResponse, statusCode: number, html: string): void {
  response.writeHead(statusCode, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(html);
}

export async function startVerifierServer(port = 4173): Promise<VerifierServer> {
  const origin = `http://${host}:${port}`;
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
        const nonce = sessionId === undefined ? "" : (sessions.get(sessionId) ?? "");
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
    server.listen(port, host, () => resolve());
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
```

- [ ] **Step 4: Run the fixture smoke test to verify GREEN**

Run:

```bash
npm run test:e2e:gmail:harness
```

Expected: one Playwright test passes without launching Chrome.

- [ ] **Step 5: Run static checks for the new fixture**

Run:

```bash
npm run typecheck:e2e:gmail
npm run lint
npm run format:check
```

Expected: all three commands exit successfully.

- [ ] **Step 6: Commit the verifier fixture**

```bash
git add e2e/gmail/verifier-server.ts e2e/gmail/verifier-server.spec.ts
git commit -m "test: add Gmail verifier E2E fixture"
```

### Task 3: Add the guided real Chrome Gmail test

**Files:**
- Create: `e2e/gmail/gmail.spec.ts`

**Interfaces:**
- Consumes: `startVerifierServer()`, installed Chrome, `.e2e/chrome-profile`, and a human-completed Gmail verification form.
- Produces: `.e2e/results/latest.json`, a failure screenshot when possible, and pass/fail assertions over the complete real `verifyEmailToken()` result.

- [ ] **Step 1: Implement the guided test and safe diagnostic capture**

Create `e2e/gmail/gmail.spec.ts`:

```ts
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import { chromium, expect, test, type Page } from "@playwright/test";

import { startVerifierServer, type VerificationSubmission } from "./verifier-server.js";

type RequestFailure = {
  method: string;
  url: string;
  errorText: string | undefined;
};

type Diagnostics = {
  startedAt: string;
  completedAt?: string;
  origin?: string;
  chromeVersion?: string;
  userAgent?: string;
  verification?: VerificationSubmission;
  consoleErrors: string[];
  pageErrors: string[];
  failedRequests: RequestFailure[];
  harnessError?: string;
};

const stateDirectory = resolve(".e2e");
const profileDirectory = resolve(stateDirectory, "chrome-profile");
const resultsDirectory = resolve(stateDirectory, "results");
const resultPath = resolve(resultsDirectory, "latest.json");
const screenshotPath = resolve(resultsDirectory, "failure.png");

function errorMessage(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

function observePage(page: Page, diagnostics: Diagnostics): void {
  page.on("console", (message) => {
    if (message.type() === "error") diagnostics.consoleErrors.push(message.text());
  });
  page.on("pageerror", (error) => diagnostics.pageErrors.push(error.message));
  page.on("requestfailed", (request) => {
    diagnostics.failedRequests.push({
      method: request.method(),
      url: request.url(),
      errorText: request.failure()?.errorText,
    });
  });
}

async function writeDiagnostics(diagnostics: Diagnostics): Promise<void> {
  await mkdir(resultsDirectory, { recursive: true });
  await writeFile(resultPath, `${JSON.stringify(diagnostics, undefined, 2)}\n`);
}

test("verifies a real Gmail account with Chrome", async () => {
  const diagnostics: Diagnostics = {
    startedAt: new Date().toISOString(),
    consoleErrors: [],
    pageErrors: [],
    failedRequests: [],
  };
  const server = await startVerifierServer();
  diagnostics.origin = server.origin;
  let page: Page | undefined;
  const context = await chromium.launchPersistentContext(profileDirectory, {
    channel: "chrome",
    headless: false,
    viewport: null,
    args: ["--enable-features=EmailVerificationProtocol"],
  });

  try {
    page = context.pages()[0] ?? (await context.newPage());
    observePage(page, diagnostics);
    diagnostics.chromeVersion = context.browser()?.version();
    await page.goto(server.origin);
    diagnostics.userAgent = await page.evaluate(() => navigator.userAgent);

    console.log(`\nGuided Gmail E2E opened at ${server.origin}.`);
    console.log("Use the Chrome window to sign in to Gmail if needed, complete the form, and submit it.\n");

    const submission = await server.submission;
    diagnostics.verification = submission;
    diagnostics.completedAt = new Date().toISOString();
    await expect(page.locator("#verification-result")).toHaveAttribute(
      "data-status",
      submission.result.ok ? "ok" : "error",
    );
    await writeDiagnostics(diagnostics);

    if (!submission.result.ok) {
      await page.screenshot({ path: screenshotPath, fullPage: true });
      throw new Error(
        `Email verification failed at ${submission.result.error.stage}/${submission.result.error.code}: ${submission.result.error.message}`,
      );
    }

    expect(submission.result.value.email.toLowerCase()).toBe(
      submission.submittedEmail.toLowerCase(),
    );
    expect(submission.result.value.issuer).toBe("https://accounts.google.com");
    expect(submission.result.value.audience).toBe(server.origin);
  } catch (error: unknown) {
    diagnostics.harnessError = errorMessage(error);
    diagnostics.completedAt = new Date().toISOString();
    if (page !== undefined && !page.isClosed()) {
      await page.screenshot({ path: screenshotPath, fullPage: true }).catch(() => undefined);
    }
    await writeDiagnostics(diagnostics);
    throw error;
  } finally {
    await context.close();
    await server.close();
  }
});
```

- [ ] **Step 2: Verify Playwright discovers the guided test without launching Chrome**

Run:

```bash
npm run build
npm run typecheck:e2e:gmail
npx playwright test gmail.spec.ts --config e2e/gmail/playwright.config.ts --list
```

Expected: Playwright lists exactly one guided Gmail test and exits without launching Chrome.

- [ ] **Step 3: Run static checks**

Run:

```bash
npm run typecheck:e2e:gmail
npm run lint
npm run format:check
```

Expected: all three commands exit successfully.

- [ ] **Step 4: Commit the guided test**

```bash
git add e2e/gmail/gmail.spec.ts
git commit -m "test: add guided real Chrome Gmail E2E"
```

### Task 4: Verify ordinary checks and run the real Gmail flow

**Files:**
- Modify only if verification uncovers a scoped E2E harness defect.

**Interfaces:**
- Consumes: the completed opt-in harness and a real signed-in Gmail session.
- Produces: fresh static, unit, harness-smoke, and real-browser evidence plus `.e2e/results/latest.json`.

- [ ] **Step 1: Verify the regular project commands remain independent and green**

Run:

```bash
npm test
npm run check
```

Expected: the existing unit suite and complete regular check pass without launching Chrome or running either Gmail E2E script.

- [ ] **Step 2: Verify the deterministic fixture smoke test**

Run:

```bash
npm run test:e2e:gmail:harness
```

Expected: one fixture smoke test passes without launching Chrome.

- [ ] **Step 3: Run the guided real Chrome Gmail E2E**

Run:

```bash
npm run test:e2e:gmail
```

Expected interaction:

1. Chrome opens with the dedicated `.e2e/chrome-profile` and `EmailVerificationProtocol` enabled.
2. If the profile is not authenticated, use the page's Gmail link to sign in manually.
3. Return to the fixture, enter the Gmail address, handle Chrome's prompt, wait for its completion indicator, and submit.

Expected result: the test passes after `verifyEmailToken()` returns success for the submitted Gmail address, `https://accounts.google.com`, and the loopback audience.

- [ ] **Step 4: Inspect the captured result before claiming completion**

Run:

```bash
node -e 'const result = require("./.e2e/results/latest.json"); console.log(JSON.stringify(result, null, 2))'
```

Expected: the artifact contains Chrome metadata, empty or explained browser-error arrays, and the complete successful structured verification result without a raw presentation token.

- [ ] **Step 5: Review final repository state**

Run:

```bash
git status --short
git log --oneline --decorate -5
git diff main...HEAD --stat
```

Expected: only the pre-existing unstaged `src/verify-issuer-signature.ts` change remains outside commits; the branch commits contain the design, plan, runner, fixture, and guided test.
