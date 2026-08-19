import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  chromium,
  expect,
  test,
  type BrowserContext,
  type Page,
} from "@playwright/test";

import {
  startVerifierServer,
  type VerificationSubmission,
  type VerifierServer,
} from "./verifier-server.js";

interface RequestFailure {
  method: string;
  url: string;
  errorText: string | undefined;
}

interface Diagnostics {
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
}

const stateDirectory = resolve(".e2e");
const profileDirectory = resolve(stateDirectory, "chrome-profile");
const resultsDirectory = resolve(stateDirectory, "results");
const resultPath = resolve(resultsDirectory, "latest.json");
const screenshotPath = resolve(resultsDirectory, "failure.png");

function errorMessage(error: unknown): string {
  return error instanceof Error
    ? `${error.name}: ${error.message}`
    : String(error);
}

function observePage(page: Page, diagnostics: Diagnostics): void {
  page.on("console", (message) => {
    if (message.type() === "error") {
      diagnostics.consoleErrors.push(message.text());
    }
  });
  page.on("pageerror", (error) => {
    diagnostics.pageErrors.push(error.message);
  });
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

function waitForContextClose(context: BrowserContext): Promise<never> {
  return new Promise((_, reject) => {
    context.once("close", () => {
      reject(
        new Error("Chrome closed before the verification form was submitted"),
      );
    });
  });
}

test("verifies a real Gmail account with Chrome", async () => {
  const diagnostics: Diagnostics = {
    startedAt: new Date().toISOString(),
    consoleErrors: [],
    pageErrors: [],
    failedRequests: [],
  };
  let server: VerifierServer | undefined;
  let context: BrowserContext | undefined;
  let page: Page | undefined;

  try {
    server = await startVerifierServer();
    diagnostics.origin = server.origin;
    context = await chromium.launchPersistentContext(profileDirectory, {
      channel: "chrome",
      headless: false,
      viewport: null,
      args: ["--enable-features=EmailVerificationProtocol"],
    });

    page = context.pages()[0] ?? (await context.newPage());
    observePage(page, diagnostics);
    const browserVersion = context.browser()?.version();
    if (browserVersion !== undefined) {
      diagnostics.chromeVersion = browserVersion;
    }
    await page.goto(server.origin);
    diagnostics.userAgent = await page.evaluate(() => navigator.userAgent);

    console.log(`\nGuided Gmail E2E opened at ${server.origin}.`);
    console.log(
      "Use the Chrome window to sign in to Gmail if needed, complete the form, and submit it.\n",
    );

    const submission = await Promise.race([
      server.submission,
      waitForContextClose(context),
    ]);
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
      await page
        .screenshot({ path: screenshotPath, fullPage: true })
        .catch(() => undefined);
    }
    await writeDiagnostics(diagnostics);
    throw error;
  } finally {
    await context?.close();
    await server?.close();
  }
});
