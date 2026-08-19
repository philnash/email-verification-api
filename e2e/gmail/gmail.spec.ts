import { spawn, type ChildProcess } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";

import {
  chromium,
  expect,
  test,
  type Browser,
  type BrowserContext,
  type Page,
} from "@playwright/test";

import { chromeDebugArguments, chromeExecutable } from "./setup-chrome.js";
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
const debuggingPort = 9333;
const cdpEndpoint = `http://127.0.0.1:${String(debuggingPort)}`;

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

function waitForBrowserDisconnect(browser: Browser): Promise<never> {
  return new Promise((_, reject) => {
    browser.once("disconnected", () => {
      reject(
        new Error("Chrome closed before the verification form was submitted"),
      );
    });
  });
}

async function waitForCdp(
  chromeProcess: ChildProcess,
  endpoint: string,
): Promise<void> {
  const deadline = Date.now() + 15_000;
  let launchError: Error | undefined;
  chromeProcess.once("error", (error) => {
    launchError = error;
  });

  while (Date.now() < deadline) {
    if (launchError !== undefined) {
      throw launchError;
    }
    if (chromeProcess.exitCode !== null || chromeProcess.signalCode !== null) {
      throw new Error(
        `Chrome exited before its debugging endpoint was ready (code ${String(chromeProcess.exitCode)}, signal ${String(chromeProcess.signalCode)})`,
      );
    }

    try {
      const response = await fetch(`${endpoint}/json/version`);
      if (response.ok) {
        return;
      }
    } catch {
      // Chrome has not opened the debugging endpoint yet.
    }
    await delay(100);
  }

  throw new Error(`Chrome debugging endpoint did not open at ${endpoint}`);
}

test("verifies a real Gmail account with Chrome", async () => {
  const diagnostics: Diagnostics = {
    startedAt: new Date().toISOString(),
    consoleErrors: [],
    pageErrors: [],
    failedRequests: [],
  };
  let server: VerifierServer | undefined;
  let browser: Browser | undefined;
  let context: BrowserContext | undefined;
  let chromeProcess: ChildProcess | undefined;
  let page: Page | undefined;

  try {
    server = await startVerifierServer();
    const origin = server.origin;
    diagnostics.origin = origin;
    await mkdir(profileDirectory, { recursive: true });
    chromeProcess = spawn(
      chromeExecutable(process.platform, process.env),
      chromeDebugArguments(profileDirectory, origin, debuggingPort),
      { stdio: "ignore" },
    );
    await waitForCdp(chromeProcess, cdpEndpoint);
    browser = await chromium.connectOverCDP(cdpEndpoint);
    context = browser.contexts()[0];
    if (context === undefined) {
      throw new Error("Chrome did not expose its default browser context");
    }

    page =
      context.pages().find((candidate) => candidate.url().startsWith(origin)) ??
      context.pages()[0] ??
      (await context.newPage());
    observePage(page, diagnostics);
    diagnostics.chromeVersion = browser.version();
    if (!page.url().startsWith(origin)) {
      await page.goto(origin);
    }
    diagnostics.userAgent = await page.evaluate(() => navigator.userAgent);

    console.log(`\nGuided Gmail E2E opened at ${origin}.`);
    console.log(
      "Use the Chrome window to sign in to Gmail if needed, complete the form, and submit it.\n",
    );

    const submission = await Promise.race([
      server.submission,
      waitForBrowserDisconnect(browser),
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
    expect(submission.result.value.issuer).toBe("accounts.google.com");
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
    await browser?.close().catch(() => undefined);
    if (chromeProcess?.exitCode === null && chromeProcess.signalCode === null) {
      chromeProcess.kill("SIGTERM");
    }
    await server?.close();
  }
});
