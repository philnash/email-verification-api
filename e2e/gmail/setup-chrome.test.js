import assert from "node:assert/strict";
import test from "node:test";

import {
  chromeArguments,
  chromeDebugArguments,
  chromeExecutable,
} from "./setup-chrome.js";

test("launches ordinary Chrome with only the dedicated profile and protocol flag", () => {
  assert.deepEqual(chromeArguments("/project/.e2e/chrome-profile"), [
    "--user-data-dir=/project/.e2e/chrome-profile",
    "--enable-features=EmailVerificationProtocol",
    "https://mail.google.com/",
  ]);
  assert.equal(
    chromeExecutable("darwin", {}),
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  );
  assert.equal(
    chromeExecutable("darwin", { CHROME_PATH: "/custom/chrome" }),
    "/custom/chrome",
  );
});

test("launches debuggable ordinary Chrome without Playwright automation flags", () => {
  const args = chromeDebugArguments(
    "/project/.e2e/chrome-profile",
    "http://127.0.0.1:4173",
    9333,
  );

  assert.deepEqual(args, [
    "--user-data-dir=/project/.e2e/chrome-profile",
    "--enable-features=EmailVerificationProtocol",
    "--remote-debugging-port=9333",
    "http://127.0.0.1:4173",
  ]);
  assert.equal(
    args.some((arg) => arg.includes("automation")),
    false,
  );
  assert.equal(
    args.some((arg) => arg.includes("sandbox")),
    false,
  );
  assert.equal(
    args.some((arg) => arg.includes("mock-keychain")),
    false,
  );
});
