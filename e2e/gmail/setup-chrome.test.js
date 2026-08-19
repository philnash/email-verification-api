import assert from "node:assert/strict";
import test from "node:test";

import { chromeArguments, chromeExecutable } from "./setup-chrome.js";

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
