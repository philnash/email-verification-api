import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

export function chromeArguments(profileDirectory) {
  return [
    `--user-data-dir=${profileDirectory}`,
    "--enable-features=EmailVerificationProtocol",
    "https://mail.google.com/",
  ];
}

export function chromeDebugArguments(
  profileDirectory,
  startUrl,
  debuggingPort,
) {
  return [
    `--user-data-dir=${profileDirectory}`,
    "--enable-features=EmailVerificationProtocol",
    `--remote-debugging-port=${String(debuggingPort)}`,
    startUrl,
  ];
}

export function chromeExecutable(platform, environment) {
  if (environment.CHROME_PATH) {
    return environment.CHROME_PATH;
  }
  if (platform === "darwin") {
    return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  }
  throw new Error(
    "Set CHROME_PATH to the installed Google Chrome executable on this platform",
  );
}

async function run() {
  const profileDirectory = resolve(".e2e/chrome-profile");
  await mkdir(profileDirectory, { recursive: true });
  const executable = chromeExecutable(process.platform, process.env);

  process.stdout.write(
    "Opening ordinary Chrome with the dedicated Gmail E2E profile.\n" +
      "Sign in to Gmail, then close that Chrome window to continue.\n",
  );

  await new Promise((resolveProcess, rejectProcess) => {
    const chrome = spawn(executable, chromeArguments(profileDirectory), {
      stdio: "ignore",
    });
    chrome.once("error", rejectProcess);
    chrome.once("exit", (code, signal) => {
      if (code === 0) {
        resolveProcess();
      } else {
        rejectProcess(
          new Error(
            `Chrome setup exited with code ${String(code)} and signal ${String(signal)}`,
          ),
        );
      }
    });
  });

  process.stdout.write(
    "Gmail profile setup complete. Run npm run test:e2e:gmail next.\n",
  );
}

const isMain =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMain) {
  await run();
}
