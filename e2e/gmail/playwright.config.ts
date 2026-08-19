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
