import { defineConfig, devices } from "@playwright/test"

export default defineConfig({
  testDir: "./tests",
  testMatch: "*.test.ts",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 1,
  timeout: 120000, // 2 minutes per test.
  reporter: [
    ["html", { outputFolder: "playwright-report", open: "never" }],
    ["junit", { outputFile: "test-results/junit.xml" }],
  ],
  use: {
    baseURL: process.env.CHARON_URL || "https://localhost:8080",
    ignoreHTTPSErrors: false,
    trace: "on-first-retry",
    viewport: { width: 1280, height: 720 },
    headless: true,
    // Assertions are generally used when the element should be present. This timeout only accounts for asynchronicity.
    actionTimeout: 10000,
    ...devices["Desktop Chrome"],
    contextOptions: {
      reducedMotion: "reduce", // Avoids animation-related test flakiness.
    },
    launchOptions: {
      args: ["--font-render-hinting=none", "--disable-skia-runtime-opts", "--disable-font-subpixel-positioning", "--disable-lcd-text"],
    },
  },
  snapshotPathTemplate: "playwright-screenshots/{testFilePath}/{arg}{ext}",
  expect: {
    timeout: 10000,
    toMatchSnapshot: {
      threshold: 0,
    },
  },
  projects: [
    {
      name: "login",
      testMatch: /\/login\/.*\.test\.ts$/, // Match auth test file.
    },
    {
      name: "does-not-require-login",
      testMatch: /does-not-require-login\/.*\.test\.ts$/, // Match files without a dependency on login.
    },
    {
      name: "requires-login",
      testMatch: /requires-login\/.*\.test\.ts$/,
      dependencies: ["login"], // This depends on login.
    },
    {
      name: "adds-application-template", // This creates a globally visible application template, should be isolated.
      testMatch: /adds-application-template\/.*\.test\.ts$/,
      dependencies: ["requires-login"],
    },
  ],
})
