/// <reference types="node" />

import type { BrowserContext, Locator, Page } from "@playwright/test"
import type { Result } from "axe-core"

import AxeBuilder from "@axe-core/playwright"
import { test as baseTest } from "@playwright/test"
import { createHtmlReport } from "axe-html-reporter"
import serialize from "canonicalize"
import { createHash } from "node:crypto"
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs"

// Allowed console message patterns.
const CONSOLE_ALLOWLIST = [/^Failed to load resource: the server responded with a status of 400 \(\)$/]

export const CHARON_URL = process.env.CHARON_URL || "https://localhost:8080"
export const MAILPIT_URL = process.env.MAILPIT_URL || "http://localhost:8025"

export const test = baseTest.extend({
  context: async ({ browser }, use) => {
    const context: BrowserContext = await browser.newContext()

    await context.exposeFunction("collectIstanbulCoverage", (coverageJSON: string) => {
      if (!coverageJSON) {
        return
      }
      mkdirSync(".nyc_output", { recursive: true })
      const filename = `.nyc_output/${Math.random().toString(36).substring(2, 15)}.json`
      writeFileSync(filename, coverageJSON, { flag: "wx" })
      console.log(`Coverage snapshot written to ${filename}.`)
    })

    await context.addInitScript(() =>
      // Collect coverage before page unload.
      window.addEventListener("beforeunload", () =>
        (window as unknown as { collectIstanbulCoverage: (coverageJSON: string) => void }).collectIstanbulCoverage(
          JSON.stringify((globalThis as { __coverage__?: unknown }).__coverage__),
        ),
      ),
    )

    context.on("page", (page) => {
      // Hide carets in all input elements once the page loads.
      page.on("load", async () => {
        await page.addStyleTag({ content: "input,textarea,[contenteditable] { caret-color: transparent !important; }" })
      })

      page.on("console", async (msg) => {
        const text = msg.text()
        const args = await Promise.all(msg.args().map((arg) => arg.jsonValue()))
        const argsMsg = args.length ? "\nArgs\n" + args.join("\n") : ""
        expect(
          CONSOLE_ALLOWLIST.some((pattern) => pattern.test(text)),
          `Console message found at ${page.url()}: [${msg.type()}] ${text}${argsMsg}`,
        ).toBe(true)
      })
    })

    try {
      await use(context)
    } finally {
      // Don't close the browser when interrupting the test (during development).
      if (baseTest.info().status !== "interrupted") {
        await context.close()
      }
    }
  },
})

export const expect = test.expect

// Generate accessibility report after all tests complete.
test.afterAll(() => {
  createHtmlReport({
    results: {
      violations: readdirSync("a11y-report")
        .filter((f) => f.endsWith(".json"))
        .map((f) => JSON.parse(readFileSync(`a11y-report/${f}`, { encoding: "utf-8" })) as Result),
    },
    options: {
      projectKey: "Charon Accessibility Report",
      outputDir: "a11y-report",
      reportFileName: "a11y-report.html",
    },
  })
})

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

// Meant for tests where the user needs to be authenticated.
export async function signInWithPassword(page: Page, expectSignup: boolean) {
  await page.goto(CHARON_URL)

  // Find and click the "SIGN-IN OR SIGN-UP" button.
  const signInButton = page.locator("#navbar-button-signin")
  await expect(signInButton).toBeVisible()
  await checkpoint(page, "main-page-before-signin")
  await signInButton.click()

  // Find the email input field and enter 'tester'.
  const emailField = page.locator("input#authstart-input-email")
  await expect(emailField).toBeVisible()
  await checkpoint(page, "main-page-after-clicking-signin")
  await emailField.fill("tester")

  // Find and click the NEXT button.
  const nextButton = page.locator("button#authstart-button-next")
  await expect(nextButton).toBeVisible()
  await checkpoint(page, "auth-page-after-entering-username")
  await nextButton.click()

  // Find the password input field and enter 'tester123'.
  const passwordField = page.locator("input#authpassword-input-currentpassword")
  await expect(passwordField).toBeVisible()
  await checkpoint(page, "auth-page-after-entering-username-and-clicking-next")
  await passwordField.fill("tester123")

  // Find and click the enabled NEXT button (not disabled).
  const nextButton2 = page.locator("button#authpassword-button-next")
  await expect(nextButton2).toBeVisible()
  await checkpoint(page, "auth-page-after-entering-password")
  await nextButton2.click()

  // Find the li element that contains "tester" and click its SELECT button.
  const testerIdentity = page.locator('li:has-text("tester")')
  const selectButton = testerIdentity.locator("button.authidentity-selector-identity")
  await expect(selectButton).toBeVisible()
  // This screenshot differs based on whether you signed up or signed in.
  await checkpoint(page, `${expectSignup ? "signup" : "signin"}-successful-signin-previous-identities-page-from-password`)
  await selectButton.click()

  // Verify success message.
  await expect(page.getByText("Everything is ready to sign you in")).toBeVisible()
  await checkpoint(page, "auth-page-after-selecting-username-identity")

  // Waiting for the automatic 3 seconds redirect.
  await page.waitForTimeout(3500)

  // Check that the Identities link is visible.
  const identitiesLink = page.locator("#menu-list-identities")
  await expect(identitiesLink).toBeVisible()

  await checkpoint(page, "successful-signin-identities-page")
}

interface CheckpointOptions {
  mask?: Array<Locator>
  fullPage?: boolean
}

export async function checkpoint(page: Page, name: string, options: CheckpointOptions = { mask: [], fullPage: true }) {
  // Wait for the page to stabilize.
  await page.waitForLoadState("networkidle")

  // Check that images have loaded.
  // See: https://github.com/microsoft/playwright/issues/6046#issuecomment-3641164427
  await page.waitForFunction(() => {
    return Array.from(document.querySelectorAll("img")).every((img) => img.complete && img.naturalWidth > 0)
  })

  // TODO: Remove when supported by Playwright.
  //       See: https://github.com/microsoft/playwright/issues/23502
  const screenshotPath = test.info().snapshotPath(`${name}.png`, { kind: "screenshot" })
  const screenshotOptions = {
    fullPage: options?.fullPage,
    mask: options?.mask,
    ...(existsSync(screenshotPath) ? {} : { path: screenshotPath }),
  }

  if (!screenshotOptions.path) {
    await expect(page).toHaveScreenshot(`${name}.png`, screenshotOptions)
  } else {
    // Only attach new screenshots to the report.
    await page.screenshot(screenshotOptions)
    await test.info().attach(name, {
      contentType: "image/png",
      path: screenshotPath,
    })
  }

  // Check for duplicate IDs.
  const duplicates = await page.evaluate(() => {
    const ids = Array.from(document.querySelectorAll("[id]"), (el) => (el as HTMLElement).id)
    return Array.from(ids.reduce((acc, v) => acc.set(v, (acc.get(v) || 0) + 1), new Map<string, number>()).entries())
      .filter(([_id, v]) => v > 1)
      .map(([id, _v]) => id)
  })
  if (duplicates.length > 0) {
    throw new Error(`Duplicate IDs found in checkpoint "${name}" at ${page.url()}: ${duplicates.join(", ")}`)
  }

  // Check for accessibility violations.
  const accessibilityScanResults = await new AxeBuilder({ page }).analyze()
  for (const violation of accessibilityScanResults.violations) {
    const serializedViolation: string = serialize(violation) as string
    const violationHash = createHash("sha256").update(serializedViolation).digest("hex")
    mkdirSync("a11y-report", { recursive: true })
    writeFileSync(`a11y-report/${violationHash}.json`, serializedViolation, { flag: "w" })
  }
}
