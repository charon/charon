/// <reference types="node" />

import type { BrowserContext, Page } from "@playwright/test"

import AxeBuilder from "@axe-core/playwright"
import { test as baseTest } from "@playwright/test"
import { createHtmlReport } from "axe-html-reporter"
import serialize from "canonicalize"
import { createHash } from "node:crypto"
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs"

// Allowed console message patterns.
const CONSOLE_ALLOWLIST = [/^Failed to load resource: the server responded with a status of 400 \(\)$/]

export const CHARON_URL = process.env.CHARON_URL || "https://localhost:8080"

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
test.afterAll(async () => {
  createHtmlReport({
    results: {
      violations: readdirSync("a11y-report")
        .filter((f) => f.endsWith(".json"))
        .map((f) => JSON.parse(readFileSync(`a11y-report/${f}`, { encoding: "utf-8" }))),
    },
    options: {
      projectKey: "Charon Accessibility Report",
      outputDir: "a11y-report",
      reportFileName: "a11y-report.html",
    },
  })
})

export async function checkpoint(page: Page, name: string) {
  await page.waitForLoadState("networkidle")

  // TODO: Remove when supported by Playwright.
  //       See: https://github.com/microsoft/playwright/issues/23502
  const screenshotPath = test.info().snapshotPath(`${name}.png`, { kind: "screenshot" })
  if (existsSync(screenshotPath)) {
    await expect(page).toHaveScreenshot(`${name}.png`, { fullPage: true })
  } else {
    await page.screenshot({ path: screenshotPath, fullPage: true })
  }

  // Check for duplicate IDs.
  const duplicates = await page.evaluate(() => {
    const ids = Array.from(document.querySelectorAll("[id]"), (el) => (el as HTMLElement).id)
    return Array.from(ids.reduce((acc, v) => acc.set(v, (acc.get(v) || 0) + 1), new Map()).entries())
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
