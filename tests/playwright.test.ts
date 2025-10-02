import type { Browser, BrowserContext, Page } from "@playwright/test"

import { existsSync } from "node:fs"
import { chromium, expect, test } from "@playwright/test"

const CHARON_URL = process.env.CHARON_URL || "https://localhost:8080"

test.describe.serial("Charon Sign-in Flows", () => {
  let browser: Browser
  let context: BrowserContext

  test.beforeAll(async () => {
    browser = await chromium.launch()
  })

  test.afterAll(async () => {
    await browser.close()
  })

  test.beforeEach(async () => {
    context = await browser.newContext()
  })

  test.afterEach(async () => {
    await context.close()
  })

  test("Successful password sign-in flow", async () => {
    const page = await context.newPage()

    await page.goto(CHARON_URL)
    await checkpoint(page, "main-page-before-signin")

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await signInButton.click()

    await checkpoint(page, "main-page-after-clicking-signin")

    // Wait for navigation to sign-in page.
    await page.waitForLoadState("networkidle")

    // Find the email input field and enter 'tester'.
    const emailField = page.locator("input#authstart-input-email")
    await emailField.waitFor({ state: "visible" })
    await emailField.fill("tester")

    // Find and click the NEXT button.
    const nextButton = page.locator("button#authstart-button-next")
    await nextButton.waitFor({ state: "visible" })
    await nextButton.click()

    await page.waitForLoadState("networkidle")

    // Find the password input field and enter 'tester123'.
    const passwordField = page.locator("input#authpassword-input-currentpassword")
    await passwordField.waitFor({ state: "visible" })
    await passwordField.fill("tester123")

    // Find and click the enabled NEXT button (not disabled).
    const nextButton2 = page.locator("button#authpassword-button-next")
    await nextButton2.waitFor({ state: "visible" })
    await nextButton2.click()

    await page.waitForLoadState("networkidle")

    // Find the li element that contains "tester" and click its SELECT button.
    const testerIdentity = page.locator('li:has-text("tester")')
    const selectButton = testerIdentity.locator("button.authidentity-selector-identity")
    await selectButton.waitFor({ state: "visible" })
    await selectButton.click()

    await page.waitForLoadState("networkidle")

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(5000)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await identitiesLink.waitFor({ state: "visible" })
    await expect(identitiesLink).toBeVisible()

    await checkpoint(page, "successful-signin-identities-page")

    console.log("Successfully completed sign-in flow: entered credentials, navigated through flow, selected tester identity, and verified Identities link is visible")
  })

  test("Wrong password sign-in flow", async () => {
    const page = await context.newPage()

    await page.goto(CHARON_URL)

    await checkpoint(page, "main-page-before-signin")

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await signInButton.click()

    await checkpoint(page, "main-page-after-clicking-signin")

    // Find the email input field and enter 'tester'.
    const emailField = page.locator("input#authstart-input-email")
    await emailField.waitFor({ state: "visible" })
    await emailField.fill("tester")

    // Find and click the NEXT button.
    const nextButton = page.locator("button#authstart-button-next")
    await nextButton.waitFor({ state: "visible" })
    await nextButton.click()

    await page.waitForLoadState("networkidle")

    // Find the password input field and enter 'tester1234' (wrong password).
    const passwordField = page.locator("input#authpassword-input-currentpassword")
    await passwordField.waitFor({ state: "visible" })
    await passwordField.fill("tester1234")

    // Find and click the enabled NEXT button (not disabled).
    const nextButton2 = page.locator("button#authpassword-button-next")
    await nextButton2.waitFor({ state: "visible" })
    await nextButton2.click()

    // Wait for error message to appear.
    const errorMessage = page.locator("#authpassword-error-wrongpassword")
    await errorMessage.waitFor({ state: "visible" })
    await expect(errorMessage).toBeVisible()

    await checkpoint(page, "wrong-password-error-message")

    console.log("Successfully tested wrong password flow: entered wrong password and verified error message appeared")
  })
})

async function checkpoint(page: Page, name: string) {
  await page.waitForLoadState("networkidle")

  // TODO: Remove when supported by Playwright.
  //       See: https://github.com/microsoft/playwright/issues/23502
  const screenshotPath = test.info().snapshotPath(`${name}.png`, { kind: "screenshot" })
  if (existsSync(screenshotPath)) {
    await expect(page).toHaveScreenshot(`${name}.png`, { fullPage: true })
  } else {
    await page.screenshot({ path: screenshotPath, fullPage: true })
  }
}
