/// <reference types="node" />

import type { BrowserContext, CDPSession, Locator, Page } from "@playwright/test"
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

// Extend BrowserContext to include console messages.
interface ExtendedBrowserContext extends BrowserContext {
  _consoleMessages: Array<Promise<string>>
}

export const test = baseTest.extend({
  context: async ({ browser }, use) => {
    const context = (await browser.newContext()) as ExtendedBrowserContext
    // Initialize console messages array for this specific context.
    context._consoleMessages = []

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
        await page.addStyleTag({ content: "input,textarea,[contenteditable] { caret-color: transparent !important; }" }).catch(() => {
          // Ignore errors if page navigates before style is added.
        })
      })

      page.on("console", (msg) => {
        const url = page.url()
        const type = msg.type()
        const text = msg.text()
        if (!CONSOLE_ALLOWLIST.some((pattern) => pattern.test(text))) {
          const messagePromise = (async function () {
            let argsMsg
            try {
              const args = await Promise.all(msg.args().map((arg) => arg.jsonValue()))
              argsMsg = args.length ? "\nArgs\n" + args.join("\n") : ""
            } catch (error) {
              argsMsg = `\nError resolving arguments: ${String(error)}`
            }
            return `at ${url}: [${type}] ${text}${argsMsg}`
          })()
          context._consoleMessages.push(messagePromise)
        }
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

// Clear the console errors array for this context.
export function clearConsoleErrors(page: Page): void {
  const context = page.context() as ExtendedBrowserContext
  context._consoleMessages.length = 0
}

// Fails the test if any console errors are present for this context.
export async function expectNoConsoleErrors(page: Page): Promise<void> {
  const context = page.context() as ExtendedBrowserContext
  const resolvedMessages = await Promise.all(context._consoleMessages)
  expect(resolvedMessages.length, `Console errors detected:\n${resolvedMessages.join("\n")}`).toBe(0)
}

// Meant for tests where the user needs to be authenticated.
export async function signInWithPassword(page: Page, username: string, password: string, expectSignup: boolean, expectingSuccessfulSignin: boolean) {
  // Wait to prevent net::ERR_ABORTED issues.
  await page.waitForTimeout(1000)
  await page.goto(CHARON_URL)

  // Find and click the "SIGN-IN OR SIGN-UP" button.
  const signInButton = page.locator("#navbar-button-signin")
  await expect(signInButton).toBeVisible()
  // Move mouse to the same location so the same element gets focused every time.
  await page.mouse.move(0, 0)
  await checkpoint(page, "main-page-before-signin")
  await signInButton.click()

  // Find the email input field and enter the username.
  const emailField = page.locator("input#authstart-input-email")
  await expect(emailField).toBeVisible()
  await checkpoint(page, "main-page-after-clicking-signin")
  await emailField.fill(username)

  // Find and click the NEXT button.
  const nextButton = page.locator("button#authstart-button-next")
  await expect(nextButton).toBeVisible()
  await checkpoint(page, `auth-page-after-entering-username-${username}`)
  await nextButton.click()

  // Find the password input field and enter it.
  const passwordField = page.locator("input#authpassword-input-currentpassword")
  await expect(passwordField).toBeVisible()
  await checkpoint(page, `auth-page-after-entering-username-${username}-and-clicking-next`)
  await passwordField.fill(password)

  // Find and click the enabled NEXT button (not disabled).
  const nextButton2 = page.locator("button#authpassword-button-next")
  await expect(nextButton2).toBeVisible()
  await checkpoint(page, `auth-page-after-entering-username-${username}-password-${password.length}-chars`)
  await nextButton2.click()

  if (expectingSuccessfulSignin) {
    // Find the li element that contains the username and click its SELECT button.
    const usernameIdentity = page.locator(`li:has-text("${username}")`)
    const selectButton = usernameIdentity.locator("button.authidentity-selector-identity")
    await expect(selectButton).toBeVisible()
    // This screenshot differs based on whether you signed up or signed in.
    await checkpoint(page, `${expectSignup ? "signup" : "signin"}-successful-signin-username-${username}-previous-identities-page-from-password`)
    await selectButton.click()

    // Verify success message.
    await expect(page.getByText("Everything is ready to sign you in")).toBeVisible()
    await checkpoint(page, `auth-page-after-selecting-username-${username}-identity`)

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(3500)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await expect(identitiesLink).toBeVisible()

    await checkpoint(page, "successful-signin-identities-page")
  } else {
    // Wait for error message to appear.
    const errorMessage = page.locator("#authpassword-error-wrongpassword")
    await expect(errorMessage).toBeVisible()

    await checkpoint(page, "auth-page-wrong-password-error-message")
  }
}

interface CheckpointOptions {
  mask?: Array<Locator>
  fullPage?: boolean
  clip?: { x: number; y: number; width: number; height: number }
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
    fullPage: options?.fullPage ?? true,
    mask: options?.mask,
    clip: options?.clip,
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

  // Check for any console logs.
  await expectNoConsoleErrors(page)
}

// Add a simple WebAuthnCredential interface since playwright does not export the Protocol type.
export interface WebAuthnCredential {
  credentialId: string
  isResidentCredential: boolean
  privateKey: string
  rpId?: string
  signCount: number
  userHandle?: string
}

export async function getIdFromAddedVirtualAuthenticator(client: CDPSession): Promise<string> {
  await client.send("WebAuthn.enable")
  const addVirtualAuthenticatorResult = await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: false,
    },
  })
  return addVirtualAuthenticatorResult.authenticatorId
}

export async function simulatePasskeyInput(
  operationTrigger: () => Promise<void>,
  action: "shouldSucceed" | "shouldNotSucceed" | "doNotSendVerifiedPasskey" | "updatePasskey",
  client: CDPSession,
  authenticatorId: string,
  credentialShouldAlreadyExist: boolean,
) {
  // Set isUserVerified option (true unless action is "doNotSendVerifiedPasskey").
  await client.send("WebAuthn.setUserVerified", {
    authenticatorId: authenticatorId,
    isUserVerified: action !== "doNotSendVerifiedPasskey",
  })

  // set automaticPresenceSimulation option to true
  // (so that the virtual authenticator will respond to the next passkey prompt).
  await client.send("WebAuthn.setAutomaticPresenceSimulation", {
    authenticatorId: authenticatorId,
    enabled: true,
  })

  try {
    // perform a user action that triggers passkey prompt
    await operationTrigger()

    // Wait to receive the event that the passkey was successfully registered or verified.
    // WebAuthn events are only triggered during successful operations.
    switch (action) {
      case "shouldSucceed":
        await new Promise<void>((resolve, reject) => {
          setTimeout(reject, 3000)
          client.on("WebAuthn.credentialAdded", () => (credentialShouldAlreadyExist ? reject(new Error("unexpected credentialAdded event")) : resolve()))
          client.on("WebAuthn.credentialAsserted", () => (credentialShouldAlreadyExist ? resolve() : reject(new Error("unexpected credentialAsserted event"))))
          client.on("WebAuthn.credentialUpdated", () => reject(new Error("unexpected credentialUpdated event")))
          client.on("WebAuthn.credentialDeleted", () => reject(new Error("unexpected credentialDeleted event")))
        })
        break
      case "updatePasskey":
        await new Promise<void>((resolve, reject) => {
          setTimeout(resolve, 3000)
          client.on("WebAuthn.credentialAdded", () => reject(new Error("unexpected credentialAdded event")))
          client.on("WebAuthn.credentialAsserted", () => reject(new Error("unexpected credentialAsserted event")))
          client.on("WebAuthn.credentialUpdated", () => resolve())
          client.on("WebAuthn.credentialDeleted", () => reject(new Error("unexpected credentialDeleted event")))
        })
        break
      case "shouldNotSucceed":
      case "doNotSendVerifiedPasskey":
        await new Promise<void>((resolve, reject) => {
          setTimeout(resolve, 500)
          client.on("WebAuthn.credentialAdded", reject)
          client.on("WebAuthn.credentialAsserted", reject)
          client.on("WebAuthn.credentialUpdated", () => reject(new Error("unexpected credentialUpdated event")))
          client.on("WebAuthn.credentialDeleted", () => reject(new Error("unexpected credentialDeleted event")))
        })
        break
    }
  } finally {
    // Set automaticPresenceSimulation option back to false.
    await client.send("WebAuthn.setAutomaticPresenceSimulation", {
      authenticatorId,
      enabled: false,
    })
  }
}

export async function takeScreenshotsOfEntries(
  page: Page,
  entrySelector: string,
  displayNameSelector: string,
  screenshotPrefix: string,
  options: CheckpointOptions = {},
): Promise<void> {
  // Get all entry elements.
  const entries = page.locator(entrySelector)
  const count = await entries.count()

  for (let i = 0; i < count; i++) {
    const entry = entries.nth(i)
    const box = await entry.boundingBox()
    if (!box) {
      continue
    }

    const displayNameElement = entry.locator(displayNameSelector)
    const displayName = (await displayNameElement.textContent())?.replace(/\s/g, "")

    await checkpoint(page, `${screenshotPrefix}-${displayName}`, { ...options, fullPage: true, clip: { x: box.x, y: box.y, width: box.width, height: box.height } })
  }
}
