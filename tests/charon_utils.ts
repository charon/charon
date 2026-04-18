import type { CDPSession, Page } from "@playwright/test"

import { checkpoint, test } from "./utils"

export const CHARON_URL = process.env.CHARON_URL || "https://localhost:8080"

export const expect = test.expect

// Takes a screenshot of the activity page. Meant to be run at the end of every successful test.
export async function takeActivityScreenshot(page: Page, name: string) {
  const homeButton = page.locator("#navbar-link-home")
  await expect(homeButton).toBeVisible()
  await homeButton.click()
  const activityLink = page.locator("#menu-list-activity")
  await expect(activityLink).toBeVisible()
  await activityLink.click()

  const activityHeader = page.locator("#activitylist-header-activity")
  await expect(activityHeader).toBeVisible()
  await checkpoint(page, name, { mask: [page.locator(".activitylistitem-text-timestamp"), page.locator(".activitylistitem-text-session")] })
}

// Meant for tests where the user needs to be authenticated.
export async function signInWithPassword(page: Page, username: string, password: string, expectSignup: boolean, expectingSuccessfulSignin: boolean) {
  // Wait to prevent net::ERR_ABORTED issues.
  await page.waitForTimeout(1000)
  await page.goto(CHARON_URL)

  // Find and click the "SIGN-IN OR SIGN-UP" button.
  const signInButton = page.locator("#navbar-button-signin")
  await expect(signInButton).toBeVisible()
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
    await expect(page.locator("#authautoredirect-text-congratulations")).toBeVisible()
    await checkpoint(page, `auth-page-after-selecting-username-${username}-identity`)

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(3500)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await expect(identitiesLink).toBeVisible()

    await checkpoint(page, "successful-signin-identities-visible-on-main-page")
  } else {
    // Wait for error message to appear.
    const errorMessage = page.locator("#authpassword-error-wrongpassword")
    await expect(errorMessage).toBeVisible()

    await checkpoint(page, "auth-page-wrong-password-error-message")
  }
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
  action: "shouldSucceed" | "shouldNotSucceed" | "doNotSendVerifiedPasskey" | "updatePasskey" | "deletePasskey",
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

  // Set up event listeners before triggering the operation to avoid race conditions.
  let eventPromise: Promise<void>
  switch (action) {
    case "shouldSucceed":
      eventPromise = new Promise<void>((resolve, reject) => {
        setTimeout(() => reject(new Error("no WebAuthn event received")), 3000)
        client.on("WebAuthn.credentialAdded", () => (credentialShouldAlreadyExist ? reject(new Error("unexpected credentialAdded event")) : resolve()))
        client.on("WebAuthn.credentialAsserted", () => (credentialShouldAlreadyExist ? resolve() : reject(new Error("unexpected credentialAsserted event"))))
        client.on("WebAuthn.credentialUpdated", () => reject(new Error("unexpected credentialUpdated event")))
        client.on("WebAuthn.credentialDeleted", () => reject(new Error("unexpected credentialDeleted event")))
      })
      break
    case "updatePasskey":
      eventPromise = new Promise<void>((resolve, reject) => {
        setTimeout(resolve, 3000)
        client.on("WebAuthn.credentialAdded", () => reject(new Error("unexpected credentialAdded event")))
        client.on("WebAuthn.credentialAsserted", () => reject(new Error("unexpected credentialAsserted event")))
        client.on("WebAuthn.credentialUpdated", () => resolve())
        client.on("WebAuthn.credentialDeleted", () => reject(new Error("unexpected credentialDeleted event")))
      })
      break
    case "deletePasskey":
      eventPromise = new Promise<void>((resolve, reject) => {
        setTimeout(resolve, 3000)
        client.on("WebAuthn.credentialAdded", () => reject(new Error("unexpected credentialAdded event")))
        client.on("WebAuthn.credentialAsserted", () => reject(new Error("unexpected credentialAsserted event")))
        client.on("WebAuthn.credentialUpdated", () => reject(new Error("unexpected credentialUpdated event")))
        client.on("WebAuthn.credentialDeleted", () => resolve())
      })
      break
    case "shouldNotSucceed":
    case "doNotSendVerifiedPasskey":
      eventPromise = new Promise<void>((resolve, reject) => {
        setTimeout(resolve, 3000)
        client.on("WebAuthn.credentialAdded", () => reject(new Error("unexpected credentialAdded event")))
        client.on("WebAuthn.credentialAsserted", () => reject(new Error("unexpected credentialAsserted event")))
        client.on("WebAuthn.credentialUpdated", () => reject(new Error("unexpected credentialUpdated event")))
        client.on("WebAuthn.credentialDeleted", () => reject(new Error("unexpected credentialDeleted event")))
      })
      break
  }

  try {
    // Perform user action that triggers passkey prompt.
    await operationTrigger()
    // Wait for the WebAuthn event.
    await eventPromise
  } finally {
    // Set automaticPresenceSimulation option back to false.
    await client.send("WebAuthn.setAutomaticPresenceSimulation", {
      authenticatorId,
      enabled: false,
    })
  }
}
