import type { CDPSession } from "@playwright/test"

import { CHARON_URL, checkpoint, expect, test } from "../utils.ts"

// Add a simple WebAuthnCredential interface since playwright does not export the Protocol type.
interface WebAuthnCredential {
  credentialId: string
  isResidentCredential: boolean
  privateKey: string
  rpId?: string
  signCount: number
  userHandle?: string
}

let sharedCredential: WebAuthnCredential | null = null

async function getIdFromAddedVirtualAuthenticator(client: CDPSession): Promise<string> {
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

async function simulatePasskeyInput(
  operationTrigger: () => Promise<void>,
  action: "shouldSucceed" | "shouldNotSucceed" | "doNotSendVerifiedPasskey",
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
          client.on("WebAuthn.credentialAdded", () => (credentialShouldAlreadyExist ? reject(new Error("Unexpected credentialAdded event")) : resolve()))
          client.on("WebAuthn.credentialAsserted", () => (credentialShouldAlreadyExist ? resolve() : reject(new Error("Unexpected credentialAsserted event"))))
        })
        break
      case "shouldNotSucceed":
      case "doNotSendVerifiedPasskey":
        await new Promise<void>((resolve, reject) => {
          setTimeout(resolve, 500)
          client.on("WebAuthn.credentialAdded", reject)
          client.on("WebAuthn.credentialAsserted", reject)
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

test.describe.serial("Charon Sign-in Flows", () => {
  test("Successful sign-up flow via passkey", async ({ context }) => {
    const page = await context.newPage()

    await page.goto(CHARON_URL)

    await checkpoint(page, "main-page-before-signin")

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await signInButton.click()

    await checkpoint(page, "main-page-after-clicking-signin")

    // Find and click the PASSKEY button.
    const passkeyButton = page.locator("button#authstart-button-passkey")
    await expect(passkeyButton).toBeVisible()

    // Enable WebAuthn environment in this session.
    const client: CDPSession = await page.context().newCDPSession(page)

    // Create a new Authenticator ID.
    const authenticatorId = await getIdFromAddedVirtualAuthenticator(client)

    // Simulate passkey input with a promise that triggers a passkey prompt as the argument.
    await simulatePasskeyInput(() => passkeyButton.click(), "shouldNotSucceed", client, authenticatorId, false)

    // Find and click the PASSKEY SIGN-UP button.
    const passkeySignupButton = page.locator("button#authpasskeysignup-button-signup")
    await expect(passkeySignupButton).toBeVisible()
    await checkpoint(page, "auth-page-after-clicking-passkey-signin-no-existing-user")
    await simulatePasskeyInput(() => passkeySignupButton.click(), "shouldSucceed", client, authenticatorId, false)

    // Find and click the CREATE NEW IDENTITY button.
    const newIdentityButton = page.locator("button#authidentity-button-newidentity")
    await expect(newIdentityButton).toBeVisible()
    await checkpoint(page, "auth-page-after-clicking-passkey-signup")
    await newIdentityButton.click()

    // Find the username input field and enter 'tester'.
    const usernameField = page.locator("input#username")
    await expect(usernameField).toBeVisible()
    await checkpoint(page, "auth-page-after-passkey-signup-add-new-identity")
    await usernameField.fill("tester")

    // Click submit.
    const submitIdentityButton = page.locator("button#identitycreate-button-create")
    await expect(submitIdentityButton).toBeVisible()
    await checkpoint(page, "auth-page-after-passkey-signup-add-new-identity-tester")
    await submitIdentityButton.click()

    // Find the li element that contains "tester" and click its SELECT button.
    const testerIdentity = page.locator('li:has-text("tester")')
    const selectButton = testerIdentity.locator("button.authidentity-selector-identity")
    await expect(selectButton).toBeVisible()
    await checkpoint(page, "auth-page-after-selecting-new-passkey-identity")
    await selectButton.click()

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(3500)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await expect(identitiesLink).toBeVisible()
    await checkpoint(page, "successful-signin-identities-page")

    // Store credentials for next test.
    const credentials = await client.send("WebAuthn.getCredentials", {
      authenticatorId: authenticatorId,
    })
    sharedCredential = credentials.credentials[0]

    console.log("Successfully completed passkey sign-up flow: entered passkey, created tester identity, selected tester identity, signed in.")
  })

  test("Successful sign-in flow via passkey", async ({ context }) => {
    const page = await context.newPage()

    await page.goto(CHARON_URL)

    await checkpoint(page, "main-page-before-signin")

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await signInButton.click()

    await checkpoint(page, "main-page-after-clicking-signin")

    // Find and click the PASSKEY button.
    const passkeyButton = page.locator("button#authstart-button-passkey")
    await expect(passkeyButton).toBeVisible()

    // Enable WebAuthn environment in this session.
    const client: CDPSession = await page.context().newCDPSession(page)

    // Create new authenticator for this session.
    const authenticatorId = await getIdFromAddedVirtualAuthenticator(client)

    // Restore credentials from previous test.
    if (!sharedCredential) {
      throw Error("sharedCredential undefined for sign-in flow")
    }
    await client.send("WebAuthn.addCredential", {
      authenticatorId: authenticatorId,
      credential: sharedCredential,
    })

    // Simulate passkey input with a promise that triggers a passkey prompt as the argument.
    await simulatePasskeyInput(() => passkeyButton.click(), "shouldSucceed", client, authenticatorId, true)

    // Find the li element that contains "tester" and click its SELECT button.
    const testerIdentity = page.locator('li:has-text("tester")')
    const selectButton = testerIdentity.locator("button.authidentity-selector-identity")
    await expect(selectButton).toBeVisible()
    await checkpoint(page, "auth-page-after-selecting-existing-passkey-identity")
    await selectButton.click()

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(3500)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await expect(identitiesLink).toBeVisible()
    await checkpoint(page, "successful-signin-identities-page")

    console.log("Successfully completed passkey sign-in flow: entered passkey, selected tester identity, signed in.")
  })

  test("Successful sign-in flow via passkey after previously failed sign-in", async ({ context }) => {
    // First try to sign in, don't do anything, charon should redirect to sign-up, then go back, sign in successfully.
    const page = await context.newPage()

    await page.goto(CHARON_URL)

    await checkpoint(page, "main-page-before-signin")

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await signInButton.click()

    await checkpoint(page, "main-page-after-clicking-signin")

    // Find and click the PASSKEY button.
    const passkeyButton = page.locator("button#authstart-button-passkey")
    await expect(passkeyButton).toBeVisible()

    // Enable WebAuthn environment in this session.
    const client: CDPSession = await page.context().newCDPSession(page)

    // Create new authenticator for this session.
    const authenticatorId = await getIdFromAddedVirtualAuthenticator(client)

    // Restore credentials from previous test.
    if (!sharedCredential) {
      throw Error("sharedCredential undefined for sign-in flow")
    }
    await client.send("WebAuthn.addCredential", {
      authenticatorId: authenticatorId,
      credential: sharedCredential,
    })

    await simulatePasskeyInput(() => passkeyButton.click(), "doNotSendVerifiedPasskey", client, authenticatorId, true)

    // Find the RETRY SIGN-IN button.
    const retrySigninButton = page.locator("button#authpasskeysignup-button-retrysignin")
    await expect(retrySigninButton).toBeVisible()
    await checkpoint(page, "auth-page-after-clicking-passkey-signin-no-existing-user")

    await simulatePasskeyInput(() => retrySigninButton.click(), "shouldSucceed", client, authenticatorId, true)

    // Find the li element that contains "tester" and click its SELECT button.
    const testerIdentity = page.locator('li:has-text("tester")')
    const selectButton = testerIdentity.locator("button.authidentity-selector-identity")
    await expect(selectButton).toBeVisible()
    await checkpoint(page, "auth-page-after-failed-signin-and-selecting-existing-passkey-identity")
    await selectButton.click()

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(3500)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await expect(identitiesLink).toBeVisible()
    await checkpoint(page, "successful-signin-identities-page")

    console.log(
      "Successfully completed passkey sign-in flow after a failed attempt: failed to enter passkey, went back, entered passkey, selected tester identity, signed in.",
    )
  })

  test("Successful sign-up flow via passkey after previously failed sign-in and sign-up", async ({ context }) => {
    const page = await context.newPage()

    await page.goto(CHARON_URL)

    await checkpoint(page, "main-page-before-signin")

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await signInButton.click()

    await checkpoint(page, "main-page-after-clicking-signin")

    // Find and click the PASSKEY button.
    const passkeyButton = page.locator("button#authstart-button-passkey")
    await expect(passkeyButton).toBeVisible()

    // Enable WebAuthn environment in this session.
    const client: CDPSession = await page.context().newCDPSession(page)

    // Create a new Authenticator ID.
    const authenticatorId = await getIdFromAddedVirtualAuthenticator(client)

    // Simulate passkey input with a promise that triggers a passkey prompt as the argument.
    await simulatePasskeyInput(() => passkeyButton.click(), "shouldNotSucceed", client, authenticatorId, false)

    // Find and click the PASSKEY SIGN-UP button.
    const passkeySignupButton = page.locator("button#authpasskeysignup-button-signup")
    await expect(passkeySignupButton).toBeVisible()
    await checkpoint(page, "auth-page-after-clicking-passkey-signin-no-existing-user")
    await simulatePasskeyInput(() => passkeySignupButton.click(), "doNotSendVerifiedPasskey", client, authenticatorId, false)

    await expect(passkeySignupButton).toBeVisible()
    await checkpoint(page, "auth-page-after-clicking-passkey-signup-and-cancelling")
    await simulatePasskeyInput(() => passkeySignupButton.click(), "shouldSucceed", client, authenticatorId, false)

    // Find and click the CREATE NEW IDENTITY button.
    const newIdentityButton = page.locator("button#authidentity-button-newidentity")
    await expect(newIdentityButton).toBeVisible()
    await checkpoint(page, "auth-page-after-clicking-passkey-signup")
    await newIdentityButton.click()

    // Find the username input field and enter 'tester'.
    const usernameField = page.locator("input#username")
    await expect(usernameField).toBeVisible()
    await checkpoint(page, "auth-page-after-passkey-signup-add-new-identity")
    await usernameField.fill("tester")

    // Click submit.
    const submitIdentityButton = page.locator("button#identitycreate-button-create")
    await expect(submitIdentityButton).toBeVisible()
    await checkpoint(page, "auth-page-after-passkey-signup-add-new-identity-tester")
    await submitIdentityButton.click()

    // Find the li element that contains "tester" and click its SELECT button.
    const testerIdentity = page.locator('li:has-text("tester")')
    const selectButton = testerIdentity.locator("button.authidentity-selector-identity")
    await expect(selectButton).toBeVisible()
    await checkpoint(page, "auth-page-after-selecting-new-passkey-identity")
    await selectButton.click()

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(3500)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await expect(identitiesLink).toBeVisible()
    await checkpoint(page, "successful-signin-identities-page")

    console.log(
      "Successfully completed passkey sign-up flow after a failed attempt: signed-in but failed,",
      "signed-up but cancelled, signed-up and succeeded, selected tester identity, signed in.",
    )
  })
})
