import { checkpoint, expect, test } from "../utils"

test.describe.serial("Charon Sign-in Flows", () => {
  test("Successful SIPASS sign-in flow", async ({ context }) => {
    const SIPASS_USERNAME = "barbarafelicijan"
    const page = await context.newPage()
    await page.goto("https://sipasstest.peer.id/")

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await checkpoint(page, "main-page-before-signin")
    await signInButton.click()

    // Sign in with SIPASS.
    const sipassButton = page.locator("button#authstart-button-sipass")
    await expect(sipassButton).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await sipassButton.click()

    // Take a screenshot while waiting for sipass redirect.
    await page.waitForTimeout(600)
    await checkpoint(page, "main-page-after-clicking-sipass")
    await page.waitForTimeout(2000)

    // Use "Digitalno potrdilo" for sign in.
    const digitalnoPotrdiloButton = page.locator("form a.box-link", { hasText: "Digitalno potrdilo" })
    await expect(digitalnoPotrdiloButton).toBeVisible()
    // Checkpoint on the SIPASS page fails due to duplicate IDs found in checkpoint: sessionId, identificationMechanism.
    await digitalnoPotrdiloButton.click()

    // Should be redirected back to Charon.

    // Find the li element that contains the username and click its SELECT button.
    const usernameIdentity = page.locator(`li:has-text("${SIPASS_USERNAME}")`)
    const selectButton = usernameIdentity.locator("button.authidentity-selector-identity")
    await expect(selectButton).toBeVisible()
    // This screenshot differs based on whether you signed up or signed in.
    await checkpoint(page, `signup-successful-signin-username-${SIPASS_USERNAME}-previous-identities-page-from-sipass`)
    await selectButton.click()

    // Verify success message.
    await expect(page.locator("#authautoredirect-text-congratulations")).toBeVisible()
    await checkpoint(page, `auth-page-after-selecting-username-${SIPASS_USERNAME}-identity`)

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(3500)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await expect(identitiesLink).toBeVisible()

    await checkpoint(page, "successful-signin-identities-visible-on-main-page")
    console.log("Successfully completed sign-in flow: clicked on SIPASS, presented certificate, selected tester identity, and verified Identities link is visible")
  })
})
