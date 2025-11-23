import { CHARON_URL, checkpoint, expect, test } from "./utils.ts"

test.describe.serial("Charon Sign-in Flows", () => {
  test("Successful password sign-in flow", async ({ context }) => {
    const page = await context.newPage()

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
    await checkpoint(page, "successful-signin-previous-identities-page-from-password")
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

    console.log("Successfully completed sign-in flow: entered credentials, navigated through flow, selected tester identity, and verified Identities link is visible")
  })

  test("Wrong password sign-in flow", async ({ context }) => {
    const page = await context.newPage()

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

    // Find the password input field and enter 'tester1234' (wrong password).
    const passwordField = page.locator("input#authpassword-input-currentpassword")
    await expect(passwordField).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-username-and-clicking-next")
    await passwordField.fill("tester1234")

    // Find and click the enabled NEXT button (not disabled).
    const nextButton2 = page.locator("button#authpassword-button-next")
    await expect(nextButton2).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-wrong-password")
    await nextButton2.click()

    // Wait for error message to appear.
    const errorMessage = page.locator("#authpassword-error-wrongpassword")
    await expect(errorMessage).toBeVisible()

    await checkpoint(page, "auth-page-wrong-password-error-message")

    console.log("Successfully tested wrong password flow: entered wrong password and verified error message appeared")
  })
})
