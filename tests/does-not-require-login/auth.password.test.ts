import { CHARON_URL, checkpoint, expect, test } from "../utils"

test.describe.serial("Charon Sign-in Flows", () => {
  test("Correct password sign-in flow with flow restarts", async ({ context }) => {
    const page = await context.newPage()
    await page.goto(CHARON_URL)

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await checkpoint(page, "main-page-before-signin")
    await signInButton.click()

    // Find the email input field and enter 'tester2'.
    const emailField = page.locator("input#authstart-input-email")
    await expect(emailField).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await emailField.fill("tester2")

    // Find and click the NEXT button.
    const nextButton = page.locator("button#authstart-button-next")
    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-sign-in-page-after-entering-username-tester2")
    await nextButton.click()

    // Go back, correct to tester3.
    const backButton = page.locator("button#authpassword-button-back")
    await expect(backButton).toBeVisible()
    await checkpoint(page, "auth-password-page-after-entering-username-tester2")
    await backButton.click()

    await expect(emailField).toBeVisible()
    await checkpoint(page, "auth-sign-in-page-after-pressing-back-username-tester2")
    await emailField.fill("tester3")

    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-sign-in-page-after-entering-username-tester3")
    await nextButton.click()

    // Go back by clicking on the username, correct to tester4.
    const emailOrUsernameButton = page.locator("button#authpassword-input-email-or-username")
    await expect(emailOrUsernameButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-username-tester3")
    await emailOrUsernameButton.click()

    await expect(emailField).toBeVisible()
    await checkpoint(page, "auth-sign-in-page-after-going-back-via-email-field")
    await emailField.fill("tester4")

    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-sign-in-page-after-going-back-via-email-field-entering-username-tester4")
    await nextButton.click()

    // Find the password input field and enter 'tester123'.
    const passwordField = page.locator("input#authpassword-input-currentpassword")
    await expect(passwordField).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-username-tester4-and-clicking-next")
    await passwordField.fill("tester123")

    // Find and click the enabled NEXT button (not disabled).
    const nextButton2 = page.locator("button#authpassword-button-next")
    await expect(nextButton2).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-password")
    await nextButton2.click()

    // Press back. We should come to the original page.
    const selectorBackButton = page.locator("button#authidentity-button-back")
    await expect(selectorBackButton).toBeVisible()
    await checkpoint(page, "auth-identity-selection-page-after-entering-username-tester4")
    await selectorBackButton.click()

    // Now go through flow again.
    await expect(emailField).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await emailField.fill("tester4")

    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-sign-in-page-after-entering-username-tester4")
    await nextButton.click()

    await expect(passwordField).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-username-and-clicking-next")
    await passwordField.fill("tester123")

    await expect(nextButton2).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-password")
    await nextButton2.click()

    // Find the li element that contains "tester4" and click its SELECT button.
    const testerIdentity = page.locator('li:has-text("tester4")')
    const selectButton = testerIdentity.locator("button.authidentity-selector-identity")
    await expect(selectButton).toBeVisible()
    await checkpoint(page, `signup-successful-signin-previous-identities-page-from-password`)
    await selectButton.click()

    // Verify success message and go back.
    await expect(page.getByText("Everything is ready to sign you in")).toBeVisible()
    const redirectBackButton = page.locator("button#authautoredirect-button-back")
    await expect(redirectBackButton).toBeVisible()
    await checkpoint(page, "auth-page-after-selecting-username-identity")
    await redirectBackButton.click()

    // Select the tester identity again.
    await expect(selectButton).toBeVisible()
    await checkpoint(page, `signin-successful-signin-tester4-previous-identities-page-from-password`)
    await selectButton.click()

    // Go back, this time by clicking on the flow link.
    const redirectFlowLink = page.locator("#authflowget-step-identity")
    await expect(redirectFlowLink).toBeVisible()
    await checkpoint(page, "auth-page-after-selecting-username-identity")
    await redirectFlowLink.click()

    // Select the tester identity again.
    await expect(selectButton).toBeVisible()
    await checkpoint(page, `signin-successful-signin-previous-identities-page-from-password`)
    await selectButton.click()

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(3500)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await expect(identitiesLink).toBeVisible()

    await checkpoint(page, "successful-signin-identities-page")
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
    await checkpoint(page, "auth-sign-in-page-after-entering-username-tester")
    await nextButton.click()

    // Find the password input field and enter 'tester1234' (wrong password).
    const passwordField = page.locator("input#authpassword-input-currentpassword")
    await expect(passwordField).toBeVisible()
    await checkpoint(page, "auth-password-page-after-entering-username-tester")
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
