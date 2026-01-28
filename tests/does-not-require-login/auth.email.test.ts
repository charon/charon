import { CHARON_URL, checkpoint, expect, MAILPIT_URL, test } from "../utils"

const EMAIL_CODE_REGEX_MATCHER: RegExp = /code to complete your Charon sign-in or sign-up:\s+(\d{6})\s+You can also open:/s
const EMAIL_LINK_REGEX_MATCHER: RegExp = /You can also open:\s+(https:\/\/[^\s]+)/s

async function extractCodeFromEmail(matcher: RegExp): Promise<string> {
  let timeoutCounter = 0
  const timeoutMaxCounter = 100 // 5 seconds.
  const messageNotFoundText = "Message not found"
  let emailText = messageNotFoundText
  while (emailText == messageNotFoundText && timeoutCounter < timeoutMaxCounter) {
    const emailResponse = await fetch(`${MAILPIT_URL}/view/latest.txt`)
    emailText = await emailResponse.text()
    if (emailText == messageNotFoundText) {
      // 50ms timeout
      await new Promise((resolve) => setTimeout(resolve, 50))
      timeoutCounter += 1
    }
  }
  expect(emailText).not.toBe(messageNotFoundText)
  await fetch(`${MAILPIT_URL}/api/v1/messages`, { method: "DELETE" })
  const codeMatch = emailText.match(matcher)
  const code = codeMatch ? codeMatch[1] : ""
  expect(code).toMatch(/\d{6}$/)

  const emailTextAfterEmailsDeleted = await (await fetch(`${MAILPIT_URL}/view/latest.txt`)).text()
  expect(emailTextAfterEmailsDeleted).toBe(messageNotFoundText)
  return code
}

test.describe.serial("Charon Sign-in Flows", () => {
  test("Successful email sign-in flow via code with flow restarts", async ({ context }) => {
    const page = await context.newPage()

    await page.goto(CHARON_URL)

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await checkpoint(page, "main-page-before-signin")
    await signInButton.click()

    // Find the email input field and enter 'tester@email.com'.
    const emailField = page.locator("input#authstart-input-email")
    await expect(emailField).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await emailField.fill("tester@email.com")

    // Find and click the NEXT button.
    const nextButton = page.locator("button#authstart-button-next")
    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-tester-email")
    await nextButton.click()

    // Go back.
    const backButton = page.locator("button#authpassword-button-back")
    await expect(backButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-and-clicking-next")
    await backButton.click()

    // Email should be filled in, we can simply click next again.
    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-tester-email-and-clicking-back")
    await nextButton.click()

    // Find and click the SEND CODE button.
    const sendCodeButton = page.locator("button#authpassword-button-sendcode")
    await expect(sendCodeButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-and-clicking-next")
    await sendCodeButton.click()

    // Delete all messages from the inbox.
    await extractCodeFromEmail(EMAIL_CODE_REGEX_MATCHER)

    // Go back and restart this part of the flow.
    const authCodeBackButton = page.locator("button#authcode-button-back")
    await expect(authCodeBackButton).toBeVisible()
    await checkpoint(page, "auth-page-after-clicking-send-code")
    await authCodeBackButton.click()

    // Click on SEND CODE again, retrieve the new code.
    await expect(sendCodeButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-and-clicking-next")
    await sendCodeButton.click()

    // Get email code from mailpit.
    const code: string = await extractCodeFromEmail(EMAIL_CODE_REGEX_MATCHER)

    // Find the code input field and enter it.
    const codeField = page.locator("input#code")
    await expect(codeField).toBeVisible()
    await checkpoint(page, "auth-page-after-clicking-send-code")
    await codeField.fill(code)

    // Find and click the enabled NEXT button (not disabled).
    const nextButton2 = page.locator("button#authcode-button-submitcode")
    await expect(nextButton2).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-code", { mask: [codeField] })
    await nextButton2.click()

    // Code should be accepted - verify successful sign-up message.
    await expect(page.getByText("You successfully signed up into Charon")).toBeVisible()

    // Find the li element that contains "tester" and click its SELECT button.
    const testerIdentity = page.locator('li:has-text("tester")')
    const selectButton = testerIdentity.locator("button.authidentity-selector-identity")
    await expect(selectButton).toBeVisible()
    await checkpoint(page, "email-successful-code-identity-selector-page-from-code")
    await selectButton.click()

    // Verify success message.
    await expect(page.getByText("Everything is ready to sign you in")).toBeVisible()
    await checkpoint(page, "auth-page-after-selecting-email-identity")

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(3500)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await expect(identitiesLink).toBeVisible()

    await checkpoint(page, "successful-signin-identities-page")

    console.log("Successfully completed email sign-in flow: entered email, navigated through flow, selected tester email, signed in via email code.")
  })

  test("Successful email sign-in flow via code after wrong password", async ({ context }) => {
    const page = await context.newPage()

    await page.goto(CHARON_URL)

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await checkpoint(page, "main-page-before-signin")
    await signInButton.click()

    // Find the email input field and enter 'tester@email.com'.
    const emailField = page.locator("input#authstart-input-email")
    await expect(emailField).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await emailField.fill("tester@email.com")

    // Find and click the NEXT button.
    const nextButton = page.locator("button#authstart-button-next")
    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-tester-email")
    await nextButton.click()

    // Find the password input field and enter 'tester1234' (wrong password).
    const passwordField = page.locator("input#authpassword-input-currentpassword")
    await expect(passwordField).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-and-clicking-next")
    await passwordField.fill("tester1234")

    // Find and click the enabled NEXT button (not disabled).
    const nextButton2 = page.locator("button#authpassword-button-next")
    await expect(nextButton2).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-and-wrong-pw")
    await nextButton2.click()

    // Get email code from mailpit.
    const code = await extractCodeFromEmail(EMAIL_CODE_REGEX_MATCHER)

    // Find the code input field and enter it.
    const codeField = page.locator("input#code")
    await expect(codeField).toBeVisible()
    await checkpoint(page, "auth-page-after-clicking-send-code")
    await codeField.fill(code)

    // Find and click the enabled NEXT button (not disabled).
    const nextButton3 = page.locator("button#authcode-button-submitcode")
    await expect(nextButton3).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-code", { mask: [codeField] })
    await nextButton3.click()

    // Code should be accepted - verify successful sign-in message.
    await expect(page.getByText("You successfully signed in into Charon")).toBeVisible()

    // Find the li element that contains "tester" and click its SELECT button.
    const testerIdentity = page.locator('li:has-text("tester")')
    const selectButton = testerIdentity.locator("button.authidentity-selector-identity")
    await expect(selectButton).toBeVisible()
    await checkpoint(page, "successful-signin-previous-identities-page-from-code")
    await selectButton.click()

    // Verify success message.
    await expect(page.getByText("Everything is ready to sign you in")).toBeVisible()
    await checkpoint(page, "auth-page-after-selecting-email-identity")

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(3500)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await expect(identitiesLink).toBeVisible()

    await checkpoint(page, "successful-signin-identities-page")

    console.log("Successfully completed email sign-in flow: entered email, navigated through flow, selected tester email, signed in via email code.")
  })

  test("Successful email sign-in flow via code after adding username", async ({ context }) => {
    const page = await context.newPage()
    await page.goto(CHARON_URL)

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await checkpoint(page, "main-page-before-signin")
    await signInButton.click()

    // Find the email input field and enter 'testerwithpassword@email.com'.
    const emailField = page.locator("input#authstart-input-email")
    await expect(emailField).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await emailField.fill("testerwithpassword@email.com")

    // Find and click the NEXT button.
    const nextButton = page.locator("button#authstart-button-next")
    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-testerwithpassword-email")
    await nextButton.click()

    // Find the password input field and enter 'tester123' (correct password).
    const passwordField = page.locator("input#authpassword-input-currentpassword")
    await expect(passwordField).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-testerwithpassword-and-clicking-next")
    await passwordField.fill("tester123")

    // Find and click the enabled NEXT button (not disabled).
    const nextButton2 = page.locator("button#authpassword-button-next")
    await expect(nextButton2).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-testerwithpassword-and-correct-pw")
    await nextButton2.click()

    // Get email code from mailpit.
    const code = await extractCodeFromEmail(EMAIL_CODE_REGEX_MATCHER)

    // Find the code input field and enter it.
    const codeField = page.locator("input#code")
    await expect(codeField).toBeVisible()
    await checkpoint(page, "auth-page-after-clicking-send-code-for-testerwithpassword")
    await codeField.fill(code)

    // Find and click the enabled NEXT button (not disabled).
    const nextButton3 = page.locator("button#authcode-button-submitcode")
    await expect(nextButton3).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-testerwithpassword-code", { mask: [codeField] })
    await nextButton3.click()

    // Code should be accepted - verify successful sign-in message.
    await expect(page.getByText("You successfully signed up into Charon")).toBeVisible()

    // Find the li element that contains "testerwithpassword" and click its SELECT button.
    const testerIdentity = page.locator('li:has-text("testerwithpassword")')
    const selectButton = testerIdentity.locator("button.authidentity-selector-identity")
    await expect(selectButton).toBeVisible()
    await checkpoint(page, "successful-signin-previous-identities-testerwithpassword-page-from-code")
    await selectButton.click()

    // Verify success message.
    await expect(page.getByText("Everything is ready to sign you in")).toBeVisible()
    await checkpoint(page, "auth-page-after-selecting-testerwithpassword-email-identity")

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(3500)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await expect(identitiesLink).toBeVisible()

    await checkpoint(page, "successful-testerwithpassword-signin-identities-page")

    // Find and click the Authentication methods link.
    const authMethodsLink = page.locator("#menu-list-credentials")
    await expect(authMethodsLink).toBeVisible()
    await authMethodsLink.click()

    // Find and click the ADD button.
    const addButton = page.locator("#credentiallist-button-add")
    await expect(addButton).toBeVisible()
    await addButton.click()

    // Add a new username.
    const usernameRadio = page.locator("#credentialadd-radio-username")
    await expect(usernameRadio).toBeVisible()
    await usernameRadio.click()

    const usernameInput = page.locator("#credentialaddusername-input-username")
    await expect(usernameInput).toBeVisible()
    await usernameInput.fill("new-user-email-flow")

    const addUsernameButton = page.locator("#credentialaddusername-button-add")
    await expect(addUsernameButton).toBeVisible()
    await addUsernameButton.click()

    const signOutButton = page.locator("#navbar-button-signout")
    // Since the signOutButton is always visible, we should wait to come back to the Auth Methods page instead.
    await expect(addButton).toBeVisible()
    const homeButton = page.locator("#navbar-link-home")
    await expect(homeButton).toBeVisible()
    await homeButton.click()
    await page.waitForLoadState("networkidle")
    await signOutButton.click()

    // Now sign in with username and password.
    // Find and click the "SIGN-IN OR SIGN-UP" button.
    await expect(signInButton).toBeVisible()
    await checkpoint(page, "main-page-before-signin-after-adding-username")
    await signInButton.click()

    // Find the email input field and enter 'new-user-email-flow'.
    await expect(emailField).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await emailField.fill("new-user-email-flow")

    // Find and click the NEXT button.
    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-username-new-user-email-flow")
    await nextButton.click()

    // Find the password input field and enter 'tester123'.
    await expect(passwordField).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-username-new-user-email-flow-and-clicking-next")
    await passwordField.fill("tester123")

    // Find and click the enabled NEXT button (not disabled).
    await expect(nextButton2).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-new-user-email-flow-and-password")
    await nextButton2.click()

    // Find the li element that contains "testerwithpassword" and click its SELECT button.
    await expect(selectButton).toBeVisible()
    // Store data ID.
    const dataUrl = await testerIdentity.locator("div[data-url]").getAttribute("data-url")
    const identityId = dataUrl?.match(/\/api\/i\/([^?]+)/)?.[1]
    await selectButton.click()
    await expect(homeButton).toBeVisible()
    await homeButton.click()
    await page.waitForLoadState("networkidle")
    await signOutButton.click()

    // Now sign in via e-mail again, confirm that identityId matches.
    // Find and click the "SIGN-IN OR SIGN-UP" button.
    await expect(signInButton).toBeVisible()
    await checkpoint(page, "main-page-before-signin-after-signing-in")
    await signInButton.click()

    // Find the email input field and enter 'testerwithpassword@email.com'.
    await expect(emailField).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await emailField.fill("testerwithpassword@email.com")

    // Find and click the NEXT button.
    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-testerwithpassword-email")
    await nextButton.click()

    // Find the password input field and enter 'tester123' (correct password).
    await expect(passwordField).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-testerwithpassword-and-clicking-next")
    await passwordField.fill("tester123")

    // Find and click the enabled NEXT button (not disabled).
    await expect(nextButton2).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-testerwithpassword-and-correct-password")
    await nextButton2.click()

    // Code should be accepted - verify successful sign-in message.
    await expect(page.getByText("You successfully signed in into Charon")).toBeVisible()

    // Find the li element that contains "testerwithpassword" and click its SELECT button.
    await expect(selectButton).toBeVisible()
    await checkpoint(page, "successful-signin-testerwithpassword-previous-identities-page-from-code")
    const emailIdentityId = dataUrl?.match(/\/api\/i\/([^?]+)/)?.[1]

    expect(identityId).toEqual(emailIdentityId)

    console.log(
      "Successfully signed up with email, added username, signed in with username, extracted identity ID, signed in via e-mail, confirmed that identity IDs match.",
    )
  })

  test("Successful email sign-in flow via e-mail link", async ({ context }) => {
    const page = await context.newPage()

    await page.goto(CHARON_URL)

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await checkpoint(page, "main-page-before-signin")
    await signInButton.click()

    // Find the email input field and enter 'tester@email.com'.
    const emailField = page.locator("input#authstart-input-email")
    await expect(emailField).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await emailField.fill("tester@email.com")

    // Find and click the NEXT button.
    const nextButton = page.locator("button#authstart-button-next")
    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-tester-email")
    await nextButton.click()

    // Find and click the SEND CODE button.
    const sendCodeButton = page.locator("button#authpassword-button-sendcode")
    await expect(sendCodeButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-and-clicking-next")
    await sendCodeButton.click()

    // Get email link from mailpit.
    const link = await extractCodeFromEmail(EMAIL_LINK_REGEX_MATCHER)
    await expect(page.locator("button#authcode-button-resendcode")).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-before-code")

    await page.goto(link)

    // Find and click the enabled NEXT button (not disabled).
    const nextButton2 = page.locator("button#authcode-button-submitcode")
    await expect(nextButton2).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-code-from-link", { mask: [page.locator("input#code")] })
    await nextButton2.click()

    // Code should be accepted - verify successful sign-in message.
    await expect(page.getByText("You successfully signed in into Charon")).toBeVisible()

    // Find the li element that contains "tester" and click its SELECT button.
    const testerIdentity = page.locator('li:has-text("tester")')
    const selectButton = testerIdentity.locator("button.authidentity-selector-identity")
    await expect(selectButton).toBeVisible()
    await checkpoint(page, "successful-signin-previous-identities-page-from-link")
    await selectButton.click()

    // Verify success message.
    await expect(page.getByText("Everything is ready to sign you in")).toBeVisible()
    await checkpoint(page, "auth-page-after-selecting-email-identity")

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(3500)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await expect(identitiesLink).toBeVisible()

    await checkpoint(page, "successful-signin-identities-page")

    console.log("Successfully completed email sign-in flow: entered email, navigated through flow, selected tester email, signed in via email link.")
  })

  test("Unsuccessful email sign-in flow via code", async ({ context }) => {
    const page = await context.newPage()

    await page.goto(CHARON_URL)

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await checkpoint(page, "main-page-before-signin")
    await signInButton.click()

    // Find the email input field and enter 'tester@email.com'.
    const emailField = page.locator("input#authstart-input-email")
    await expect(emailField).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await emailField.fill("tester@email.com")

    // Find and click the NEXT button.
    const nextButton = page.locator("button#authstart-button-next")
    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-tester-email")
    await nextButton.click()

    // Find and click the SEND CODE button.
    const sendCodeButton = page.locator("button#authpassword-button-sendcode")
    await expect(sendCodeButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-and-clicking-next")
    await sendCodeButton.click()

    // Despite not needing the code, we call this function to delete all emails.
    await extractCodeFromEmail(EMAIL_CODE_REGEX_MATCHER)

    // Find the code input field and enter wrong code.
    const codeField = page.locator("input#code")
    await expect(codeField).toBeVisible()
    await checkpoint(page, "auth-page-after-clicking-send-code")
    await codeField.fill("abcabc") // Code is always numerical, this will always fail.

    // Find and click the enabled NEXT button (not disabled).
    const nextButton2 = page.locator("button#authcode-button-submitcode")
    await expect(nextButton2).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-wrong-code")
    await nextButton2.click()

    // Code should not be accepted - verify error message.
    await expect(page.locator('text="Code is invalid. Please try again."')).toBeVisible()

    await checkpoint(page, "auth-page-incorrect-email-code")

    console.log(
      "Successfully completed wrong email code sign-in flow: entered email, navigated through flow, selected tester email, attempted signin via incorrect code.",
    )
  })

  test("Unsuccessful email sign-in flow via link", async ({ context }) => {
    const page = await context.newPage()

    await page.goto(CHARON_URL)

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await checkpoint(page, "main-page-before-signin")
    await signInButton.click()

    // Find the email input field and enter 'tester@email.com'.
    const emailField = page.locator("input#authstart-input-email")
    await expect(emailField).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await emailField.fill("tester@email.com")

    // Find and click the NEXT button.
    const nextButton = page.locator("button#authstart-button-next")
    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-tester-email")
    await nextButton.click()

    // Find and click the SEND CODE button.
    const sendCodeButton = page.locator("button#authpassword-button-sendcode")
    await expect(sendCodeButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-and-clicking-next")
    await sendCodeButton.click()

    // Get email link from mailpit.
    const link = await extractCodeFromEmail(EMAIL_LINK_REGEX_MATCHER)
    await expect(page.locator("button#authcode-button-resendcode")).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-before-code")

    // By replacing the code with letters, the code will always be invalid (and reproducible).
    await page.goto(link.slice(0, -6) + "abcabc")

    // Find and click the enabled NEXT button (not disabled).
    const nextButton2 = page.locator("button#authcode-button-submitcode")
    await expect(nextButton2).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-wrong-code-from-link")
    await nextButton2.click()

    // Code should not be accepted - verify error message.
    await expect(page.locator('text="Code is invalid. Please try again."')).toBeVisible()

    await checkpoint(page, "auth-page-incorrect-email-code-from-link")

    console.log(
      "Successfully completed wrong email code sign-in flow: entered email, navigated through flow, selected tester email, attempted signin via incorrect code.",
    )
  })

  test("Email sign-in code width test", async ({ context }) => {
    const page = await context.newPage()

    await page.goto(CHARON_URL)

    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await checkpoint(page, "main-page-before-signin")
    await signInButton.click()

    // Find the email input field and enter 'tester@email.com'.
    const emailField = page.locator("input#authstart-input-email")
    await expect(emailField).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await emailField.fill("tester@email.com")

    // Find and click the NEXT button.
    const nextButton = page.locator("button#authstart-button-next")
    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-tester-email")
    await nextButton.click()

    // Find and click the SEND CODE button.
    const sendCodeButton = page.locator("button#authpassword-button-sendcode")
    await expect(sendCodeButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-and-clicking-next")
    await sendCodeButton.click()

    // Get email code from mailpit to delete all emails.
    await extractCodeFromEmail(EMAIL_CODE_REGEX_MATCHER)
    await expect(page.locator("button#authcode-button-resendcode")).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-email-before-code")

    // Find the code input field and enter it.
    const codeField = page.locator("input#code")
    await expect(codeField).toBeVisible()
    await checkpoint(page, "auth-page-after-clicking-send-code")
    // 15 characters can still fit into the input field with all vertical lines visible.
    for (let i = 1; i < 15; i++) {
      await codeField.pressSequentially(String.fromCharCode(96 + i))
    }

    for (let i = 1; i < 10; i++) {
      await codeField.pressSequentially(String.fromCharCode(96 + i))
      // Vertical lines should disappear one by one until they are all gone.
      await checkpoint(page, `auth-page-after-entering-char-for-code-${i}`)
    }

    // Now go back by pressing left arrow key.
    for (let i = 1; i < 15; i++) {
      await codeField.press("ArrowLeft")
    }
    for (let i = 1; i < 10; i++) {
      // Vertical lines should reappear one by one as cursor moves left.
      await codeField.press("ArrowLeft")
      await checkpoint(page, `auth-page-after-pressing-left-${i}`)
    }

    console.log("Successfully entered an email code so long that vertical lines disappear.")
  })
})
