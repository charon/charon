import type { CDPSession } from "@playwright/test"
import {
  checkpoint,
  clearConsoleErrors,
  expect,
  getIdFromAddedVirtualAuthenticator,
  signInWithPassword,
  simulatePasskeyInput,
  takeScreenshotsOfEntries,
  test,
} from "../utils"

test.describe.serial("Charon Auth Methods Flows", () => {
  test("Test adding a new password", async ({ context }) => {
    const page = await context.newPage()

    await signInWithPassword(page, "tester", "tester123", false, true)

    // Find and click the Authentication methods link.
    let authMethodsLink = page.locator("#menu-list-credentials")
    await expect(authMethodsLink).toBeVisible()
    await authMethodsLink.click()

    // Find and click the ADD button.
    let addButton = page.locator("#credentiallist-button-add")
    await expect(addButton).toBeVisible()
    await takeScreenshotsOfEntries(page, ".credentiallist-div-credentialentry", ".credentialfull-displayname", "auth-methods")
    await addButton.click()

    // Add a new password
    const passwordRadio = page.locator("#credentialadd-radio-password")
    await expect(passwordRadio).toBeVisible()
    await passwordRadio.click()

    const passwordInput = page.locator("#credentialaddpassword-input-password")
    await expect(passwordInput).toBeVisible()
    await passwordInput.fill("tester1234")

    const displayNameInput = page.locator("#credentialaddpassword-input-displayname")
    await expect(displayNameInput).toBeVisible()
    await displayNameInput.fill("password2")

    const addPasswordButton = page.locator("#credentialaddpassword-button-add")
    await expect(addPasswordButton).toBeVisible()
    await checkpoint(page, "auth-methods-add-password-filled")
    await addPasswordButton.click()
    // Since the signOutButton is always visible, we should wait to come back to the Auth Methods page instead.
    await expect(addButton).toBeVisible()

    const homeButton = page.locator("#navbar-link-home")
    await expect(homeButton).toBeVisible()
    await homeButton.click()
    const signOutButton = page.locator("#navbar-button-signout")
    await expect(signOutButton).toBeVisible()
    await page.waitForLoadState("networkidle")
    await signOutButton.click()

    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()

    // Sign in with new password.
    await signInWithPassword(page, "tester", "tester1234", false, true)

    // Go to auth methods.
    authMethodsLink = page.locator("#menu-list-credentials")
    await expect(authMethodsLink).toBeVisible()
    await authMethodsLink.click()

    // Now rename the password.
    const passwordItem = page.locator('.credentiallist-div-credentialentry:has-text("password2")')
    const renameButton = passwordItem.locator("button.credentiallist-button-rename")
    await expect(renameButton).toBeVisible()
    await takeScreenshotsOfEntries(page, ".credentiallist-div-credentialentry", ".credentialfull-displayname", "auth-methods")
    await renameButton.click()

    const passwordRenameInput = page.locator("input.credentialfull-input")
    await expect(passwordRenameInput).toBeVisible()
    await passwordRenameInput.fill("password23")
    const confirmRenameButton = passwordRenameInput.locator("..").locator("button.credentialfull-button-rename")
    await expect(confirmRenameButton).toBeVisible()
    await confirmRenameButton.click()

    // Now remove the password.
    const renamedPasswordItem = page.locator('.credentiallist-div-credentialentry:has-text("password23")')
    const removeButton = renamedPasswordItem.locator("button.credentiallist-button-remove")
    await expect(removeButton).toBeVisible()
    await takeScreenshotsOfEntries(page, ".credentiallist-div-credentialentry", ".credentialfull-displayname", "auth-methods")
    await removeButton.click()

    // Since the signOutButton is always visible, we should wait to come back to the Auth Methods page instead.
    addButton = page.locator("#credentiallist-button-add")
    await expect(addButton).toBeVisible()

    await expect(homeButton).toBeVisible()
    await homeButton.click()
    await page.waitForLoadState("networkidle")
    await signOutButton.click()

    // Now try to sign in, it should fail.
    await signInWithPassword(page, "tester", "tester1234", false, false)

    console.log("Successfully added a new password, signed in, removed it, and tried to sign in unsuccessfully.")
  })

  test("Test adding a new passkey", async ({ context }) => {
    const page = await context.newPage()

    await signInWithPassword(page, "tester", "tester123", false, true)

    // Find and click the Authentication methods link.
    let authMethodsLink = page.locator("#menu-list-credentials")
    await expect(authMethodsLink).toBeVisible()
    await authMethodsLink.click()

    // Find and click the ADD button.
    let addButton = page.locator("#credentiallist-button-add")
    await expect(addButton).toBeVisible()

    await takeScreenshotsOfEntries(page, ".credentiallist-div-credentialentry", ".credentialfull-displayname", "auth-methods")
    await addButton.click()

    // Add a new passkey
    const passkeyRadio = page.locator("#credentialadd-radio-passkey")
    await expect(passkeyRadio).toBeVisible()
    await passkeyRadio.click()

    const displayNameInput = page.locator("#credentialaddpasskey-input-displayname")
    await expect(displayNameInput).toBeVisible()
    await displayNameInput.fill("passkey")

    // Enable WebAuthn environment in this session.
    const client: CDPSession = await page.context().newCDPSession(page)

    // Create a new Authenticator ID.
    const authenticatorId = await getIdFromAddedVirtualAuthenticator(client)

    const addPasskeyButton = page.locator("#credentialaddpasskey-button-add")
    await expect(addPasskeyButton).toBeVisible()
    await checkpoint(page, "auth-methods-add-passkey-filled")

    // Simulate passkey input with a promise that triggers a passkey prompt as the argument.
    await simulatePasskeyInput(() => addPasskeyButton.click(), "shouldSucceed", client, authenticatorId, false)

    let signOutButton = page.locator("#navbar-button-signout")
    // Since the signOutButton is always visible, we should wait to come back to the Auth Methods page instead.
    await expect(addButton).toBeVisible()
    await takeScreenshotsOfEntries(page, ".credentiallist-div-credentialentry", ".credentialfull-displayname", "auth-methods")

    const homeButton = page.locator("#navbar-link-home")
    await expect(homeButton).toBeVisible()
    await homeButton.click()
    await page.waitForLoadState("networkidle")
    await signOutButton.click()

    const signInButton = page.locator("#navbar-button-signin")
    await page.waitForSelector("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await signInButton.click()

    // Sign in with new passkey.
    const passkeyButton = page.locator("button#authstart-button-passkey")
    await expect(passkeyButton).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")

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

    // Go to auth methods.
    authMethodsLink = page.locator("#menu-list-credentials")
    await expect(authMethodsLink).toBeVisible()
    await takeScreenshotsOfEntries(page, ".credentiallist-div-credentialentry", ".credentialfull-displayname", "auth-methods")
    await authMethodsLink.click()

    // Now rename the passkey.
    const passkeyItem = page.locator('.credentiallist-div-credentialentry:has-text("passkey")')
    const renameButton = passkeyItem.locator("button.credentiallist-button-rename")
    await expect(renameButton).toBeVisible()
    await takeScreenshotsOfEntries(page, ".credentiallist-div-credentialentry", ".credentialfull-displayname", "auth-methods")
    await renameButton.click()

    const passkeyRenameInput = page.locator("input.credentialfull-input")
    await expect(passkeyRenameInput).toBeVisible()
    await passkeyRenameInput.fill("differentpasskey")
    const confirmRenameButton = passkeyRenameInput.locator("..").locator("button.credentialfull-button-rename")
    await expect(confirmRenameButton).toBeVisible()
    await simulatePasskeyInput(() => confirmRenameButton.click(), "updatePasskey", client, authenticatorId, true)

    // Now remove the passkey.
    const renamedPasskeyItem = page.locator(`div.flex.flex-row:has-text("differentpasskey")`)
    const removeButton = renamedPasskeyItem.locator("button.credentiallist-button-remove")
    await expect(removeButton).toBeVisible()

    // After the new passkey name is visible in the frontend, the passkey should be renamed in the backend as well.
    const renamedCredentials = await client.send("WebAuthn.getCredentials", {
      authenticatorId: authenticatorId,
    })
    const renamedCredential = renamedCredentials.credentials[0]
    expect(renamedCredential.userDisplayName).toBe("Charon (differentpasskey)")
    expect(renamedCredential.userName).toBe("Charon (differentpasskey)")

    // Continue removing the passkey.
    await takeScreenshotsOfEntries(page, ".credentiallist-div-credentialentry", ".credentialfull-displayname", "auth-methods")
    await simulatePasskeyInput(() => removeButton.click(), "deletePasskey", client, authenticatorId, true)

    // Since the signOutButton is always visible, we should wait to come back to the Auth Methods page instead.
    addButton = page.locator("#credentiallist-button-add")
    await expect(addButton).toBeVisible()
    signOutButton = page.locator("#navbar-button-signout")

    await expect(homeButton).toBeVisible()
    await homeButton.click()
    await page.waitForLoadState("networkidle")
    await signOutButton.click()

    await page.waitForSelector("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await signInButton.click()

    // Sign in with new passkey.
    await expect(passkeyButton).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")

    // Simulate passkey input with a promise that triggers a passkey prompt as the argument.
    await simulatePasskeyInput(() => passkeyButton.click(), "shouldNotSucceed", client, authenticatorId, true)
    const failedSigninText = page.locator("#authpasskeysignup-text-instructions")
    await expect(failedSigninText).toBeVisible()
    // TODO: This triggers a "AuthPasskeySignin.onAfterEnter G: fetch POST error 400:"
    //   "Failed to lookup Client-side Discoverable Credential: account not found" appears in server-side logs.
    clearConsoleErrors(page)
    await checkpoint(page, "auth-page-after-failed-signin-with-removed-passkey")

    console.log("Successfully added a new passkey, signed in, removed it, and tried to sign in unsuccessfully.")
  })

  test("Test adding a new username", async ({ context }) => {
    const page = await context.newPage()

    await signInWithPassword(page, "tester", "tester123", false, true)

    // Find and click the Authentication methods link.
    let authMethodsLink = page.locator("#menu-list-credentials")
    await expect(authMethodsLink).toBeVisible()
    await authMethodsLink.click()

    // Find and click the ADD button.
    let addButton = page.locator("#credentiallist-button-add")
    await expect(addButton).toBeVisible()
    await takeScreenshotsOfEntries(page, ".credentiallist-div-credentialentry", ".credentialfull-displayname", "auth-methods")
    await addButton.click()

    // Add a new username.
    const usernameRadio = page.locator("#credentialadd-radio-username")
    await expect(usernameRadio).toBeVisible()
    await usernameRadio.click()

    const usernameInput = page.locator("#credentialaddusername-input-username")
    await expect(usernameInput).toBeVisible()
    await usernameInput.fill("another")

    const addUsernameButton = page.locator("#credentialaddusername-button-add")
    await expect(addUsernameButton).toBeVisible()
    await takeScreenshotsOfEntries(page, ".credentiallist-div-credentialentry", ".credentialfull-displayname", "auth-methods")
    await addUsernameButton.click()

    let signOutButton = page.locator("#navbar-button-signout")
    const homeButton = page.locator("#navbar-link-home")
    await expect(homeButton).toBeVisible()
    await homeButton.click()
    await page.waitForLoadState("networkidle")
    await signOutButton.click()

    // Sign in with new username.
    // Find and click the "SIGN-IN OR SIGN-UP" button.
    const signInButton = page.locator("#navbar-button-signin")
    await expect(signInButton).toBeVisible()
    await checkpoint(page, "main-page-before-signin-after-added-username")
    await signInButton.click()

    // Find the email input field and enter the username.
    const emailField = page.locator("input#authstart-input-email")
    await expect(emailField).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await emailField.fill("another")

    // Find and click the NEXT button.
    const nextButton = page.locator("button#authstart-button-next")
    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-username-another")
    await nextButton.click()

    // Find the password input field and enter it.
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
    const usernameIdentity = page.locator(`li:has-text("tester")`)
    const selectButton = usernameIdentity.locator("button.authidentity-selector-identity")
    await expect(selectButton).toBeVisible()
    // This screenshot differs based on whether you signed up or signed in.
    await checkpoint(page, `signin-successful-signin-previous-identities-page-from-password`)
    await selectButton.click()

    // Verify success message.
    await expect(page.getByText("Everything is ready to sign you in")).toBeVisible()
    await checkpoint(page, "auth-page-after-selecting-username-identity")

    // Waiting for the automatic 3 seconds redirect.
    await page.waitForTimeout(3500)

    // Check that the Identities link is visible.
    const identitiesLink = page.locator("#menu-list-identities")
    await expect(identitiesLink).toBeVisible()

    // Go to auth methods.
    authMethodsLink = page.locator("#menu-list-credentials")
    await expect(authMethodsLink).toBeVisible()
    await authMethodsLink.click()

    // Now remove the username.
    const usernameItem = page.locator(`div.flex.flex-row:has-text("another")`)
    const removeButton = usernameItem.locator("button.credentiallist-button-remove")
    await expect(removeButton).toBeVisible()
    await takeScreenshotsOfEntries(page, ".credentiallist-div-credentialentry", ".credentialfull-displayname", "auth-methods")
    await removeButton.click()

    // Since the signOutButton is always visible, we should wait to come back to the Auth Methods page instead.
    addButton = page.locator("#credentiallist-button-add")
    await expect(addButton).toBeVisible()
    signOutButton = page.locator("#navbar-button-signout")
    await expect(homeButton).toBeVisible()
    await homeButton.click()
    await expect(signOutButton).toBeVisible()
    await page.waitForLoadState("networkidle")
    await signOutButton.click()

    // Now try to sign in with the other username, it should succeed but as that own user.
    await signInWithPassword(page, "another", "tester123", true, true)

    console.log("Successfully added a new username, signed in, removed it, and signed in as a new user.")
  })
})
