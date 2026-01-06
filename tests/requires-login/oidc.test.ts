import { checkpoint, expect, signInWithPassword, test } from "../utils"

test.describe.serial("Charon OIDC Flows", () => {
  test("Test OIDC login", async ({ context }) => {
    const page = await context.newPage()

    await signInWithPassword(page, false)

    // Find and click the Application Templates link.
    const applicationsLink = page.locator("#menu-list-applicationTemplates")
    await expect(applicationsLink).toBeVisible()
    await applicationsLink.click()

    await checkpoint(page, "oidc-applications-first-view")

    // Create a new one.
    const applicationCreateButton = page.locator("#applicationtemplatelist-button-create")
    await expect(applicationCreateButton).toBeVisible()
    await applicationCreateButton.click()

    await checkpoint(page, "oidc-applications-create-application")

    const applicationNameField = page.locator("input#applicationtemplatecreate-input-name")
    await expect(applicationNameField).toBeVisible()
    await applicationNameField.fill("OIDC Application")

    await checkpoint(page, "oidc-applications-create-application-filled")

    const applicationSubmitButton = page.locator("#applicationtemplatecreate-button-create")
    await expect(applicationSubmitButton).toBeVisible()
    await applicationSubmitButton.click()

    await checkpoint(page, "oidc-applications-created-application-initial")

    const idScopesField = page.locator("#applicationtemplateget-input-idscopes")
    await expect(idScopesField).toBeVisible()
    await idScopesField.fill("openid profile email")

    const applicationUpdateButton = page.locator("#applicatiomtemplateget-update-button")
    await expect(applicationUpdateButton).toBeVisible()
    await applicationUpdateButton.click()

    await checkpoint(page, "oidc-applications-created-application-with-id-scopes")

    // Create a public client.
    const addPublicClientButton = page.locator("#applicationtemplateget-button-addpublicclient")
    await expect(addPublicClientButton).toBeVisible()
    await addPublicClientButton.click()

    // Add redirect url.
    const redirectField = page.locator("#client-public-0-redirectUriTemplates-0")
    await expect(redirectField).toBeVisible()
    await redirectField.fill("{uriBase}/debug")

    const updatePublicClientButton = page.locator("#applicationtemplateget-button-updatepublicclient")
    await expect(updatePublicClientButton).toBeVisible()
    await updatePublicClientButton.click()

    await checkpoint(page, "oidc-oidc-applications-created-application-with-updated-public-client")

    // Click on home.
    const homeButton = page.locator("#navbar-link-home")
    await expect(homeButton).toBeVisible()
    await homeButton.click()

    // Find and click the Organizations link.
    const organizationsLink = page.locator("#menu-list-organizations")
    await expect(organizationsLink).toBeVisible()
    await organizationsLink.click()

    // Find and click the CREATE button.
    const createButton = page.locator("#organizationlist-button-create")
    await expect(createButton).toBeVisible()
    await createButton.click()

    // Create an organization.
    // Find the organization name input field and enter organization name.
    const orgNameField = page.locator("input#organizationcreate-input-name")
    await expect(orgNameField).toBeVisible()
    await orgNameField.fill("Test Organization 1")

    // Find and click the CREATE button.
    const createOrgButton = page.locator("button#organizationcreate-button-create")
    await expect(createOrgButton).toBeVisible()
    await createOrgButton.click()

    // Add oidc app to the organization.
    const oidcItem = page.locator('li:has-text("OIDC Application")')
    await expect(oidcItem).toBeVisible()
    const addButton = oidcItem.locator(".organizationget-button-add")
    await expect(addButton).toBeVisible()
    await addButton.click()

    await checkpoint(page, "oidc-organization-adding-application")

    const uriBaseField = page.locator("input#application-0-values-0")
    await expect(uriBaseField).toBeVisible()
    await uriBaseField.fill("https://oidcdebugger.com")
    const activateApplicationButton = page.locator("#organizationget-button-activateordeactivate-0")
    await expect(activateApplicationButton).toBeVisible()
    await activateApplicationButton.click()

    await checkpoint(page, "oidc-organization-with-activated-application")

    // Update the added application.
    const updateApplicationButton = page.locator("#organizationget-button-applicationsupdate")
    await expect(updateApplicationButton).toBeVisible()
    await updateApplicationButton.click()

    // Store client ID.
    const clientIdField = page.locator("#organizationget-code-clientid-0")
    await expect(clientIdField).not.toBeEmpty()
    const oidcClientId = await clientIdField.textContent() as string
    expect(oidcClientId).not.toBeNull()

    await checkpoint(page, "oidc-organization-with-added-application", {mask: [clientIdField]})

    // Now go to oidcdebugger.com, try to sign in.
    await page.goto("https://oidcdebugger.com/")
    const oidcDebuggerAuthorizeUriField = page.locator("input#authorizeUri")
    await expect(oidcDebuggerAuthorizeUriField).toBeVisible()
    await oidcDebuggerAuthorizeUriField.fill("https://localhost:8080/auth/oidc/authorize")
    const oidcDebuggerClientIdField = page.locator("input#clientId")
    await expect(oidcDebuggerClientIdField).toBeVisible()
    await oidcDebuggerClientIdField.fill(oidcClientId)
    const oidcDebuggerScopesField = page.locator("input#scopes")
    await expect(oidcDebuggerScopesField).toBeVisible()
    await oidcDebuggerScopesField.fill("openid profile email")

    // Enable PKCE.
    const usePkceCheckbox = page.locator("input#use-pkce")
    await expect(usePkceCheckbox).toBeVisible()
    await usePkceCheckbox.click()
    const oidcDebuggerTokenUriField = page.locator("input#tokenUri")
    await expect(oidcDebuggerTokenUriField).toBeVisible()
    await oidcDebuggerTokenUriField.fill("https://localhost:8080/auth/oidc/token")

    // Click Send Request button.
    const sendRequestButton = page.locator(".debug__form-submit--button")
    await expect(sendRequestButton).toBeVisible()
    await sendRequestButton.click()

    // Now sign in with tester2.
    // Find the email input field and enter 'tester2'.
    const emailField = page.locator("input#authstart-input-email")
    await expect(emailField).toBeVisible()
    await checkpoint(page, "main-page-after-clicking-signin")
    await emailField.fill("tester2")

    // Find and click the NEXT button.
    const nextButton = page.locator("button#authstart-button-next")
    await expect(nextButton).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-username-tester2")
    await nextButton.click()

    // Find the password input field and enter 'tester1234'.
    const passwordField = page.locator("input#authpassword-input-currentpassword")
    await expect(passwordField).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-username-and-clicking-next")
    await passwordField.fill("tester1234")

    // Find and click the enabled NEXT button (not disabled).
    const nextButton2 = page.locator("button#authpassword-button-next")
    await expect(nextButton2).toBeVisible()
    await checkpoint(page, "auth-page-after-entering-username-tester2-password-tester1234")
    await nextButton2.click()

    // Find the li element that contains "tester2" and click its SELECT button.
    const tester2Identity = page.locator('li:has-text("tester2")')
    const selectButton = tester2Identity.locator("button.authidentity-selector-identity")
    await expect(selectButton).toBeVisible()
    await checkpoint(page, "signup-successful-signin-username-tester2-previous-identities-page-from-password")
    await selectButton.click()

    // Verify success message.
    await expect(page.getByText("Everything is ready to sign you in")).toBeVisible()

    // Now sign in with tester and check activity logs.
    await signInWithPassword(page, false)

    // Check user activity.
    await expect(organizationsLink).toBeVisible()
    await organizationsLink.click()
    const getUserActivity = tester2Identity.locator("button#organizationget-button-getactivity")
    await expect(getUserActivity).toBeVisible()
    await getUserActivity.click()

    // Verify that activity log contains tester2 identity link.
    const activityLogIdentityLink = page.locator('a.link:has-text("tester2")')
    await expect(activityLogIdentityLink).toBeVisible()

    await checkpoint(page, "oidc-organization-user-activity-contains-tester2")

    console.log("Successfully created an OIDC application, added it to an organization and signed in.")
  })
})
