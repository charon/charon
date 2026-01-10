import { CHARON_URL, checkpoint, expect, signInWithPassword, test } from "../utils"

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

    const idScopesField = page.locator("#applicationtemplateget-input-idscopes")
    await expect(idScopesField).toBeVisible()
    await checkpoint(page, "oidc-applications-created-application-initial")
    await idScopesField.fill("openid profile email")

    const applicationUpdateButton = page.locator("#applicationtemplateget-button-updatebasic")
    await expect(applicationUpdateButton).toBeVisible()
    await applicationUpdateButton.click()

    // Check for the success message.
    await expect(page.getByText("Application template updated successfully.")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(500)

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

    // Check for the success message.
    await expect(page.getByText("Public clients updated successfully.")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(500)

    await checkpoint(page, "oidc-applications-created-application-with-updated-public-client")

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
    await orgNameField.fill("Test OIDC Organization 1")

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
    const activateApplicationButton = page.locator("#organizationget-button-activateordisable-0")
    await expect(activateApplicationButton).toBeVisible()
    await activateApplicationButton.click()

    // Update the added application.
    const updateApplicationButton = page.locator("#organizationget-button-applicationsupdate")
    await expect(updateApplicationButton).toBeVisible()
    await expect(page.getByText("Status: active")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(500)
    await checkpoint(page, "oidc-organization-with-pending-activation-application")
    await updateApplicationButton.click()

    // Store client ID.
    const clientIdField = page.locator("#organizationget-code-clientid-0")
    await expect(clientIdField).not.toBeEmpty()
    const oidcClientId = (await clientIdField.textContent()) as string
    expect(oidcClientId).not.toBeNull()

    // Check for the success message.
    await expect(page.getByText("Added applications updated successfully.")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(500)
    await checkpoint(page, "oidc-organization-with-added-and-activated-application", { mask: [clientIdField] })

    // Test with all three response modes.
    const responseModes = [
      { mode: "query", username: "tester-query" },
      { mode: "formPost", username: "tester-formPost" },
      { mode: "fragment", username: "tester-fragment" },
    ]

    for (const { mode, username } of responseModes) {
      // Go to oidcdebugger.com.
      await page.goto("https://oidcdebugger.com/")
      const oidcDebuggerAuthorizeUriField = page.locator("input#authorizeUri")
      await expect(oidcDebuggerAuthorizeUriField).toBeVisible()
      await oidcDebuggerAuthorizeUriField.fill(`${CHARON_URL}/auth/oidc/authorize`)
      const oidcDebuggerClientIdField = page.locator("input#clientId")
      await expect(oidcDebuggerClientIdField).toBeVisible()
      await oidcDebuggerClientIdField.fill(oidcClientId)
      const oidcDebuggerScopesField = page.locator("input#scopes")
      await expect(oidcDebuggerScopesField).toBeVisible()
      await oidcDebuggerScopesField.fill("openid profile email")

      // Enable PKCE.
      const usePkceCheckbox = page.locator("input#use-pkce")
      await expect(usePkceCheckbox).toBeVisible()
      await usePkceCheckbox.check()
      const oidcDebuggerTokenUriField = page.locator("input#tokenUri")
      await expect(oidcDebuggerTokenUriField).toBeVisible()
      await oidcDebuggerTokenUriField.fill(`${CHARON_URL}/auth/oidc/token`)

      // Select response mode.
      const responseModeRadio = page.locator(`input#responseMode-${mode}`)
      await expect(responseModeRadio).toBeVisible()
      await responseModeRadio.click()

      // Click Send Request button.
      const sendRequestButton = page.locator(".debug__form-submit--button")
      await expect(sendRequestButton).toBeVisible()
      await sendRequestButton.click()

      // Sign in with the username.
      const emailField = page.locator("input#authstart-input-email")
      await expect(emailField).toBeVisible()
      await checkpoint(page, `main-page-after-clicking-signin-${mode}`)
      await emailField.fill(username)

      const nextButton = page.locator("button#authstart-button-next")
      await expect(nextButton).toBeVisible()
      await checkpoint(page, `auth-page-after-entering-username-${username}`)
      await nextButton.click()

      const passwordField = page.locator("input#authpassword-input-currentpassword")
      await expect(passwordField).toBeVisible()
      await checkpoint(page, `auth-page-after-entering-username-and-clicking-next-${mode}`)
      await passwordField.fill("tester1234")

      const nextButton2 = page.locator("button#authpassword-button-next")
      await expect(nextButton2).toBeVisible()
      await checkpoint(page, `auth-page-after-entering-username-${username}-password-tester1234`)
      await nextButton2.click()

      const testerIdentity = page.locator(`li:has-text("${username}")`)
      const selectButton = testerIdentity.locator("button.authidentity-selector-identity")
      await expect(selectButton).toBeVisible()
      await checkpoint(page, `signup-successful-signin-username-${username}-previous-identities-page-from-password`)
      await selectButton.click()

      // Verify success message.
      await expect(page.getByText("Everything is ready to sign you in")).toBeVisible()
    }

    // Now sign in with tester and check activity logs.
    await signInWithPassword(page, false)

    await expect(organizationsLink).toBeVisible()
    await organizationsLink.click()

    // Select organization "Test OIDC Organization 1".
    const organization1Link = page.locator('a.link:has-text("Test OIDC Organization 1")')
    await expect(organization1Link).toBeVisible()
    await organization1Link.click()

    // Get user activity.
    const getUserActivity = page.locator("#organizationget-button-getactivity")
    await expect(getUserActivity).toBeVisible()
    await getUserActivity.click()

    // Check user activity for each tester.
    for (const { username } of responseModes) {
      // Verify that activity log contains the identity link.
      const activityLogIdentityLink = page.locator(`a.link:has-text("${username}")`)
      await expect(activityLogIdentityLink).toBeVisible()
    }
    await checkpoint(page, "oidc-organization-user-activity-contains-testers", {
      mask: [page.locator(".activitylistitem-text-session"), page.locator(".activitylistitem-text-timestamp")],
    })

    console.log("Successfully created an OIDC application, added it to an organization and signed in.")
  })
})
