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

    const idScopesField = page.locator("input#applicationtemplateget-input-idscopes")
    await expect(idScopesField).toBeVisible()
    await idScopesField.fill("openid profile email")

    // Find and click the Organizations link.
    const organizationsLink = page.locator("#menu-list-organizations")
    await expect(organizationsLink).toBeVisible()
    await organizationsLink.click()

    // Find and click the CREATE button.
    const createButton = page.locator("#organizationlist-button-create")
    await expect(createButton).toBeVisible()
    await checkpoint(page, "organization-list-page", { mask: [page.locator("#organizationlist-content-list")] })
    await createButton.click()

    // Create 10 organizations.
    for (let i = 1; i <= 10; i++) {
      // Find the organization name input field and enter organization name.
      const orgNameField = page.locator("input#organizationcreate-input-name")
      await expect(orgNameField).toBeVisible()
      if (i === 1) {
        await checkpoint(page, "organization-create-page")
      }
      await orgNameField.fill(`Test Organization ${i}`)

      // Find and click the CREATE button.
      const createOrgButton = page.locator("button#organizationcreate-button-create")
      await expect(createOrgButton).toBeVisible()
      if (i === 1) {
        await checkpoint(page, "organization-create-page-filled")
      }
      await createOrgButton.click()

      // Wait for organization to be created.
      const manageUsersButton = page.locator("#organizationget-button-manageusers")
      await expect(manageUsersButton).toBeVisible()
      if (i === 1) {
        await checkpoint(page, "organization-created-page")
      }
      // Navigate back to create page.
      await page.goBack()
    }

    // Navigate to the organizations list.
    await page.goBack()

    const NUM_SCROLLS = 30
    // Scroll down the page in increments, taking screenshots.
    for (let i = 1; i < NUM_SCROLLS; i++) {
      await page.mouse.wheel(0, 5)
      await page.waitForTimeout(200) // ms.
      await checkpoint(page, `organization-list-scrolled-down-${i}`, { fullPage: false, mask: [page.locator("#organizationlist-content-list")] })
    }

    // Scroll back up.
    for (let i = 1; i < NUM_SCROLLS; i++) {
      await page.mouse.wheel(0, -5)
      await page.waitForTimeout(200) // ms.
      await checkpoint(page, `organization-list-scrolled-up-${i}`, { fullPage: false, mask: [page.locator("#organizationlist-content-list")] })
    }

    console.log("Successfully created 10 organizations and verified navbar scrolling behavior.")
  })
})
