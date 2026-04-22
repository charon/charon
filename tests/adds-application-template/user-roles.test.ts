import { createApplicationTemplate, createOrganization, signInWithPassword, takeActivityScreenshot } from "../charon_utils"
import { checkpoint, expect, test } from "../utils"

test.describe.serial("Charon User Roles", () => {
  test("Test user roles in organization", async ({ context }) => {
    const page = await context.newPage()
    const rolesUsername = "tester-roles-admin"
    const rolesOrganizationName = "Roles Test Organization"
    await signInWithPassword(page, rolesUsername, "tester123", true, true)

    // Create application template with role.
    await createApplicationTemplate(page, "Roles Application", "roles")

    const addRoleButton = page.locator("#applicationtemplateget-button-addrole")
    await expect(addRoleButton).toBeVisible()
    await addRoleButton.click()

    const roleKeyField = page.locator("input#applicationtemplateget-role-0-key")
    await expect(roleKeyField).toBeVisible()
    await roleKeyField.fill("applicationRole")

    const updateApplicationRolesButton = page.locator("#applicationtemplateget-button-updateroles")
    await expect(updateApplicationRolesButton).toBeVisible()
    await updateApplicationRolesButton.click()

    await expect(page.locator("#applicationtemplateget-text-rolesupdated")).toBeVisible()
    await page.waitForTimeout(1000)
    await checkpoint(page, "roles-applications-role-added")

    // Create organization.
    const homeButton = page.locator("#navbar-link-home")
    await expect(homeButton).toBeVisible()
    await homeButton.click()
    await createOrganization(page, rolesOrganizationName)

    // Add application template to organization.
    const appItem = page.locator('li:has-text("Roles Application")')
    await expect(appItem).toBeVisible()
    const addButton = appItem.locator(".organizationget-button-add")
    await expect(addButton).toBeVisible()
    await addButton.click()

    const uriBaseField = page.locator("input#application-0-values-0")
    await expect(uriBaseField).toBeVisible()
    await expect(uriBaseField).toBeFocused()
    await uriBaseField.fill("https://oidcdebugger.com")
    const activateOrDisableButton = page.locator("#organizationget-button-activateordisable-0")
    await expect(activateOrDisableButton).toBeVisible()
    await activateOrDisableButton.click()

    // Update the added application.
    const updateApplicationButton = page.locator("#organizationget-button-applicationsupdate")
    await expect(updateApplicationButton).toBeVisible()
    await expect(page.locator("#organizationget-text-status-0")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(1000)
    await checkpoint(page, "roles-organization-with-application-pending")
    await updateApplicationButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationget-text-applicationsupdated")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(1000)
    await checkpoint(page, "roles-organization-with-application-activated")

    // Add admin identity to the organization.
    const adminIdentityItem = page.locator(`li:has-text("${rolesUsername}"):has(button:has-text("Add"))`)
    await expect(adminIdentityItem).toBeVisible()
    const addIdentityButton = adminIdentityItem.locator('button:has-text("Add")')
    await expect(addIdentityButton).toBeVisible()
    await addIdentityButton.click()

    // Activate the added identity.
    const addedIdentityItem = page.locator(`li:has-text("${rolesUsername}"):has(button:has-text("Activate"))`)
    await expect(addedIdentityItem).toBeVisible()
    const activateIdentityButton = addedIdentityItem.locator('button:has-text("Activate")')
    await expect(activateIdentityButton).toBeVisible()
    await activateIdentityButton.click()

    const updateIdentitiesButton = page.locator("#identities-update")
    await expect(updateIdentitiesButton).toBeVisible()
    await updateIdentitiesButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationget-text-identitiesupdated")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(1000)
    await checkpoint(page, "roles-organization-admin-identity-added")

    // Navigate to manage users and assign role to added identity.
    const manageUsersButton = page.locator("#organizationget-button-manageusers")
    await expect(manageUsersButton).toBeVisible()
    await manageUsersButton.click()

    const userRolesButton = page.locator("#organizationusers-button-roles-0")
    await expect(userRolesButton).toBeVisible()
    await checkpoint(page, "organizationusers-manage-users")
    await userRolesButton.click()

    const roleCheckbox = page.locator("#organizationroles-checkbox-applicationRole")
    await expect(roleCheckbox).toBeVisible()
    await roleCheckbox.click()

    const updateRolesButton = page.locator("#organizationroles-button-update")
    await expect(updateRolesButton).toBeVisible()
    await checkpoint(page, "roles-organization-roles-selected")
    await updateRolesButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationroles-text-rolesupdated")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(1000)
    await checkpoint(page, "organizationroles-roles-assigned")

    // Deactivate first application.
    await page.goBack()
    await page.goBack()
    await expect(activateOrDisableButton).toBeVisible()
    await activateOrDisableButton.click()

    await expect(updateApplicationButton).toBeVisible()
    await expect(page.locator("#organizationget-text-status-0")).toBeVisible()
    await updateApplicationButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationget-text-applicationsupdated")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(1000)
    await checkpoint(page, "roles-organization-with-application-disabled")

    await expect(manageUsersButton).toBeVisible()
    await manageUsersButton.click()

    await expect(userRolesButton).toBeVisible()
    await userRolesButton.click()
    await checkpoint(page, "roles-organization-enabled-disabled-removed-roles")

    // Uncheck role, role from disabled application template disappears.
    await roleCheckbox.click()

    await expect(updateRolesButton).toBeVisible()
    await checkpoint(page, "roles-organization-roles-unselected")
    await updateRolesButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationroles-text-rolesupdated")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(1000)

    // Inactive app role disappears.
    await expect(roleCheckbox).not.toBeVisible()
    await checkpoint(page, "organizationroles-inactive-roles-gone")

    // To take activity screenshot, go back to organization and re-enable the application.
    await page.goBack()
    await page.goBack()
    await expect(activateOrDisableButton).toBeVisible()
    await activateOrDisableButton.click()

    await expect(updateApplicationButton).toBeVisible()
    await expect(page.locator("#organizationget-text-status-0")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(1000)
    await checkpoint(page, "roles-organization-application-pending-reenable")
    await updateApplicationButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationget-text-applicationsupdated")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(1000)
    await checkpoint(page, "roles-organization-application-reenabled")

    await takeActivityScreenshot(page, "roles-activity")

    // Back to organization
    await homeButton.click()
    const organizationMenuButton = page.locator("#menu-list-organizations")
    await expect(organizationMenuButton).toBeVisible()
    await organizationMenuButton.click()
    const orgLink = page.locator(`a:has-text("${rolesOrganizationName}")`)
    await expect(orgLink).toBeVisible()
    await orgLink.click()

    // Add role back to user.
    await expect(manageUsersButton).toBeVisible()
    await manageUsersButton.click()
    await expect(userRolesButton).toBeVisible()
    await userRolesButton.click()
    await expect(roleCheckbox).toBeVisible()
    await roleCheckbox.click()
    await expect(updateRolesButton).toBeVisible()
    await updateRolesButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationroles-text-rolesupdated")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(1000)
    await checkpoint(page, "organizationroles-role-reassigned")

    // Go back to organization and remove the application.
    await page.goBack()
    await page.goBack()
    const removeButton = page.locator("#organizationget-button-remove-0")
    await expect(removeButton).toBeVisible()
    await removeButton.click()

    await expect(updateApplicationButton).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(1000)
    await checkpoint(page, "roles-organization-application-pending-remove")
    await updateApplicationButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationget-text-applicationsupdated")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(1000)
    await checkpoint(page, "roles-organization-application-removed")

    // Navigate to roles: role shows with "(removed app)" annotation, still assigned.
    await expect(manageUsersButton).toBeVisible()
    await manageUsersButton.click()
    await expect(userRolesButton).toBeVisible()
    await userRolesButton.click()
    await expect(roleCheckbox).toBeVisible()
    await checkpoint(page, "roles-organization-role-removed-app")
    // Uncheck role, role from removed application disappears.
    await roleCheckbox.click()
    await expect(updateRolesButton).toBeVisible()
    await checkpoint(page, "roles-organization-removed-role-unselected")
    await updateRolesButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationroles-text-rolesupdated")).toBeVisible()
    // Without waiting, navbar sometimes appears in the middle of the screenshot.
    await page.waitForTimeout(1000)

    // Removed app role disappears.
    await expect(roleCheckbox).not.toBeVisible()
    await checkpoint(page, "organizationroles-removed-roles-gone")
  })
})
