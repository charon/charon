import { createApplicationTemplate, createOrganization, signInWithPassword, takeActivityScreenshot } from "../charon_utils"
import { checkpoint, expect, test } from "../utils"

test.describe.serial("Charon User Roles", () => {
  test("Test user roles in organization", async ({ context }) => {
    const page = await context.newPage()
    const rolesUsername = "tester-roles-admin"
    const rolesOrganizationName = "Roles Test Organization"
    await signInWithPassword(page, rolesUsername, "tester123", true, true)

    // Mask the available applications list to avoid flakiness from identifier-based ordering.
    const availableApplicationsMask = page.locator("ul:has(.organizationget-button-add)")

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
    await checkpoint(page, "roles-applications-with-role-added")

    // Click on home.
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
    await checkpoint(page, "roles-organization-adding-application")
    await uriBaseField.fill("https://oidcdebugger.com")
    const activateOrDisableButton = page.locator("#organizationget-button-activateordisable-0")
    await expect(activateOrDisableButton).toBeVisible()
    await activateOrDisableButton.click()

    // Update the added application.
    const updateApplicationButton = page.locator("#organizationget-button-applicationsupdate")
    await expect(updateApplicationButton).toBeVisible()
    await expect(page.locator(".organizationget-text-status").first()).toBeVisible()
    await checkpoint(page, "roles-organization-with-pending-activation-application", { mask: [availableApplicationsMask] })
    await updateApplicationButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationget-text-applicationsupdated")).toBeVisible()
    await checkpoint(page, "roles-organization-with-added-and-activated-application", { mask: [availableApplicationsMask] })

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
    await checkpoint(page, "roles-organization-with-admin-identity-added", { mask: [availableApplicationsMask] })

    // Navigate to manage users and assign role to added identity.
    const manageUsersButton = page.locator("#organizationget-button-manageusers")
    await expect(manageUsersButton).toBeVisible()
    await manageUsersButton.click()

    const userEntry = page.locator(`.organizationusers-div-userentry:has-text("${rolesUsername}")`)
    const userRolesButton = userEntry.locator(".organizationusers-button-roles")
    await expect(userRolesButton).toBeVisible()
    await checkpoint(page, "roles-organization-manage-users")
    await userRolesButton.click()

    const roleCheckbox = page.locator("#organizationroles-checkbox-applicationRole")
    await expect(roleCheckbox).toBeVisible()
    await roleCheckbox.click()

    const updateRolesButton = page.locator("#organizationroles-button-update")
    await expect(updateRolesButton).toBeVisible()
    await checkpoint(page, "roles-organization-with-role-selected")
    await updateRolesButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationroles-text-rolesupdated")).toBeVisible()
    await checkpoint(page, "roles-organization-with-role-assigned")

    // Deactivate first application.
    await page.goBack()
    await page.goBack()
    await expect(activateOrDisableButton).toBeVisible()
    await activateOrDisableButton.click()

    await expect(updateApplicationButton).toBeVisible()
    await expect(page.locator(".organizationget-text-status").first()).toBeVisible()
    await checkpoint(page, "roles-organization-with-pending-deactivation-application", { mask: [availableApplicationsMask] })
    await updateApplicationButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationget-text-applicationsupdated")).toBeVisible()
    await checkpoint(page, "roles-organization-with-application-disabled", { mask: [availableApplicationsMask] })

    await expect(manageUsersButton).toBeVisible()
    await manageUsersButton.click()

    await expect(userRolesButton).toBeVisible()
    await userRolesButton.click()
    await checkpoint(page, "roles-organization-with-role-from-disabled-application")

    // Uncheck role, role from disabled application template disappears.
    await roleCheckbox.click()

    await expect(updateRolesButton).toBeVisible()
    await checkpoint(page, "roles-organization-with-role-unselected-disabled-application")
    await updateRolesButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationroles-text-rolesupdated")).toBeVisible()

    // Inactive app role disappears.
    await expect(roleCheckbox).not.toBeVisible()
    await checkpoint(page, "roles-organization-without-roles-after-app-deactivation")

    // To take activity screenshot, go back to organization and re-enable the application.
    await page.goBack()
    await page.goBack()
    await expect(activateOrDisableButton).toBeVisible()
    await activateOrDisableButton.click()

    await expect(updateApplicationButton).toBeVisible()
    await expect(page.locator(".organizationget-text-status").first()).toBeVisible()
    await checkpoint(page, "roles-organization-with-pending-reactivation-application", { mask: [availableApplicationsMask] })
    await updateApplicationButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationget-text-applicationsupdated")).toBeVisible()
    await checkpoint(page, "roles-organization-with-reactivated-application", { mask: [availableApplicationsMask] })

    await takeActivityScreenshot(page, "roles-activity")

    // Back to organization
    await homeButton.click()
    const organizationMenuButton = page.locator("#menu-list-organizations")
    await expect(organizationMenuButton).toBeVisible()
    await organizationMenuButton.click()
    const orgLink = page.locator(`a.link:has-text("${rolesOrganizationName}")`)
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
    await checkpoint(page, "roles-organization-with-role-reassigned")

    // Go back to organization and remove the application.
    await page.goBack()
    await page.goBack()
    const removeButton = page.locator("#organizationget-button-remove-0")
    await expect(removeButton).toBeVisible()
    await removeButton.click()

    await expect(updateApplicationButton).toBeVisible()
    await checkpoint(page, "roles-organization-with-pending-removal-application", { mask: [availableApplicationsMask] })
    await updateApplicationButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationget-text-applicationsupdated")).toBeVisible()
    await checkpoint(page, "roles-organization-with-application-removed", { mask: [availableApplicationsMask] })

    // Navigate to roles: role shows with "(removed app)" annotation, still assigned.
    await expect(manageUsersButton).toBeVisible()
    await manageUsersButton.click()

    await expect(userRolesButton).toBeVisible()
    await userRolesButton.click()
    await expect(roleCheckbox).toBeVisible()
    await checkpoint(page, "roles-organization-with-role-from-removed-application")

    // Uncheck role, role from removed application disappears.
    await roleCheckbox.click()

    await expect(updateRolesButton).toBeVisible()
    await checkpoint(page, "roles-organization-with-role-unselected-removed-application")
    await updateRolesButton.click()

    // Check for the success message.
    await expect(page.locator("#organizationroles-text-rolesupdated")).toBeVisible()

    // Removed app role disappears.
    await expect(roleCheckbox).not.toBeVisible()
    await checkpoint(page, "roles-organization-without-roles-after-app-removal")

    console.log("Successfully added application template to organization and manipulated user roles.")
  })
})
