package charon_test

import (
	"context"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/tozd/identifier"

	"gitlab.com/charon/charon"
)

func TestCreateIdentity(t *testing.T) {
	t.Parallel()

	_, service, _, _ := startTestServer(t) //nolint:dogsled

	newIdentity := charon.Identity{
		Username: "newuser",
		Email:    "newuser@example.com",
	}

	accountID := identifier.New()
	ctx := service.TestingWithAccountID(context.Background(), accountID)

	errE := service.TestingCreateIdentity(ctx, &newIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	identityID := *newIdentity.ID
	identityRef := charon.IdentityRef{ID: identityID}

	access := service.TestingGetIdentitiesAccess(accountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		identityRef: {{}},
	}, access)

	createdIdentity, isAdmin, errE := service.TestingGetIdentity(ctx, identityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)
	assert.Equal(t, newIdentity.Username, createdIdentity.Username)
	assert.Equal(t, newIdentity.Email, createdIdentity.Email)
	assert.Empty(t, createdIdentity.Users)
	assert.Equal(t, []charon.IdentityRef{identityRef}, createdIdentity.Admins)

	ctx = service.TestingWithIdentityID(ctx, identityID)

	newIdentity = charon.Identity{
		Username: "another",
		Email:    "another@example.com",
	}

	errE = service.TestingCreateIdentity(ctx, &newIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	newIdentityRef := charon.IdentityRef{ID: *newIdentity.ID}

	access = service.TestingGetIdentitiesAccess(accountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		identityRef:    {{}},
		newIdentityRef: {{identityRef}},
	}, access)

	createdIdentity, isAdmin, errE = service.TestingGetIdentity(ctx, *newIdentity.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)
	assert.Equal(t, newIdentity.Username, createdIdentity.Username)
	assert.Equal(t, newIdentity.Email, createdIdentity.Email)
	assert.Empty(t, createdIdentity.Users)
	assert.Contains(t, createdIdentity.Admins, identityRef)

	// Only the first identity has a creator (account), the second not.
	a, ok := service.TestingGetCreatedIdentities(identityRef)
	assert.True(t, ok)
	assert.Equal(t, accountID, a)
	_, ok = service.TestingGetCreatedIdentities(newIdentityRef)
	assert.False(t, ok)
}

func createTestIdentity(t *testing.T, service *charon.Service, ctx context.Context) identifier.Identifier {
	t.Helper()

	newIdentity := charon.Identity{Username: identifier.New().String()}
	errE := service.TestingCreateIdentity(ctx, &newIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)
	return *newIdentity.ID
}

func assertEqualAccess(t *testing.T, expected, actual map[charon.IdentityRef][][]charon.IdentityRef) {
	t.Helper()

	if assert.ElementsMatch(t, mapset.NewThreadUnsafeSetFromMapKeys(expected).ToSlice(), mapset.NewThreadUnsafeSetFromMapKeys(actual).ToSlice()) {
		for id := range expected {
			assert.ElementsMatch(t, expected[id], actual[id], id.ID.String())
		}
	}
}

func TestUpdateIdentity(t *testing.T) {
	t.Parallel()

	_, service, _, _ := startTestServer(t) //nolint:dogsled

	accountID := identifier.New()
	ctx := service.TestingWithAccountID(context.Background(), accountID)

	identityID := createTestIdentity(t, service, ctx)
	createdIdentity, _, errE := service.TestingGetIdentity(ctx, identityID)
	require.NoError(t, errE, "% -+#.1v", errE)

	user1 := createTestIdentity(t, service, ctx)
	user2 := createTestIdentity(t, service, ctx)
	admin1 := createTestIdentity(t, service, ctx)
	admin2 := createTestIdentity(t, service, ctx)

	user1Ref := charon.IdentityRef{ID: user1}
	user2Ref := charon.IdentityRef{ID: user2}
	admin1Ref := charon.IdentityRef{ID: admin1}
	admin2Ref := charon.IdentityRef{ID: admin2}

	newUsers := []charon.IdentityRef{user1Ref, user2Ref}
	newAdmins := []charon.IdentityRef{admin1Ref, admin2Ref}

	createdIdentity.Users = newUsers
	createdIdentity.Admins = newAdmins

	// Changing users and admins is not allowed without identity ID in the context.
	errE = service.TestingUpdateIdentity(ctx, createdIdentity)
	require.ErrorIs(t, errE, charon.ErrIdentityValidationFailed)

	ctx = service.TestingWithIdentityID(ctx, identityID)

	errE = service.TestingUpdateIdentity(ctx, createdIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	updatedIdentity, _, errE := service.TestingGetIdentity(ctx, identityID)
	require.NoError(t, errE)

	identityRef := charon.IdentityRef{ID: identityID}

	// Current identity (in the context) should be automatically added to admins.
	newAdmins = append(newAdmins, identityRef)

	// We check using newUsers and newAdmins because createdIdentity has been
	// changed in-place and always matches updatedIdentity.
	assert.ElementsMatch(t, newUsers, updatedIdentity.Users)
	assert.ElementsMatch(t, newAdmins, updatedIdentity.Admins)

	access := service.TestingGetIdentitiesAccess(accountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		user1Ref:    {{}},
		user2Ref:    {{}},
		admin1Ref:   {{}},
		admin2Ref:   {{}},
		identityRef: {{}, {user1Ref}, {user2Ref}, {admin1Ref}, {admin2Ref}},
	}, access)

	// All identities were created without identity ID in the context and thus have a creator.
	for _, id := range []charon.IdentityRef{user1Ref, user2Ref, admin1Ref, admin2Ref, identityRef} {
		a, ok := service.TestingGetCreatedIdentities(id)
		assert.True(t, ok)
		assert.Equal(t, accountID, a)
	}
}

func TestIdentityAccessControl(t *testing.T) { //nolint:maintidx
	t.Parallel()

	_, service, _, _ := startTestServer(t) //nolint:dogsled

	userAccountID := identifier.New()
	userCtx := service.TestingWithAccountID(context.Background(), userAccountID)

	userIdentityID := createTestIdentity(t, service, userCtx)
	userIdentity, _, errE := service.TestingGetIdentity(userCtx, userIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	userIdentityRef := charon.IdentityRef{ID: userIdentityID}

	adminAccountID := identifier.New()
	adminCtx := service.TestingWithAccountID(context.Background(), adminAccountID)

	adminIdentityID := createTestIdentity(t, service, adminCtx)
	adminIdentityRef := charon.IdentityRef{ID: adminIdentityID}

	access := service.TestingGetIdentitiesAccess(userAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		userIdentityRef: {{}},
	}, access)
	access = service.TestingGetIdentitiesAccess(adminAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		adminIdentityRef: {{}},
	}, access)
	a, ok := service.TestingGetCreatedIdentities(userIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, userAccountID, a)
	a, ok = service.TestingGetCreatedIdentities(adminIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, adminAccountID, a)

	// It is not possible to get the identity of the other.
	_, _, errE = service.TestingGetIdentity(adminCtx, userIdentityID)
	assert.ErrorIs(t, errE, charon.ErrIdentityUnauthorized)
	_, _, errE = service.TestingGetIdentity(userCtx, adminIdentityID)
	assert.ErrorIs(t, errE, charon.ErrIdentityUnauthorized)
	result, errE := service.TestListIdentity(userCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{userIdentityRef}, result)
	result, errE = service.TestListIdentity(adminCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef}, result)

	userIdentity.Admins = append(userIdentity.Admins, adminIdentityRef)
	// Admin cannot add itself.
	errE = service.TestingUpdateIdentity(adminCtx, userIdentity)
	assert.ErrorIs(t, errE, charon.ErrIdentityUnauthorized)
	// User cannot add admin without identity ID in the context.
	errE = service.TestingUpdateIdentity(userCtx, userIdentity)
	assert.ErrorIs(t, errE, charon.ErrIdentityValidationFailed)

	userCtx = service.TestingWithIdentityID(userCtx, userIdentityID)
	// Now the user can add the admin.
	errE = service.TestingUpdateIdentity(userCtx, userIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	access = service.TestingGetIdentitiesAccess(userAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		userIdentityRef: {{}},
	}, access)
	access = service.TestingGetIdentitiesAccess(adminAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		adminIdentityRef: {{}},
		userIdentityRef:  {{adminIdentityRef}},
	}, access)
	a, ok = service.TestingGetCreatedIdentities(userIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, userAccountID, a)
	a, ok = service.TestingGetCreatedIdentities(adminIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, adminAccountID, a)

	// Both should now have access to the user identity.
	_, isAdmin, errE := service.TestingGetIdentity(userCtx, userIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)
	updatedUserIdentity, isAdmin, errE := service.TestingGetIdentity(adminCtx, userIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)
	assert.Contains(t, updatedUserIdentity.Admins, adminIdentityRef)
	result, errE = service.TestListIdentity(userCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{userIdentityRef}, result)
	result, errE = service.TestListIdentity(adminCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef, userIdentityRef}, result)

	// Attempt an update with admin identity.
	newUsername := identifier.New().String()
	updatedUserIdentity.Username = newUsername
	errE = service.TestingUpdateIdentity(adminCtx, updatedUserIdentity)
	require.NoError(t, errE)

	// Re-fetch and verify the update.
	updatedUserIdentity, _, err := service.TestingGetIdentity(userCtx, userIdentityID)
	require.NoError(t, err)
	assert.Equal(t, newUsername, updatedUserIdentity.Username)

	// Remove admin access. By removing all admins, we expect
	// Validate to re-add back the user identity.
	updatedUserIdentity.Admins = nil
	errE = service.TestingUpdateIdentity(userCtx, updatedUserIdentity)
	require.NoError(t, errE)

	access = service.TestingGetIdentitiesAccess(userAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		userIdentityRef: {{}},
	}, access)
	access = service.TestingGetIdentitiesAccess(adminAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		adminIdentityRef: {{}},
	}, access)
	a, ok = service.TestingGetCreatedIdentities(userIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, userAccountID, a)
	a, ok = service.TestingGetCreatedIdentities(adminIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, adminAccountID, a)

	// It is not possible to get the identity of the other anymore.
	_, _, errE = service.TestingGetIdentity(adminCtx, userIdentityID)
	assert.ErrorIs(t, errE, charon.ErrIdentityUnauthorized)
	_, _, errE = service.TestingGetIdentity(userCtx, adminIdentityID)
	assert.ErrorIs(t, errE, charon.ErrIdentityUnauthorized)
	result, errE = service.TestListIdentity(userCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{userIdentityRef}, result)
	result, errE = service.TestListIdentity(adminCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef}, result)

	// Add admin with only user access.
	updatedUserIdentity.Users = append(updatedUserIdentity.Users, adminIdentityRef)
	updatedUserIdentity.Admins = nil
	errE = service.TestingUpdateIdentity(userCtx, updatedUserIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	access = service.TestingGetIdentitiesAccess(userAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		userIdentityRef: {{}},
	}, access)
	access = service.TestingGetIdentitiesAccess(adminAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		adminIdentityRef: {{}},
		userIdentityRef:  {{adminIdentityRef}},
	}, access)
	a, ok = service.TestingGetCreatedIdentities(userIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, userAccountID, a)
	a, ok = service.TestingGetCreatedIdentities(adminIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, adminAccountID, a)

	// Both should now have access to the user identity.
	_, isAdmin, errE = service.TestingGetIdentity(userCtx, userIdentityID)
	assert.True(t, isAdmin)
	require.NoError(t, errE, "% -+#.1v", errE)
	updatedUserIdentity, isAdmin, errE = service.TestingGetIdentity(adminCtx, userIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.False(t, isAdmin)
	assert.Contains(t, updatedUserIdentity.Users, adminIdentityRef)
	result, errE = service.TestListIdentity(userCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{userIdentityRef}, result)
	result, errE = service.TestListIdentity(adminCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef, userIdentityRef}, result)

	// Attempt an update with admin identity should fail now.
	updatedUserIdentity.Username = identifier.New().String()
	errE = service.TestingUpdateIdentity(adminCtx, updatedUserIdentity)
	assert.ErrorIs(t, errE, charon.ErrIdentityUnauthorized)
	// Give admin back admin access. We on purpose list only adminIdentityRef
	// expecting userIdentityRef to be added by the backend.
	updatedUserIdentity.Users = nil
	updatedUserIdentity.Admins = []charon.IdentityRef{adminIdentityRef}
	errE = service.TestingUpdateIdentity(userCtx, updatedUserIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Both should now have admin access to the user identity.
	_, isAdmin, errE = service.TestingGetIdentity(userCtx, userIdentityID)
	assert.True(t, isAdmin)
	require.NoError(t, errE, "% -+#.1v", errE)
	updatedUserIdentity, isAdmin, errE = service.TestingGetIdentity(adminCtx, userIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)
	// userIdentityRef has been added by the backend.
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef, userIdentityRef}, updatedUserIdentity.Admins)
	result, errE = service.TestListIdentity(userCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{userIdentityRef}, result)
	result, errE = service.TestListIdentity(adminCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef, userIdentityRef}, result)

	// Remove access for user identity itself, effectively transferring the identity to admin.
	adminCtx = service.TestingWithIdentityID(adminCtx, adminIdentityID)
	updatedUserIdentity.Admins = []charon.IdentityRef{adminIdentityRef}
	errE = service.TestingUpdateIdentity(adminCtx, updatedUserIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	access = service.TestingGetIdentitiesAccess(userAccountID)
	assert.Equal(t, map[charon.IdentityRef][][]charon.IdentityRef(nil), access)
	access = service.TestingGetIdentitiesAccess(adminAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		adminIdentityRef: {{}},
		userIdentityRef:  {{adminIdentityRef}},
	}, access)
	a, ok = service.TestingGetCreatedIdentities(userIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, userAccountID, a)
	a, ok = service.TestingGetCreatedIdentities(adminIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, adminAccountID, a)

	// Only admin should have access to both identities. User should not have any access anymore.
	_, _, errE = service.TestingGetIdentity(userCtx, userIdentityID)
	assert.ErrorIs(t, errE, charon.ErrIdentityUnauthorized)
	updatedUserIdentity, isAdmin, errE = service.TestingGetIdentity(adminCtx, userIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef}, updatedUserIdentity.Admins)
	result, errE = service.TestListIdentity(userCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Empty(t, result)
	result, errE = service.TestListIdentity(adminCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef, userIdentityRef}, result)

	// Adding user identity to user access does not work.
	updatedUserIdentity.Users = []charon.IdentityRef{userIdentityRef}
	errE = service.TestingUpdateIdentity(adminCtx, updatedUserIdentity)
	require.ErrorIs(t, errE, charon.ErrIdentityValidationFailed)

	// But adding user identity back to admin access works and restores creator's access.
	// Supporting this is important so that we can support undo functionality.
	updatedUserIdentity.Users = nil
	updatedUserIdentity.Admins = []charon.IdentityRef{adminIdentityRef, userIdentityRef}
	errE = service.TestingUpdateIdentity(adminCtx, updatedUserIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Both should now have admin access to the user identity.
	_, isAdmin, errE = service.TestingGetIdentity(userCtx, userIdentityID)
	assert.True(t, isAdmin)
	require.NoError(t, errE, "% -+#.1v", errE)
	updatedUserIdentity, isAdmin, errE = service.TestingGetIdentity(adminCtx, userIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef, userIdentityRef}, updatedUserIdentity.Admins)
	result, errE = service.TestListIdentity(userCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{userIdentityRef}, result)
	result, errE = service.TestListIdentity(adminCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef, userIdentityRef}, result)

	access = service.TestingGetIdentitiesAccess(userAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		userIdentityRef: {{}},
	}, access)
	access = service.TestingGetIdentitiesAccess(adminAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		adminIdentityRef: {{}},
		userIdentityRef:  {{adminIdentityRef}},
	}, access)
	a, ok = service.TestingGetCreatedIdentities(userIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, userAccountID, a)
	a, ok = service.TestingGetCreatedIdentities(adminIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, adminAccountID, a)

	// User creates a third identity, but this time with identity ID in ctx, so is not recorded as its creator.
	thirdIdentityID := createTestIdentity(t, service, userCtx)
	thirdIdentityRef := charon.IdentityRef{ID: thirdIdentityID}

	access = service.TestingGetIdentitiesAccess(userAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		userIdentityRef:  {{}},
		thirdIdentityRef: {{userIdentityRef}},
	}, access)
	access = service.TestingGetIdentitiesAccess(adminAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		adminIdentityRef: {{}},
		userIdentityRef:  {{adminIdentityRef}},
		thirdIdentityRef: {{adminIdentityRef, userIdentityRef}},
	}, access)
	a, ok = service.TestingGetCreatedIdentities(userIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, userAccountID, a)
	a, ok = service.TestingGetCreatedIdentities(adminIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, adminAccountID, a)
	_, ok = service.TestingGetCreatedIdentities(thirdIdentityRef)
	assert.False(t, ok)

	// Both accounts should have admin access to the third identity (because admin account
	// has access to user identity which has admin access to the third identity).
	_, isAdmin, errE = service.TestingGetIdentity(userCtx, thirdIdentityID)
	assert.True(t, isAdmin)
	require.NoError(t, errE, "% -+#.1v", errE)
	thirdIdentity, isAdmin, errE := service.TestingGetIdentity(adminCtx, thirdIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)
	assert.ElementsMatch(t, []charon.IdentityRef{userIdentityRef}, thirdIdentity.Admins)
	result, errE = service.TestListIdentity(userCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{userIdentityRef, thirdIdentityRef}, result)
	result, errE = service.TestListIdentity(adminCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef, userIdentityRef, thirdIdentityRef}, result)

	// We can add identity itself to admin access slice, but nothing changes because the third identity does not have a creator.
	thirdIdentity.Admins = []charon.IdentityRef{userIdentityRef, thirdIdentityRef}
	errE = service.TestingUpdateIdentity(userCtx, thirdIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	access = service.TestingGetIdentitiesAccess(userAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		userIdentityRef:  {{}},
		thirdIdentityRef: {{userIdentityRef}},
	}, access)
	access = service.TestingGetIdentitiesAccess(adminAccountID)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		adminIdentityRef: {{}},
		userIdentityRef:  {{adminIdentityRef}},
		thirdIdentityRef: {{adminIdentityRef, userIdentityRef}},
	}, access)
	a, ok = service.TestingGetCreatedIdentities(userIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, userAccountID, a)
	a, ok = service.TestingGetCreatedIdentities(adminIdentityRef)
	assert.True(t, ok)
	assert.Equal(t, adminAccountID, a)
	_, ok = service.TestingGetCreatedIdentities(thirdIdentityRef)
	assert.False(t, ok)

	// Both accounts should have admin access to the third identity (because admin account
	// has access to user identity which has admin access to the third identity).
	_, isAdmin, errE = service.TestingGetIdentity(userCtx, thirdIdentityID)
	assert.True(t, isAdmin)
	require.NoError(t, errE, "% -+#.1v", errE)
	thirdIdentity, isAdmin, errE = service.TestingGetIdentity(adminCtx, thirdIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)
	assert.ElementsMatch(t, []charon.IdentityRef{userIdentityRef, thirdIdentityRef}, thirdIdentity.Admins)
	result, errE = service.TestListIdentity(userCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{userIdentityRef, thirdIdentityRef}, result)
	result, errE = service.TestListIdentity(adminCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef, userIdentityRef, thirdIdentityRef}, result)
}
