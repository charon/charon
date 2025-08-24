package charon_test

import (
	"context"
	"slices"
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
		IdentityPublic: charon.IdentityPublic{
			Username: "newuser",
			Email:    "newuser@example.com",
		},
	}

	accountID := identifier.New()
	ctx := service.TestingWithAccountID(context.Background(), accountID)
	ctx = service.TestingWithSessionID(ctx)
	ctx = service.TestingWithRequestID(ctx)

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
		IdentityPublic: charon.IdentityPublic{
			Username: "another",
			Email:    "another@example.com",
		},
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

func createTestIdentity(t *testing.T, service *charon.Service, ctx context.Context) identifier.Identifier { //nolint:revive
	t.Helper()

	newIdentity := charon.Identity{IdentityPublic: charon.IdentityPublic{Username: identifier.New().String()}}
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
	ctx = service.TestingWithSessionID(ctx)
	ctx = service.TestingWithRequestID(ctx)

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
	require.NoError(t, errE, "% -+#.1v", errE)

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
	userCtx = service.TestingWithSessionID(userCtx)
	userCtx = service.TestingWithRequestID(userCtx)

	userIdentityID := createTestIdentity(t, service, userCtx)
	userIdentity, _, errE := service.TestingGetIdentity(userCtx, userIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	userIdentityRef := charon.IdentityRef{ID: userIdentityID}

	adminAccountID := identifier.New()
	adminCtx := service.TestingWithAccountID(context.Background(), adminAccountID)
	adminCtx = service.TestingWithSessionID(adminCtx)
	adminCtx = service.TestingWithRequestID(adminCtx)

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

	// Update of admin identity itself should be allowed without identity ID in the context.
	newUsername := identifier.New().String()
	updatedAdminIdentity, _, errE := service.TestingGetIdentity(adminCtx, adminIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	updatedAdminIdentity.Username = newUsername
	errE = service.TestingUpdateIdentity(adminCtx, updatedAdminIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Re-fetch and verify the update.
	updatedAdminIdentity, _, errE = service.TestingGetIdentity(adminCtx, adminIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, newUsername, updatedAdminIdentity.Username)

	// Attempt an update of user identity with admin identity should not be allowed without identity ID in the context.
	newUsername = identifier.New().String()
	updatedUserIdentity.Username = newUsername
	errE = service.TestingUpdateIdentity(adminCtx, updatedUserIdentity)
	assert.ErrorIs(t, errE, charon.ErrIdentityUpdateNotAllowed)

	// Retry with identity ID in the context.
	adminCtx = service.TestingWithIdentityID(adminCtx, adminIdentityID)
	errE = service.TestingUpdateIdentity(adminCtx, updatedUserIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Re-fetch and verify the update.
	updatedUserIdentity, _, errE = service.TestingGetIdentity(userCtx, userIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, newUsername, updatedUserIdentity.Username)

	// Remove admin access. By removing all admins, we expect
	// Validate to re-add back the user identity.
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

	// Adding user identity to user access.
	updatedUserIdentity.Users = []charon.IdentityRef{userIdentityRef}
	errE = service.TestingUpdateIdentity(adminCtx, updatedUserIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	_, isAdmin, errE = service.TestingGetIdentity(userCtx, userIdentityID)
	assert.False(t, isAdmin)
	require.NoError(t, errE, "% -+#.1v", errE)
	updatedUserIdentity, isAdmin, errE = service.TestingGetIdentity(adminCtx, userIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)
	assert.ElementsMatch(t, []charon.IdentityRef{userIdentityRef}, updatedUserIdentity.Users)
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef}, updatedUserIdentity.Admins)
	result, errE = service.TestListIdentity(userCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{userIdentityRef}, result)
	result, errE = service.TestListIdentity(adminCtx)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.ElementsMatch(t, []charon.IdentityRef{adminIdentityRef, userIdentityRef}, result)

	// Adding user identity back to admin access works and restores creator's access.
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

type testIdentity struct {
	ctx     context.Context //nolint:containedctx
	account identifier.Identifier
	id      charon.IdentityRef
}

func setupIdentityHierarchy(t *testing.T, service *charon.Service) []testIdentity {
	t.Helper()

	accountID := identifier.New()
	ctxRoot := service.TestingWithAccountID(context.Background(), accountID)
	ctxRoot = service.TestingWithSessionID(ctxRoot)
	ctxRoot = service.TestingWithRequestID(ctxRoot)
	rootIdentityID := createTestIdentity(t, service, ctxRoot)
	rootIdentityRef := charon.IdentityRef{ID: rootIdentityID}
	ctxRoot = service.TestingWithIdentityID(ctxRoot, rootIdentityID)

	accountID1 := identifier.New()
	ctx1 := service.TestingWithAccountID(context.Background(), accountID1)
	ctx1 = service.TestingWithSessionID(ctx1)
	ctx1 = service.TestingWithRequestID(ctx1)
	child1IdentityID := createTestIdentity(t, service, ctx1)
	ctx1 = service.TestingWithIdentityID(ctx1, child1IdentityID)

	accountID2 := identifier.New()
	ctx2 := service.TestingWithAccountID(context.Background(), accountID2)
	ctx2 = service.TestingWithSessionID(ctx2)
	ctx2 = service.TestingWithRequestID(ctx2)
	child2IdentityID := createTestIdentity(t, service, ctx2)
	ctx2 = service.TestingWithIdentityID(ctx2, child2IdentityID)

	child1Identity, isAdmin, errE := service.TestingGetIdentity(ctx1, child1IdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)

	child2Identity, isAdmin, errE := service.TestingGetIdentity(ctx2, child2IdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)

	// Grant root identity admin access to child identities.
	child1Identity.Admins = append(child1Identity.Admins, rootIdentityRef)
	child2Identity.Admins = append(child2Identity.Admins, rootIdentityRef)

	errE = service.TestingUpdateIdentity(ctx1, child1Identity)
	require.NoError(t, errE, "% -+#.1v", errE)
	errE = service.TestingUpdateIdentity(ctx2, child2Identity)
	require.NoError(t, errE, "% -+#.1v", errE)

	return []testIdentity{
		{
			ctx:     ctxRoot,
			account: accountID,
			id:      rootIdentityRef,
		},
		{
			ctx:     ctx1,
			account: accountID1,
			id:      charon.IdentityRef{ID: child1IdentityID},
		},
		{
			ctx:     ctx2,
			account: accountID2,
			id:      charon.IdentityRef{ID: child2IdentityID},
		},
	}
}

func TestRecursiveIdentityAccess(t *testing.T) {
	t.Parallel()

	_, service, _, _ := startTestServer(t) //nolint:dogsled

	ids := setupIdentityHierarchy(t, service)

	// Test access recursion.
	for _, id := range ids {
		_, isAdmin, errE := service.TestingGetIdentity(ids[0].ctx, id.id.ID)
		require.NoError(t, errE, "% -+#.1v", errE)
		require.True(t, isAdmin)
	}

	// Children do not have access to the root identity.
	for _, id := range ids[1:] {
		_, _, errE := service.TestingGetIdentity(id.ctx, ids[0].id.ID)
		assert.ErrorIs(t, errE, charon.ErrIdentityUnauthorized)
	}

	access := service.TestingGetIdentitiesAccess(ids[0].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[0].id: {{}},
		ids[1].id: {{ids[0].id}},
		ids[2].id: {{ids[0].id}},
	}, access)
	access = service.TestingGetIdentitiesAccess(ids[1].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[1].id: {{}},
	}, access)
	access = service.TestingGetIdentitiesAccess(ids[2].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[2].id: {{}},
	}, access)

	for _, id := range ids {
		a, ok := service.TestingGetCreatedIdentities(id.id)
		assert.True(t, ok)
		assert.Equal(t, id.account, a)
	}
}

func TestCyclicIdentityAccess(t *testing.T) {
	t.Parallel()

	_, service, _, _ := startTestServer(t) //nolint:dogsled

	ids := setupIdentityHierarchy(t, service)

	// Introducing cycle: make child identity admin over the root.
	updatedRootIdentity, _, errE := service.TestingGetIdentity(ids[0].ctx, ids[0].id.ID)
	require.NoError(t, errE, "% -+#.1v", errE)

	updatedRootIdentity.Admins = append(updatedRootIdentity.Admins, ids[1].id)
	errE = service.TestingUpdateIdentity(ids[0].ctx, updatedRootIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	access := service.TestingGetIdentitiesAccess(ids[0].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[0].id: {{}},
		ids[1].id: {{ids[0].id}},
		ids[2].id: {{ids[0].id}},
	}, access)
	access = service.TestingGetIdentitiesAccess(ids[1].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[0].id: {{ids[1].id}},
		ids[1].id: {{}},
		ids[2].id: {{ids[1].id, ids[0].id}},
	}, access)
	access = service.TestingGetIdentitiesAccess(ids[2].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[2].id: {{}},
	}, access)

	for _, id := range ids {
		a, ok := service.TestingGetCreatedIdentities(id.id)
		assert.True(t, ok)
		assert.Equal(t, id.account, a)
	}

	// Child identity should have admin access to the root identity.
	_, isAdmin, errE := service.TestingGetIdentity(ids[1].ctx, ids[0].id.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)

	// We remove creator's access to the root identity.
	updatedRootIdentity.Admins = []charon.IdentityRef{ids[1].id}
	errE = service.TestingUpdateIdentity(ids[1].ctx, updatedRootIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	access = service.TestingGetIdentitiesAccess(ids[0].account)
	assert.Equal(t, map[charon.IdentityRef][][]charon.IdentityRef(nil), access)
	access = service.TestingGetIdentitiesAccess(ids[1].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[0].id: {{ids[1].id}},
		ids[1].id: {{}},
		ids[2].id: {{ids[1].id, ids[0].id}},
	}, access)
	access = service.TestingGetIdentitiesAccess(ids[2].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[2].id: {{}},
	}, access)

	// Child identity has access to all identities.
	for _, id := range ids {
		_, isAdmin, errE = service.TestingGetIdentity(ids[1].ctx, id.id.ID)
		require.NoError(t, errE, "% -+#.1v", errE)
		require.True(t, isAdmin)
	}

	// Root identity does not have access to any identity.
	for _, id := range ids {
		_, _, errE = service.TestingGetIdentity(ids[0].ctx, id.id.ID)
		assert.ErrorIs(t, errE, charon.ErrIdentityUnauthorized)
	}

	// We restore creator's access to the root identity.
	updatedRootIdentity.Admins = []charon.IdentityRef{ids[1].id, ids[0].id}
	errE = service.TestingUpdateIdentity(ids[1].ctx, updatedRootIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	access = service.TestingGetIdentitiesAccess(ids[0].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[0].id: {{}},
		ids[1].id: {{ids[0].id}},
		ids[2].id: {{ids[0].id}},
	}, access)
	access = service.TestingGetIdentitiesAccess(ids[1].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[0].id: {{ids[1].id}},
		ids[1].id: {{}},
		ids[2].id: {{ids[1].id, ids[0].id}},
	}, access)
	access = service.TestingGetIdentitiesAccess(ids[2].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[2].id: {{}},
	}, access)

	// Another cycle: making another child identity admin over the root identity.
	updatedRootIdentity.Admins = []charon.IdentityRef{ids[1].id, ids[0].id, ids[2].id}
	errE = service.TestingUpdateIdentity(ids[0].ctx, updatedRootIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	access = service.TestingGetIdentitiesAccess(ids[0].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[0].id: {{}},
		ids[1].id: {{ids[0].id}},
		ids[2].id: {{ids[0].id}},
	}, access)
	access = service.TestingGetIdentitiesAccess(ids[1].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[0].id: {{ids[1].id}},
		ids[1].id: {{}},
		ids[2].id: {{ids[1].id, ids[0].id}},
	}, access)
	access = service.TestingGetIdentitiesAccess(ids[2].account)
	assertEqualAccess(t, map[charon.IdentityRef][][]charon.IdentityRef{
		ids[0].id: {{ids[2].id}},
		ids[1].id: {{ids[2].id, ids[0].id}},
		ids[2].id: {{}},
	}, access)
}

func TestIdentityChanges(t *testing.T) { //nolint:maintidx
	t.Parallel()

	identityID := identifier.New()
	identity1ID := identifier.New()
	identity2ID := identifier.New()
	identity3ID := identifier.New()
	org1ID := identifier.New()
	org2ID := identifier.New()
	app1ID := identifier.New()
	app2ID := identifier.New()

	tests := []struct {
		name               string
		existing           *charon.Identity
		updated            *charon.Identity
		expectedChanges    []charon.ActivityChangeType
		expectedIdentities []charon.IdentityRef
		expectedOrgs       []charon.OrganizationRef
		expectedApps       []charon.OrganizationApplicationRef
	}{
		{
			name: "no changes",
			existing: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
					Email:    "test@example.com",
				},
				Description: "Test description",
				Users:       []charon.IdentityRef{{ID: identity1ID}},
				Admins:      []charon.IdentityRef{{ID: identity2ID}},
				Organizations: []charon.IdentityOrganization{
					{
						Organization: charon.OrganizationRef{ID: org1ID},
						Active:       true,
						Applications: []charon.OrganizationApplicationApplicationRef{{ID: app1ID}},
					},
				},
			},
			updated: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
					Email:    "test@example.com",
				},
				Description: "Test description",
				Users:       []charon.IdentityRef{{ID: identity1ID}},
				Admins:      []charon.IdentityRef{{ID: identity2ID}},
				Organizations: []charon.IdentityOrganization{
					{
						Organization: charon.OrganizationRef{ID: org1ID},
						Active:       true,
						Applications: []charon.OrganizationApplicationApplicationRef{{ID: app1ID}},
					},
				},
			},
			expectedChanges:    []charon.ActivityChangeType{},
			expectedIdentities: []charon.IdentityRef{},
			expectedOrgs:       []charon.OrganizationRef{},
			expectedApps:       []charon.OrganizationApplicationRef{},
		},
		{
			name: "username changed",
			existing: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
					Email:    "test@example.com",
				},
				Description: "Old description",
			},
			updated: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "newuser",
					Email:    "test@example.com",
				},
				Description: "Old description",
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeOtherData},
			expectedIdentities: []charon.IdentityRef{},
			expectedOrgs:       []charon.OrganizationRef{},
			expectedApps:       []charon.OrganizationApplicationRef{},
		},
		{
			name: "description changed",
			existing: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
					Email:    "test@example.com",
				},
				Description: "Old description",
			},
			updated: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
					Email:    "test@example.com",
				},
				Description: "New description",
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeOtherData},
			expectedIdentities: []charon.IdentityRef{},
			expectedOrgs:       []charon.OrganizationRef{},
			expectedApps:       []charon.OrganizationApplicationRef{},
		},
		{
			name: "admin added",
			existing: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Users:  []charon.IdentityRef{{ID: identity1ID}},
				Admins: []charon.IdentityRef{},
			},
			updated: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Users:  []charon.IdentityRef{{ID: identity1ID}},
				Admins: []charon.IdentityRef{{ID: identity2ID}},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangePermissionsAdded},
			expectedIdentities: []charon.IdentityRef{{ID: identity2ID}},
			expectedOrgs:       []charon.OrganizationRef{},
			expectedApps:       []charon.OrganizationApplicationRef{},
		},
		{
			name: "user added",
			existing: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Users:  []charon.IdentityRef{{ID: identity1ID}},
				Admins: []charon.IdentityRef{},
			},
			updated: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Users:  []charon.IdentityRef{{ID: identity1ID}, {ID: identity3ID}},
				Admins: []charon.IdentityRef{},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangePermissionsAdded},
			expectedIdentities: []charon.IdentityRef{{ID: identity3ID}},
			expectedOrgs:       []charon.OrganizationRef{},
			expectedApps:       []charon.OrganizationApplicationRef{},
		},
		{
			name: "admin removed",
			existing: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Users:  []charon.IdentityRef{{ID: identity1ID}},
				Admins: []charon.IdentityRef{{ID: identity2ID}},
			},
			updated: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Users:  []charon.IdentityRef{{ID: identity1ID}},
				Admins: []charon.IdentityRef{},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangePermissionsRemoved},
			expectedIdentities: []charon.IdentityRef{{ID: identity2ID}},
			expectedOrgs:       []charon.OrganizationRef{},
			expectedApps:       []charon.OrganizationApplicationRef{},
		},
		{
			name: "organization membership added",
			existing: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Organizations: []charon.IdentityOrganization{},
			},
			updated: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Organizations: []charon.IdentityOrganization{
					{
						Organization: charon.OrganizationRef{ID: org1ID},
						Active:       true,
						Applications: []charon.OrganizationApplicationApplicationRef{{ID: app1ID}},
					},
				},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded},
			expectedIdentities: []charon.IdentityRef{},
			expectedOrgs:       []charon.OrganizationRef{{ID: org1ID}},
			expectedApps: []charon.OrganizationApplicationRef{
				{
					Organization: charon.OrganizationRef{ID: org1ID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app1ID},
				},
			},
		},
		{
			name: "organization membership removed",
			existing: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Organizations: []charon.IdentityOrganization{
					{
						Organization: charon.OrganizationRef{ID: org1ID},
						Active:       true,
						Applications: []charon.OrganizationApplicationApplicationRef{{ID: app1ID}},
					},
				},
			},
			updated: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Organizations: []charon.IdentityOrganization{},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeMembershipRemoved},
			expectedIdentities: []charon.IdentityRef{},
			expectedOrgs:       []charon.OrganizationRef{{ID: org1ID}},
			expectedApps: []charon.OrganizationApplicationRef{
				{
					Organization: charon.OrganizationRef{ID: org1ID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app1ID},
				},
			},
		},
		{
			name: "organization membership activated",
			existing: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Organizations: []charon.IdentityOrganization{
					{
						Organization: charon.OrganizationRef{ID: org1ID},
						Active:       false,
						Applications: []charon.OrganizationApplicationApplicationRef{{ID: app1ID}},
					},
				},
			},
			updated: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Organizations: []charon.IdentityOrganization{
					{
						Organization: charon.OrganizationRef{ID: org1ID},
						Active:       true,
						Applications: []charon.OrganizationApplicationApplicationRef{{ID: app1ID}},
					},
				},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeMembershipActivated},
			expectedIdentities: []charon.IdentityRef{},
			expectedOrgs:       []charon.OrganizationRef{{ID: org1ID}},
			expectedApps:       []charon.OrganizationApplicationRef{},
		},
		{
			name: "organization membership disabled",
			existing: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Organizations: []charon.IdentityOrganization{
					{
						Organization: charon.OrganizationRef{ID: org1ID},
						Active:       true,
						Applications: []charon.OrganizationApplicationApplicationRef{{ID: app1ID}},
					},
				},
			},
			updated: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Organizations: []charon.IdentityOrganization{
					{
						Organization: charon.OrganizationRef{ID: org1ID},
						Active:       false,
						Applications: []charon.OrganizationApplicationApplicationRef{{ID: app1ID}},
					},
				},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeMembershipDisabled},
			expectedIdentities: []charon.IdentityRef{},
			expectedOrgs:       []charon.OrganizationRef{{ID: org1ID}},
			expectedApps:       []charon.OrganizationApplicationRef{},
		},
		{
			name: "application membership added",
			existing: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Organizations: []charon.IdentityOrganization{
					{
						Organization: charon.OrganizationRef{ID: org1ID},
						Active:       true,
						Applications: []charon.OrganizationApplicationApplicationRef{{ID: app1ID}},
					},
				},
			},
			updated: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
				},
				Organizations: []charon.IdentityOrganization{
					{
						Organization: charon.OrganizationRef{ID: org1ID},
						Active:       true,
						Applications: []charon.OrganizationApplicationApplicationRef{{ID: app1ID}, {ID: app2ID}},
					},
				},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded},
			expectedIdentities: []charon.IdentityRef{},
			expectedOrgs:       []charon.OrganizationRef{},
			expectedApps: []charon.OrganizationApplicationRef{
				{
					Organization: charon.OrganizationRef{ID: org1ID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app2ID},
				},
			},
		},
		{
			name: "complex scenario with multiple changes",
			existing: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "testuser",
					Email:    "old@example.com",
				},
				Description: "Old description",
				Users:       []charon.IdentityRef{{ID: identity1ID}},
				Admins:      []charon.IdentityRef{{ID: identity2ID}},
				Organizations: []charon.IdentityOrganization{
					{
						Organization: charon.OrganizationRef{ID: org1ID},
						Active:       false,
						Applications: []charon.OrganizationApplicationApplicationRef{{ID: app1ID}},
					},
				},
			},
			updated: &charon.Identity{
				IdentityPublic: charon.IdentityPublic{
					ID:       &identityID,
					Username: "newuser",
					Email:    "new@example.com",
				},
				Description: "New description",
				Users:       []charon.IdentityRef{{ID: identity3ID}},
				Admins:      []charon.IdentityRef{{ID: identity2ID}},
				Organizations: []charon.IdentityOrganization{
					{
						Organization: charon.OrganizationRef{ID: org1ID},
						Active:       true,
						Applications: []charon.OrganizationApplicationApplicationRef{{ID: app1ID}, {ID: app2ID}},
					},
					{
						Organization: charon.OrganizationRef{ID: org2ID},
						Active:       true,
						Applications: []charon.OrganizationApplicationApplicationRef{{ID: app1ID}},
					},
				},
			},
			expectedChanges: []charon.ActivityChangeType{
				charon.ActivityChangeOtherData,
				charon.ActivityChangePermissionsAdded,
				charon.ActivityChangePermissionsRemoved,
				charon.ActivityChangeMembershipAdded,
				charon.ActivityChangeMembershipActivated,
			},
			expectedIdentities: []charon.IdentityRef{{ID: identity1ID}, {ID: identity3ID}},
			expectedOrgs:       []charon.OrganizationRef{{ID: org1ID}, {ID: org2ID}},
			expectedApps: []charon.OrganizationApplicationRef{
				{
					Organization: charon.OrganizationRef{ID: org1ID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app2ID},
				},
				{
					Organization: charon.OrganizationRef{ID: org2ID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app1ID},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			changes, identities, orgs, apps := tt.updated.Changes(tt.existing)

			// Sort expected slices to match deterministic ordering from Changes method.
			slices.SortFunc(tt.expectedIdentities, charon.TestingIdentityRefCmp)
			slices.SortFunc(tt.expectedOrgs, charon.TestingOrganizationRefCmp)
			slices.SortFunc(tt.expectedApps, charon.TestingOrganizationApplicationRefCmp)

			// Check all expected outputs with deterministic ordering.
			assert.Equal(t, tt.expectedChanges, changes, "Changes mismatch")
			assert.Equal(t, tt.expectedIdentities, identities, "Identities mismatch")
			assert.Equal(t, tt.expectedOrgs, orgs, "Organizations mismatch")
			assert.Equal(t, tt.expectedApps, apps, "Applications mismatch")
		})
	}
}
