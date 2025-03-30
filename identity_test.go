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
	assert.Equal(t, map[charon.IdentityRef]mapset.Set[charon.IdentityRef]{
		identityRef: mapset.NewThreadUnsafeSet(identityRef),
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

	access = service.TestingGetIdentitiesAccess(accountID)
	assert.Equal(t, map[charon.IdentityRef]mapset.Set[charon.IdentityRef]{
		identityRef:           mapset.NewThreadUnsafeSet(identityRef),
		{ID: *newIdentity.ID}: mapset.NewThreadUnsafeSet(identityRef),
	}, access)

	createdIdentity, isAdmin, errE = service.TestingGetIdentity(ctx, *newIdentity.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)
	assert.Equal(t, newIdentity.Username, createdIdentity.Username)
	assert.Equal(t, newIdentity.Email, createdIdentity.Email)
	assert.Empty(t, createdIdentity.Users)
	assert.Contains(t, createdIdentity.Admins, identityRef)
}

func createTestIdentity(t *testing.T, service *charon.Service, ctx context.Context) identifier.Identifier {
	t.Helper()

	newIdentity := charon.Identity{Username: identifier.New().String()}
	errE := service.TestingCreateIdentity(ctx, &newIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)
	return *newIdentity.ID
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

	newUsers := []charon.IdentityRef{{ID: user1}, {ID: user2}}
	newAdmins := []charon.IdentityRef{{ID: admin1}, {ID: admin2}}

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
	assert.Equal(t, map[charon.IdentityRef]mapset.Set[charon.IdentityRef]{
		identityRef: mapset.NewThreadUnsafeSet(
			identityRef,
			charon.IdentityRef{ID: user1},
			charon.IdentityRef{ID: user2},
			charon.IdentityRef{ID: admin1},
			charon.IdentityRef{ID: admin2},
		),
		{ID: user1}:  mapset.NewThreadUnsafeSet(charon.IdentityRef{ID: user1}),
		{ID: user2}:  mapset.NewThreadUnsafeSet(charon.IdentityRef{ID: user2}),
		{ID: admin1}: mapset.NewThreadUnsafeSet(charon.IdentityRef{ID: admin1}),
		{ID: admin2}: mapset.NewThreadUnsafeSet(charon.IdentityRef{ID: admin2}),
	}, access)
}
}
