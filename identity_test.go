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

	createdIdentity, isAdmin, errE := service.TestingGetIdentity(ctx, identityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)
	assert.Equal(t, newIdentity.Username, createdIdentity.Username)
	assert.Equal(t, newIdentity.Email, createdIdentity.Email)
	assert.Empty(t, createdIdentity.Users)
	assert.Equal(t, []charon.IdentityRef{identityRef}, createdIdentity.Admins)

	access := service.TestingGetIdentitiesAccess(accountID)
	assert.Equal(t, map[charon.IdentityRef]mapset.Set[charon.IdentityRef]{
		identityRef: mapset.NewThreadUnsafeSet(identityRef),
	}, access)

	ctx = service.TestingWithIdentityID(ctx, identityID)

	newIdentity = charon.Identity{
		Username: "another",
		Email:    "another@example.com",
	}

	errE = service.TestingCreateIdentity(ctx, &newIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	createdIdentity, isAdmin, errE = service.TestingGetIdentity(ctx, *newIdentity.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.True(t, isAdmin)
	assert.Equal(t, newIdentity.Username, createdIdentity.Username)
	assert.Equal(t, newIdentity.Email, createdIdentity.Email)
	assert.Empty(t, createdIdentity.Users)
	assert.Contains(t, createdIdentity.Admins, identityRef)

	access = service.TestingGetIdentitiesAccess(accountID)
	assert.Equal(t, map[charon.IdentityRef]mapset.Set[charon.IdentityRef]{
		identityRef:           mapset.NewThreadUnsafeSet(identityRef),
		{ID: *newIdentity.ID}: mapset.NewThreadUnsafeSet(identityRef),
	}, access)
}
