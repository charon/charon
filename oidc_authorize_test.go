package charon_test

import (
	"fmt"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/charon/charon"
	"gitlab.com/tozd/identifier"
)

type testCase struct {
	accessTokenType      charon.AccessTokenType
	accessTokenLifespan  time.Duration
	idTokenLifespan      time.Duration
	refreshTokenLifespan *time.Duration
}

func (t testCase) String() string {
	return fmt.Sprintf("%s-%s-%s-%s", t.accessTokenType, t.accessTokenLifespan, t.idTokenLifespan, t.refreshTokenLifespan)
}

func TestOIDCAuthorizeAndToken(t *testing.T) {
	t.Parallel()

	days30 := time.Hour * 24 * 30

	for _, tt := range []testCase{
		{
			charon.AccessTokenHMAC,
			time.Hour,
			time.Hour,
			&days30,
		},
		{
			charon.AccessTokenJWT,
			time.Hour,
			time.Hour,
			&days30,
		},
		{
			charon.AccessTokenJWT,
			days30,
			days30,
			nil,
		},
	} {
		t.Run(tt.String(), func(t *testing.T) {
			t.Parallel()

			ts, service, _, _, _ := startTestServer(t)

			username := identifier.New().String()

			flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)
			accessToken, _ := signinUser(t, ts, service, username, username, charon.CompletedSignup, flowID, nonce, state, pkceVerifier, config, verifier)

			applicationTemplate := createApplicationTemplate(t, ts, service, accessToken, tt.accessTokenType, tt.accessTokenLifespan, tt.idTokenLifespan, tt.refreshTokenLifespan, []charon.Role{})

			organization := createOrganization(t, ts, service, accessToken, applicationTemplate)

			appID := organization.Applications[0].ID.String()
			clientID := organization.Applications[0].ClientsBackend[0].ID.String()

			accessToken, idToken, refreshToken, identityID, sessionID, now := doOIDCOrganizationFlow(t, ts, service, username, clientID, *organization.ID, tt.accessTokenLifespan, nonce)

			accessTokenLastTimestamps := map[string]time.Time{}
			idTokenLastTimestamps := map[string]time.Time{}
			expectedRoles := []string{}

			uniqueStrings := mapset.NewThreadUnsafeSet[string]()
			assert.True(t, uniqueStrings.Add(validateAccessToken(t, ts, service, now, clientID, appID, organization.ID.String(), sessionID, accessToken, accessTokenLastTimestamps, identityID, tt.accessTokenType, tt.accessTokenLifespan, expectedRoles)))
			assert.True(t, uniqueStrings.Add(validateIDToken(t, ts, service, now, clientID, appID, organization.ID.String(), sessionID, nonce, accessToken, idToken, idTokenLastTimestamps, identityID, expectedRoles)))
			validateIntrospect(t, ts, service, now, clientID, appID, organization.ID.String(), sessionID, refreshToken, "refresh_token", identityID, tt.refreshTokenLifespan)
			validateUserInfo(t, ts, service, accessToken, identityID, expectedRoles)

			// We use assert.WithinDuration with 3 seconds allowed delta, so in 10 iterations every
			// second we should still catch if any timestamp is not progressing as expected.
			for range 10 {
				// We sleep for a second so that all timestamps increase (they are at second granularity).
				time.Sleep(time.Second)

				accessToken, idToken, refreshToken, now = exchangeRefreshTokenForTokens(t, ts, service, clientID, refreshToken, accessToken, tt.accessTokenLifespan)

				assert.True(t, uniqueStrings.Add(validateAccessToken(t, ts, service, now, clientID, appID, organization.ID.String(), sessionID, accessToken, accessTokenLastTimestamps, identityID, tt.accessTokenType, tt.accessTokenLifespan, expectedRoles)))
				assert.True(t, uniqueStrings.Add(validateIDToken(t, ts, service, now, clientID, appID, organization.ID.String(), sessionID, nonce, accessToken, idToken, idTokenLastTimestamps, identityID, expectedRoles)))
				validateIntrospect(t, ts, service, now, clientID, appID, organization.ID.String(), sessionID, refreshToken, "refresh_token", identityID, tt.refreshTokenLifespan)
				validateUserInfo(t, ts, service, accessToken, identityID, expectedRoles)
			}
		})
	}
}

// TestOIDCAuthorizeCopiesAllowedProvidersIntoFlow verifies that OIDCAuthorizeGet copies
// the organization's AllowedProviders into the newly created flow. The flow snapshots
// the policy at authorize time, so changes to the org afterwards should not affect the
// in-progress flow (the snapshot is what matters).
func TestOIDCAuthorizeCopiesAllowedProvidersIntoFlow(t *testing.T) {
	t.Parallel()

	ts, service, _, _, _ := startTestServer(t) //nolint:dogsled

	// Mutate the Charon dashboard organization (which is what createAuthFlow uses) to
	// have an explicit allowed-provider list. We bypass the admin check by writing
	// directly to storage.
	charonOrgID := service.TestingCharonOrganizationID()
	org, errE := service.TestingGetOrganization(t.Context(), charonOrgID)
	require.NoError(t, errE, "% -+#.1v", errE)
	org.AllowedProviders = []charon.Provider{charon.ProviderEmail, charon.ProviderPassword, charon.ProviderUsername}
	errE = service.TestingStoreOrganization(org)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Run an OIDC authorize. createAuthFlow goes through OIDCAuthorizeGet end-to-end.
	flowID, _, _, _, _, _ := createAuthFlow(t, ts, service) //nolint:dogsled

	// The flow must have inherited AllowedProviders from the organization.
	f, errE := service.TestingGetFlow(t.Context(), flowID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, []charon.Provider{charon.ProviderEmail, charon.ProviderPassword, charon.ProviderUsername}, f.AllowedProviders)

	// Changing the org after the flow exists must not retroactively change the flow.
	org.AllowedProviders = []charon.Provider{}
	errE = service.TestingStoreOrganization(org)
	require.NoError(t, errE, "% -+#.1v", errE)

	f, errE = service.TestingGetFlow(t.Context(), flowID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, []charon.Provider{charon.ProviderEmail, charon.ProviderPassword, charon.ProviderUsername}, f.AllowedProviders)
}
