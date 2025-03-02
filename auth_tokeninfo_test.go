package charon_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/identifier"

	"gitlab.com/charon/charon"
)

func validateIDToken(
	t *testing.T, ts *httptest.Server, service *charon.Service, now time.Time,
	clientID, appID, sessionID, nonce, accessToken, idToken string,
	lastTimestamps map[string]time.Time, identityID identifier.Identifier,
) string {
	t.Helper()

	hash := sha256.Sum256([]byte(accessToken))
	accessTokenHash := base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])

	// TODO: Validate using tokeninfo endpoint when it will be available.

	all := validateJWT(t, ts, service, now, clientID, appID, idToken, identityID)

	for _, claim := range []string{"exp", "iat"} {
		if assert.Contains(t, all, claim) {
			claimTimeFloat, ok := all[claim].(float64)
			if assert.True(t, ok, all[claim]) {
				claimTime := time.Unix(int64(claimTimeFloat), 0)
				if !lastTimestamps[claim].IsZero() {
					// New timestamp should be after the last timestamps.
					assert.True(t, claimTime.After(lastTimestamps[claim]), claim)
				}
				lastTimestamps[claim] = claimTime
			}
			delete(all, claim)
		}
	}

	for _, claim := range []string{"auth_time", "rat"} {
		if assert.Contains(t, all, claim) {
			claimTimeFloat, ok := all[claim].(float64)
			if assert.True(t, ok, all[claim]) {
				claimTime := time.Unix(int64(claimTimeFloat), 0)
				if !lastTimestamps[claim].IsZero() {
					// These timestamps should not change.
					assert.True(t, lastTimestamps[claim].Equal(claimTime), claim)
				}
				lastTimestamps[claim] = claimTime
				// Cannot be in the future.
				assert.False(t, now.Before(claimTime), claim)
			}
			delete(all, claim)
		}
	}

	require.Contains(t, all, "jti")
	jti, ok := all["jti"].(string)
	assert.True(t, ok, all["jti"])
	_, errE := identifier.FromString(jti)
	require.NoError(t, errE, "% -+#.1v", errE)
	delete(all, "jti")

	assert.Equal(t, map[string]interface{}{
		"aud":                []interface{}{clientID},
		"client_id":          clientID,
		"iss":                ts.URL,
		"sid":                sessionID,
		"nonce":              nonce,
		"at_hash":            accessTokenHash,
		"sub":                identityID.String(),
		"email":              "user@example.com",
		"email_verified":     true,
		"given_name":         "User",
		"name":               "User Name",
		"picture":            "https://example.com/picture.png",
		"preferred_username": "username",
	}, all)

	return jti
}
