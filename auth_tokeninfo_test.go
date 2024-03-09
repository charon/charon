package charon_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/identifier"

	"gitlab.com/charon/charon"
)

func validateIDToken(
	t *testing.T, ts *httptest.Server, service *charon.Service,
	clientID, applicationID, nonce, accessToken, idToken string,
	lastTimestamps map[string]time.Time,
) string {
	t.Helper()

	const leeway = time.Minute

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	cookies := ts.Client().Jar.Cookies(u)

	var session string
	for _, cookie := range cookies {
		if cookie.Name == charon.SessionCookieName {
			session = cookie.Value
			break
		}
	}
	require.NotEmpty(t, session)

	hash := sha256.Sum256([]byte(accessToken))
	accessTokenHash := base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])

	// TODO: Validate using tokeninfo endpoint when it will be available.

	now := time.Now()

	all := validateJWT(t, ts, service, now, leeway, clientID, applicationID, idToken)

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
				assert.False(t, now.Add(leeway).Before(claimTime), claim)
			}
			delete(all, claim)
		}
	}

	require.Contains(t, all, "jti")
	jti, ok := all["jti"].(string)
	assert.True(t, ok, all["jti"])
	_, errE := identifier.FromString(jti)
	assert.NoError(t, errE, "% -+#.1v", errE)
	delete(all, "jti")

	// TODO: Check exact value of the subject.
	assert.NotEmpty(t, all["sub"])
	delete(all, "sub")

	assert.Equal(t, map[string]interface{}{
		"aud":       []interface{}{clientID},
		"client_id": clientID,
		"iss":       ts.URL,
		"sid":       session,
		"nonce":     nonce,
		"at_hash":   accessTokenHash,
	}, all)

	return jti
}
