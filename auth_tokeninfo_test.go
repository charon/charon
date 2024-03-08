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

func validateIDToken(t *testing.T, ts *httptest.Server, service *charon.Service, clientID, applicationID, nonce, accessToken, idToken string) {
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

	assert.Contains(t, all, "exp")
	delete(all, "exp")
	assert.Contains(t, all, "iat")
	delete(all, "iat")
	if assert.NotEmpty(t, all["jti"]) {
		_, errE := identifier.FromString(all["jti"].(string))
		assert.NoError(t, errE, "% -+#.1v", errE)
	}
	delete(all, "jti")

	for _, claim := range []string{"auth_time", "rat"} {
		if assert.Contains(t, all, claim) {
			claimTime, ok := all[claim].(float64)
			if assert.True(t, ok) {
				// Cannot be in the future.
				assert.False(t, now.Add(leeway).Before(time.Unix(int64(claimTime), 0)))
			}

			delete(all, claim)
		}
	}

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
}
