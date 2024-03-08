package charon_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"

	"gitlab.com/charon/charon"
)

func validateJWT(t *testing.T, ts *httptest.Server, service *charon.Service, now time.Time, leeway time.Duration, clientID, applicationID, token string) map[string]interface{} {
	t.Helper()

	keySet := getKeys(t, ts, service)

	parsedToken, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	// We manually search for the key because fosite does not set kid and we
	// cannot just pass the keySet to token.Claims (it needs kid to match the key).
	// See: https://github.com/ory/fosite/pull/799
	// See: https://github.com/go-jose/go-jose/pull/104
	var key *jose.JSONWebKey
	for _, k := range keySet.Keys {
		k := k
		if k.Algorithm == "RS256" {
			require.Nil(t, key)
			key = &k
		}
	}
	require.NotNil(t, key)

	assert.ElementsMatch(t, []jose.Header{
		{
			// TODO: Uncomment once fosite sets kid.
			//       See: https://github.com/ory/fosite/pull/799
			// KeyID: key.KeyID.
			Algorithm: "RS256",
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				jose.HeaderType: "JWT",
			},
		},
	}, parsedToken.Headers)

	claims := jwt.Claims{}
	all := map[string]interface{}{}
	err = parsedToken.Claims(key, &claims, &all)
	require.NoError(t, err)

	err = claims.ValidateWithLeeway(jwt.Expected{
		// TODO: Check exact value of the subject.
		Subject:     "",
		Issuer:      ts.URL,
		AnyAudience: []string{applicationID, clientID},
		Time:        now,
	}, leeway)
	assert.NoError(t, err, claims)

	return all
}

func validateAccessToken(t *testing.T, ts *httptest.Server, service *charon.Service, clientID, applicationID, accessToken string) string {
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

	oidcIntrospect, errE := service.ReverseAPI("OIDCIntrospect", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	data := url.Values{
		"token":           []string{accessToken},
		"token_type_hint": []string{"access_token"},
		"scope":           []string{"openid offline_access"},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+oidcIntrospect, strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":chc-"+applicationClientSecret)))
	resp, err := ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json;charset=UTF-8", resp.Header.Get("Content-Type"))
	//nolint:tagliatelle
	var response struct {
		Error            string          `json:"error"`
		ErrorDescription string          `json:"error_description"`
		Active           bool            `json:"active"`
		ClientID         string          `json:"client_id"`
		ExpirationTime   jwt.NumericDate `json:"exp"`
		IssueTime        jwt.NumericDate `json:"iat"`
		NotBeforeTime    jwt.NumericDate `json:"nbf"`
		Scope            string          `json:"scope"`
		Subject          string          `json:"sub"`
		Audience         []string        `json:"aud"`
		Issuer           string          `json:"iss"`
		JTI              string          `json:"jti"`
		Session          string          `json:"sid"`
	}
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &response)
	require.NoError(t, errE, "% -+#.1v", errE)

	now := time.Now()

	assert.Empty(t, response.Error)
	assert.Empty(t, response.ErrorDescription)
	assert.True(t, response.Active)
	assert.Equal(t, clientID, response.ClientID)
	assert.WithinDuration(t, now.Add(60*time.Minute), response.ExpirationTime.Time(), leeway)
	assert.WithinDuration(t, now, response.IssueTime.Time(), leeway)
	assert.WithinDuration(t, now, response.NotBeforeTime.Time(), leeway)
	assert.Equal(t, "openid offline_access", response.Scope)
	// TODO: Check exact value of the subject.
	assert.NotEmpty(t, response.Subject)
	assert.Equal(t, []string{applicationID, clientID}, response.Audience)
	assert.Equal(t, ts.URL, response.Issuer)
	// We assert response.JTI at the end.
	assert.Equal(t, session, response.Session)

	all := validateJWT(t, ts, service, now, leeway, clientID, applicationID, accessToken)

	assert.Contains(t, all, "exp")
	delete(all, "exp")
	assert.Contains(t, all, "iat")
	delete(all, "iat")
	assert.Contains(t, all, "nbf")
	delete(all, "nbf")
	require.Contains(t, all, "jti")
	jti, ok := all["jti"].(string)
	assert.True(t, ok, all["jti"])
	_, errE = identifier.FromString(jti)
	assert.NoError(t, errE, "% -+#.1v", errE)
	delete(all, "jti")

	// TODO: Check exact value of the subject.
	assert.NotEmpty(t, all["sub"])
	delete(all, "sub")

	assert.Equal(t, map[string]interface{}{
		"aud":       []interface{}{applicationID, clientID},
		"client_id": clientID,
		"iss":       ts.URL,
		"scope":     "openid offline_access",
		"sid":       session,
	}, all)

	assert.Equal(t, jti, response.JTI)

	return jti
}
