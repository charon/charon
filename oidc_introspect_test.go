package charon_test

import (
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
	"gitlab.com/charon/charon"
	"gitlab.com/tozd/go/x"
)

func validateAccessToken(t *testing.T, ts *httptest.Server, service *charon.Service, clientID, applicationID, accessToken string) {
	t.Helper()

	const leeway = time.Minute

	oidcIntrospect, errE := service.ReverseAPI("OIDCIntrospect", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	data := url.Values{
		"token":           []string{accessToken},
		"token_type_hint": []string{"access_token"},
		"scope":           []string{"openid"},
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+oidcIntrospect, strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":chc-"+applicationClientSecret)))
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json;charset=UTF-8", resp.Header.Get("Content-Type"))
	//nolint:tagliatelle
	var response struct {
		Error            string   `json:"error"`
		ErrorDescription string   `json:"error_description"`
		Active           bool     `json:"active"`
		ClientID         string   `json:"client_id"`
		ExpirationTime   int      `json:"exp"`
		IssueTime        int      `json:"iat"`
		Scope            string   `json:"scope"`
		Subject          string   `json:"sub"`
		Audience         []string `json:"aud"`
	}
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &response)
	require.NoError(t, errE, "% -+#.1v", errE)

	now := time.Now()

	assert.Empty(t, response.Error)
	assert.Empty(t, response.ErrorDescription)
	assert.True(t, response.Active)
	assert.Equal(t, clientID, response.ClientID)
	assert.InDelta(t, now.Unix()+int64((60*time.Minute).Seconds()), response.ExpirationTime, leeway.Seconds())
	assert.InDelta(t, now.Unix(), response.IssueTime, leeway.Seconds())
	assert.Equal(t, "openid", response.Scope)
	// TODO: Check exact value of the subject.
	assert.NotEmpty(t, response.Subject)
	assert.Equal(t, []string{applicationID}, response.Audience)

	keySet := getKeys(t, ts, service)

	token, err := jwt.ParseSigned(accessToken, []jose.SignatureAlgorithm{jose.RS256})
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
	}, token.Headers)

	claims := jwt.Claims{}
	all := map[string]interface{}{}
	err = token.Claims(key, &claims, &all)
	require.NoError(t, err)

	err = claims.ValidateWithLeeway(jwt.Expected{
		// TODO: Check exact value of the subject.
		Subject:     "",
		Issuer:      ts.URL,
		AnyAudience: []string{applicationID},
		Time:        now,
	}, leeway)
	assert.NoError(t, err, claims)

	assert.Contains(t, all, "exp")
	delete(all, "exp")
	assert.Contains(t, all, "iat")
	delete(all, "iat")
	assert.Contains(t, all, "jti")
	delete(all, "jti")

	// TODO: Check exact value of the subject.
	delete(all, "sub")

	assert.Equal(t, map[string]interface{}{
		"aud":       []interface{}{applicationID},
		"client_id": clientID,
		"iss":       ts.URL,
		"scope":     "openid",
	}, all)
}
