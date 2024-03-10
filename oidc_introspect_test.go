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

//nolint:tagliatelle
type introspectAccessTokenResponse struct {
	Error            string          `json:"error"`
	ErrorDescription string          `json:"error_description"`
	Active           bool            `json:"active"`
	ClientID         string          `json:"client_id"`
	ExpirationTime   jwt.NumericDate `json:"exp"`
	IssueTime        jwt.NumericDate `json:"iat"`
	Scope            string          `json:"scope"`
	Subject          string          `json:"sub"`
	Audience         []string        `json:"aud"`
	Issuer           string          `json:"iss"`
	JTI              string          `json:"jti"`
	Session          string          `json:"sid"`
}

//nolint:tagliatelle
type introspectRefreshTokenResponse struct {
	Error            string          `json:"error"`
	ErrorDescription string          `json:"error_description"`
	Active           bool            `json:"active"`
	ExpirationTime   jwt.NumericDate `json:"exp"`
}

func validateJWT(t *testing.T, ts *httptest.Server, service *charon.Service, now time.Time, clientID, applicationID, token string) map[string]interface{} {
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
	}, 0)
	assert.NoError(t, err, claims)

	return all
}

func validateIntrospect(t *testing.T, ts *httptest.Server, service *charon.Service, now time.Time, clientID, applicationID, sessionID, token, typeHint string) *introspectAccessTokenResponse {
	t.Helper()

	oidcIntrospect, errE := service.ReverseAPI("OIDCIntrospect", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	data := url.Values{
		"token":           []string{token},
		"token_type_hint": []string{typeHint},
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

	if typeHint == "refresh_token" {
		var response introspectRefreshTokenResponse
		errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &response)
		require.NoError(t, errE, "% -+#.1v", errE)

		assert.Empty(t, response.Error)
		assert.Empty(t, response.ErrorDescription)
		assert.True(t, response.Active)
		assert.WithinDuration(t, now.Add(30*24*60*time.Minute), response.ExpirationTime.Time().UTC(), 2*time.Second)

		return nil
	}

	var response introspectAccessTokenResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &response)
	require.NoError(t, errE, "% -+#.1v", errE)

	assert.Empty(t, response.Error)
	assert.Empty(t, response.ErrorDescription)
	assert.True(t, response.Active)
	assert.Equal(t, clientID, response.ClientID)
	assert.WithinDuration(t, now.Add(60*time.Minute), response.ExpirationTime.Time().UTC(), 2*time.Second)
	assert.WithinDuration(t, now, response.IssueTime.Time().UTC(), 2*time.Second)
	assert.Equal(t, "openid offline_access", response.Scope)
	// TODO: Check exact value of the subject.
	assert.NotEmpty(t, response.Subject)
	assert.Equal(t, []string{applicationID, clientID}, response.Audience)
	assert.Equal(t, ts.URL, response.Issuer)
	_, errE = identifier.FromString(response.JTI)
	assert.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, sessionID, response.Session)

	return &response
}

func validateNotValidIntrospect(t *testing.T, ts *httptest.Server, service *charon.Service, clientID, token, typeHint string) {
	t.Helper()

	oidcIntrospect, errE := service.ReverseAPI("OIDCIntrospect", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	data := url.Values{
		"token":           []string{token},
		"token_type_hint": []string{typeHint},
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
	var response introspectAccessTokenResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &response)
	require.NoError(t, errE, "% -+#.1v", errE)

	assert.Empty(t, response.Error)
	assert.Empty(t, response.ErrorDescription)
	assert.False(t, response.Active)
}

func validateAccessToken(
	t *testing.T, ts *httptest.Server, service *charon.Service, now time.Time,
	clientID, applicationID, sessionID, accessToken string,
	lastTimestamps map[string]time.Time,
) string {
	t.Helper()
	response := validateIntrospect(t, ts, service, now, clientID, applicationID, sessionID, accessToken, "access_token")

	all := validateJWT(t, ts, service, now, clientID, applicationID, accessToken)

	timestamps := map[string]int64{}

	for _, claim := range []string{"exp", "iat"} {
		if assert.Contains(t, all, claim) {
			claimTimeFloat, ok := all[claim].(float64)
			if assert.True(t, ok, all[claim]) {
				timestamp := int64(claimTimeFloat)
				timestamps[claim] = timestamp
				claimTime := time.Unix(timestamp, 0)
				if !lastTimestamps[claim].IsZero() {
					// New timestamp should be after the last timestamps.
					assert.True(t, claimTime.After(lastTimestamps[claim]), claim)
				}
				lastTimestamps[claim] = claimTime
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
		"aud":       []interface{}{applicationID, clientID},
		"client_id": clientID,
		"iss":       ts.URL,
		"scope":     "openid offline_access",
		"sid":       sessionID,
	}, all)

	assert.Equal(t, jti, response.JTI)
	assert.Equal(t, timestamps["exp"], int64(response.ExpirationTime))
	assert.Equal(t, timestamps["iat"], int64(response.IssueTime))

	return jti
}
