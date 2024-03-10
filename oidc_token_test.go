package charon_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/tozd/go/x"

	"gitlab.com/charon/charon"
)

func exchangeCodeForTokens(t *testing.T, ts *httptest.Server, service *charon.Service, clientID, code, codeVerifier string) (string, string, string, time.Time) {
	t.Helper()

	oidcToken, errE := service.ReverseAPI("OIDCToken", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	data := url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{"chc-" + applicationClientSecret},
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"code_verifier": []string{codeVerifier},
		"redirect_uri":  []string{"https://example.com/redirect"},
	}

	resp, err := ts.Client().Post(ts.URL+oidcToken, "application/x-www-form-urlencoded", strings.NewReader(data.Encode())) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json;charset=UTF-8", resp.Header.Get("Content-Type"))

	now := time.Now().UTC()

	//nolint:tagliatelle
	var response struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
	}
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &response)
	require.NoError(t, errE, "% -+#.1v", errE)

	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IDToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.InDelta(t, 3599, response.ExpiresIn, 1)
	assert.Equal(t, "openid offline_access", response.Scope)
	assert.Equal(t, "bearer", response.TokenType)

	return response.AccessToken, response.IDToken, response.RefreshToken, now
}

func exchangeRefreshTokenForTokens(t *testing.T, ts *httptest.Server, service *charon.Service, clientID, refreshToken, accessToken string) (string, string, string, time.Time) {
	t.Helper()

	oidcToken, errE := service.ReverseAPI("OIDCToken", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	data := url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{"chc-" + applicationClientSecret},
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{refreshToken},
		// "redirect_uri":  []string{"https://example.com/redirect"},
	}

	resp, err := ts.Client().Post(ts.URL+oidcToken, "application/x-www-form-urlencoded", strings.NewReader(data.Encode())) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json;charset=UTF-8", resp.Header.Get("Content-Type"))

	now := time.Now().UTC()

	//nolint:tagliatelle
	var response struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
	}
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &response)
	require.NoError(t, errE, "% -+#.1v", errE)

	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IDToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.InDelta(t, 3599, response.ExpiresIn, 1)
	assert.Equal(t, "openid offline_access", response.Scope)
	assert.Equal(t, "bearer", response.TokenType)

	// Previous tokens should not be valid anymore.
	validateNotValidIntrospect(t, ts, service, clientID, refreshToken, "refresh_token")
	validateNotValidIntrospect(t, ts, service, clientID, accessToken, "access_token")

	return response.AccessToken, response.IDToken, response.RefreshToken, now
}
