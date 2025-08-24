package charon_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/automattic/go-gravatar"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

//nolint:tagliatelle
type userInfoResponse struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	GivenName         string `json:"given_name"`
	Name              string `json:"name"`
	Picture           string `json:"picture"`
	PreferredUsername string `json:"preferred_username"`
}

func validateUserInfo(t *testing.T, ts *httptest.Server, service *charon.Service, token string, identityID identifier.Identifier) {
	t.Helper()

	oidcUserInfo, errE := service.ReverseAPI("OIDCUserInfo", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	data := url.Values{
		"access_token": []string{token},
	}

	resp, err := ts.Client().Post(ts.URL+oidcUserInfo, "application/x-www-form-urlencoded", strings.NewReader(data.Encode())) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var response userInfoResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &response)
	require.NoError(t, errE, "% -+#.1v", errE)

	assert.Equal(t, identityID.String(), response.Subject)
	assert.Equal(t, "user@example.com", response.Email)
	assert.True(t, response.EmailVerified)
	assert.Equal(t, "User", response.GivenName)
	assert.Equal(t, "User Name", response.Name)
	assert.Equal(t, "https://example.com/picture.png", response.Picture)
	assert.Equal(t, "username", response.PreferredUsername)
}

func TestRouteUserinfoAndSignOut(t *testing.T) {
	t.Parallel()

	username := identifier.New().String()

	ts, service, _, _ := startTestServer(t)

	userinfo, errE := service.ReverseAPI("OIDCUserInfo", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Initial GET (without access token) should return error.
	resp, err := ts.Client().Get(ts.URL + userinfo) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		// TODO: This should return JSON with some error payload.
		assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
		assert.Equal(t, "Unauthorized\n", string(out))
	}

	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)
	accessToken, identityID := signinUser(t, ts, service, username, charon.CompletedSignup, flowID, nonce, state, pkceVerifier, config, verifier)

	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderPassword}, 0, 1, 0, 1},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})

	g := gravatar.NewGravatarFromEmail(username)
	g.Default = "identicon"
	gravatarURL := g.GetURL()

	// After sign-up, GET (with access token) should return success.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+userinfo, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = ts.Client().Do(req) //nolint:bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"picture":"`+gravatarURL+`","preferred_username":"`+username+`","sub":"`+identityID.String()+`"}`, string(out))
	}

	signoutUser(t, ts, service, accessToken)

	// After sign-out GET (with revoked access token) should return error.
	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+userinfo, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = ts.Client().Do(req) //nolint:bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		// TODO: This should return JSON with some error payload.
		assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
		assert.Equal(t, "Unauthorized\n", string(out))
	}

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Loading flow when signed out (no session cookie anymore) should error.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		_, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		// TODO: This should return JSON with some error payload.
	}

	flowID, nonce, state, pkceVerifier, config, verifier = createAuthFlow(t, ts, service)
	accessToken, identityID = signinUser(t, ts, service, username, charon.CompletedSignin, flowID, nonce, state, pkceVerifier, config, verifier)

	// After sign-in, GET (with new access token) should again return success.
	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+userinfo, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = ts.Client().Do(req) //nolint:bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"picture":"`+gravatarURL+`","preferred_username":"`+username+`","sub":"`+identityID.String()+`"}`, string(out))
	}

	// Loading old flow when signed in again does not work because sessions are bound to flows.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		_, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		// TODO: This should return JSON with some error payload.
	}

	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderPassword}, 0, 1, 0, 1}, // Signin (after signout).
		{charon.ActivitySignOut, nil, nil, 0, 0, 0, 0},                                       // Signout.
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderPassword}, 0, 1, 0, 1},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})
}
