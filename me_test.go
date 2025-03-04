package charon_test

import (
	"context"
	_ "embed"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

func TestRouteMeAndSignOut(t *testing.T) {
	t.Parallel()

	username := identifier.New().String()

	ts, service, _, _ := startTestServer(t)

	me, errE := service.ReverseAPI("Me", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Initial GET (without access token) should return error.
	resp, err := ts.Client().Get(ts.URL + me) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"error":"unauthorized"}`, string(out)) //nolint:testifylint
	}

	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)
	accessToken := signinUser(t, ts, service, username, charon.CompletedSignup, nil, flowID, "Charon", "Dashboard", nonce, state, pkceVerifier, config, verifier)

	// After sign-up, GET (with access token) should return success.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+me, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = ts.Client().Do(req) //nolint:noctx,bodycloseodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"success":true}`, string(out))
	}

	signoutUser(t, ts, service, accessToken)

	// After sign-out GET (with revoked access token) should return error.
	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+me, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = ts.Client().Do(req) //nolint:noctx,bodycloseodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"error":"unauthorized"}`, string(out)) //nolint:testifylint
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
	accessToken = signinUser(t, ts, service, username, charon.CompletedSignin, nil, flowID, "Charon", "Dashboard", nonce, state, pkceVerifier, config, verifier)

	// After sign-in, GET (with new access token) should again return success.
	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+me, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = ts.Client().Do(req) //nolint:noctx,bodycloseodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"success":true}`, string(out))
	}

	// Loading old flow when signed in again does not work because sessions are bound to flows.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		_, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		// TODO: This should return JSON with some error payload.
	}
}
