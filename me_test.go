package charon_test

import (
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

	// Initial GET should return error.
	resp, err := ts.Client().Get(ts.URL + me) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"error":"unauthorized"}`, string(out))
	}

	flowID := createAuthFlow(t, ts, service)
	signinUser(t, ts, service, username, charon.CompletedSignup, nil, flowID, charon.TargetSession)

	// After sign-up, GET should return success.
	resp, err = ts.Client().Get(ts.URL + me) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"success":true}`, string(out))
	}

	signoutUser(t, ts, service)

	// After sign-out GET should return error.
	resp, err = ts.Client().Get(ts.URL + me) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"error":"unauthorized"}`, string(out))
	}

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Loading flow when signed out should error.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		_, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusGone, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		// TODO: This should return JSON with some error payload.
	}

	flowID = createAuthFlow(t, ts, service)
	signinUser(t, ts, service, username, charon.CompletedSignin, nil, flowID, charon.TargetSession)

	// After sign-in, GET should again return success.
	resp, err = ts.Client().Get(ts.URL + me) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"success":true}`, string(out))
	}

	// Loading old flow when signed in again with same account should work.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"password","completed":"`+string(charon.CompletedSignup)+`","location":{"url":"/","replace":true}}`, string(out))
	}
}
