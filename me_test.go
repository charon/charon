package charon_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	_ "embed"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

func TestRouteMeAndSignOut(t *testing.T) {
	t.Parallel()

	username := identifier.New().String()

	ts, service, _ := startTestServer(t)

	path, errE := service.ReverseAPI("Me", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Initial GET should return error.
	resp, err := ts.Client().Get(ts.URL + path) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"error":"unauthorized"}`, string(out))
	}

	flowID := signinUser(t, ts, service, username, charon.CompletedSignup)

	// After sign-up, GET should return success.
	resp, err = ts.Client().Get(ts.URL + path) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"success":true}`, string(out))
	}

	authSignout, errE := service.ReverseAPI("AuthSignout", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Post(ts.URL+authSignout, "application/json", strings.NewReader(`{"location":"/"}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authSignoutResponse charon.AuthSignoutResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authSignoutResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, "/", authSignoutResponse.URL)

	// After sign-out GET should return error.
	resp, err = ts.Client().Get(ts.URL + path) //nolint:noctx,bodyclose
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

	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		_, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusGone, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		// TODO: This should return JSON with some error payload.
	}

	signinUser(t, ts, service, username, charon.CompletedSignin)

	// After sign-in, GET should return success.
	resp, err = ts.Client().Get(ts.URL + path) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"success":true}`, string(out))
	}
}

func signinUser(t *testing.T, ts *httptest.Server, service *charon.Service, emailOrUsername string, signinOrSignout charon.Completed) identifier.Identifier {
	t.Helper()

	authFlowCreate, errE := service.ReverseAPI("AuthFlowCreate", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Post(ts.URL+authFlowCreate, "application/json", strings.NewReader(`{"location":"/"}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authFlowCreateResponse charon.AuthFlowCreateResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowCreateResponse)
	require.NoError(t, errE, "% -+#.1v", errE)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": authFlowCreateResponse.ID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard"}`, string(out))
	}

	authFlowPasswordStart, errE := service.ReverseAPI("AuthFlowPasswordStart", waf.Params{"id": authFlowCreateResponse.ID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Post(ts.URL+authFlowPasswordStart, "application/json", strings.NewReader(`{"emailOrUsername":"`+emailOrUsername+`"}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authFlowResponse charon.AuthFlowResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, charon.TargetSession, authFlowResponse.Target)
	require.NotNil(t, authFlowResponse.Password)

	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"password","emailOrUsername":"`+emailOrUsername+`"}`, string(out))
	}

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	remotePublicKey, err := ecdh.P256().NewPublicKey(authFlowResponse.Password.PublicKey)
	require.NoError(t, err)
	secret, err := privateKey.ECDH(remotePublicKey)
	require.NoError(t, err)
	block, err := aes.NewCipher(secret)
	require.NoError(t, err)
	aesgcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	sealedPassword := aesgcm.Seal(nil, authFlowResponse.Password.EncryptOptions.Nonce, []byte("test1234"), nil)

	authFlowPasswordComplete, errE := service.ReverseAPI("AuthFlowPasswordComplete", waf.Params{"id": authFlowCreateResponse.ID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	authFlowPasswordCompleteRequest := charon.AuthFlowPasswordCompleteRequest{
		PublicKey: privateKey.PublicKey().Bytes(),
		Password:  sealedPassword,
	}

	data, errE := x.MarshalWithoutEscapeHTML(authFlowPasswordCompleteRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Post(ts.URL+authFlowPasswordComplete, "application/json", bytes.NewReader(data)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	authFlowResponse = charon.AuthFlowResponse{}
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Equal(t, signinOrSignout, authFlowResponse.Completed)
	assert.Len(t, resp.Cookies(), 1)
	for _, cookie := range resp.Cookies() {
		assert.Equal(t, charon.SessionCookieName, cookie.Name)
	}

	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"password","completed":"`+string(signinOrSignout)+`","location":{"url":"/","replace":true}}`, string(out))
	}

	return authFlowCreateResponse.ID
}
