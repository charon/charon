package charon_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
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

func startPasswordSignin(t *testing.T, ts *httptest.Server, service *charon.Service, emailOrUsername string, organizationID *identifier.Identifier, flowID identifier.Identifier, target charon.Target) *http.Response {
	t.Helper()

	authFlowPasswordStart, errE := service.ReverseAPI("AuthFlowPasswordStart", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Start password authentication.
	resp, err := ts.Client().Post(ts.URL+authFlowPasswordStart, "application/json", strings.NewReader(`{"emailOrUsername":"`+emailOrUsername+`"}`)) //nolint:noctx
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authFlowResponse charon.AuthFlowResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, target, authFlowResponse.Target)
	assert.Equal(t, charon.PasswordProvider, authFlowResponse.Provider)
	require.NotNil(t, authFlowResponse.Password)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available, current provider is password.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		if target == charon.TargetSession {
			assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"password","emailOrUsername":"`+emailOrUsername+`"}`, string(out))
		} else {
			assert.Equal(t, `{"target":"oidc","name":"Test application","homepage":"https://example.com","organizationId":"`+organizationID.String()+`","provider":"password","emailOrUsername":"`+emailOrUsername+`"}`, string(out))
		}
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

	authFlowPasswordComplete, errE := service.ReverseAPI("AuthFlowPasswordComplete", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	authFlowPasswordCompleteRequest := charon.AuthFlowPasswordCompleteRequest{
		PublicKey: privateKey.PublicKey().Bytes(),
		Password:  sealedPassword,
	}

	data, errE := x.MarshalWithoutEscapeHTML(authFlowPasswordCompleteRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Complete password authentication.
	resp, err = ts.Client().Post(ts.URL+authFlowPasswordComplete, "application/json", bytes.NewReader(data)) //nolint:noctx
	require.NoError(t, err)

	return resp
}

func signinUser(t *testing.T, ts *httptest.Server, service *charon.Service, emailOrUsername string, signinOrSignout charon.Completed, organizationID *identifier.Identifier, flowID identifier.Identifier, target charon.Target) {
	t.Helper()

	resp := startPasswordSignin(t, ts, service, emailOrUsername, organizationID, flowID, target) //nolint:bodyclose
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	authFlowResponse := charon.AuthFlowResponse{}
	errE := x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Equal(t, signinOrSignout, authFlowResponse.Completed)
	assert.Len(t, resp.Cookies(), 1)
	for _, cookie := range resp.Cookies() {
		assert.Equal(t, charon.SessionCookieName, cookie.Name)
	}

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available and is completed.
	resp, err := ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		// There is no username or e-mail address in the response after the flow completes.
		if target == charon.TargetSession {
			assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"password","completed":"`+string(signinOrSignout)+`","location":{"url":"/","replace":true}}`, string(out))
		} else {
			assert.Equal(t, `{"target":"oidc","name":"Test application","homepage":"https://example.com","organizationId":"`+organizationID.String()+`","provider":"password","completed":"`+string(signinOrSignout)+`"}`, string(out))
		}
	}
}
