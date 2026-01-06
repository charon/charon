package charon_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
	"golang.org/x/oauth2"

	"gitlab.com/charon/charon"
)

func startPasswordSignin(t *testing.T, ts *httptest.Server, service *charon.Service, emailOrUsername string, password []byte, organizationID *identifier.Identifier, flowID identifier.Identifier, organization, app string) *http.Response {
	t.Helper()

	authFlowPasswordStart, errE := service.ReverseAPI("AuthFlowPasswordStart", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Start password authentication.
	resp, err := ts.Client().Post(ts.URL+authFlowPasswordStart, "application/json", strings.NewReader(`{"emailOrUsername":"`+emailOrUsername+`"}`)) //nolint:noctx
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authFlowResponse charon.AuthFlowResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, []charon.Provider{charon.ProviderPassword}, authFlowResponse.Providers)
	require.NotNil(t, authFlowResponse.Password)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available, current provider is password.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, organizationID, []charon.Completed{}, []charon.Provider{charon.ProviderPassword}, emailOrUsername, assertAppName(t, organization, app))
	}

	publicKey, sealedPassword := encryptPassword(t, password, authFlowResponse.Password.PublicKey, authFlowResponse.Password.EncryptOptions.Nonce)

	authFlowPasswordComplete, errE := service.ReverseAPI("AuthFlowPasswordComplete", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	authFlowPasswordCompleteRequest := charon.AuthFlowPasswordCompleteRequest{
		PublicKey: publicKey,
		Password:  sealedPassword,
	}

	data, errE := x.MarshalWithoutEscapeHTML(authFlowPasswordCompleteRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Complete password authentication.
	resp, err = ts.Client().Post(ts.URL+authFlowPasswordComplete, "application/json", bytes.NewReader(data)) //nolint:noctx
	require.NoError(t, err)

	return resp
}

func assertSignedUser(t *testing.T, signinOrSignout charon.Completed, flowID identifier.Identifier, resp *http.Response) {
	t.Helper()

	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authFlowResponse charon.AuthFlowResponse
	errE := x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Equal(t, []charon.Completed{signinOrSignout}, authFlowResponse.Completed)
	assert.Len(t, resp.Cookies(), 1)
	for _, cookie := range resp.Cookies() {
		assert.Equal(t, charon.TestingSessionCookiePrefix()+flowID.String(), cookie.Name)
	}
}

func signinUser(t *testing.T, ts *httptest.Server, service *charon.Service, emailOrUsername string, identityEmailOrUsername string, signinOrSignout charon.Completed, flowID identifier.Identifier, nonce, state, pkceVerifier string, config *oauth2.Config, verifier *oidc.IDTokenVerifier) (string, identifier.Identifier) {
	t.Helper()

	resp := startPasswordSignin(t, ts, service, emailOrUsername, []byte("test1234"), nil, flowID, "Charon", "Dashboard") //nolint:bodyclose
	assertSignedUser(t, signinOrSignout, flowID, resp)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available and signinOrSignout is completed.
	resp, err := ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	require.NoError(t, err)
	oid := assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{signinOrSignout}, []charon.Provider{charon.ProviderPassword}, "", assertCharonDashboard)

	identityID := chooseIdentity(t, ts, service, oid, flowID, "Charon", "Dashboard", signinOrSignout, []charon.Provider{charon.ProviderPassword}, 1, identityEmailOrUsername)
	return doRedirectAndAccessToken(t, ts, service, oid, flowID, "Charon", "Dashboard", nonce, state, pkceVerifier, config, verifier, signinOrSignout, []charon.Provider{charon.ProviderPassword}), identityID
}

// encryptPassword mimics client-side encryption as done in browser.
func encryptPassword(t *testing.T, password []byte, serverPublicKey []byte, nonce []byte) ([]byte, []byte) {
	t.Helper()

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	remotePublicKey, err := ecdh.P256().NewPublicKey(serverPublicKey)
	require.NoError(t, err)
	secret, err := privateKey.ECDH(remotePublicKey)
	require.NoError(t, err)
	block, err := aes.NewCipher(secret)
	require.NoError(t, err)
	aesgcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	sealedPassword := aesgcm.Seal(nil, nonce, password, nil)

	return privateKey.PublicKey().Bytes(), sealedPassword
}
