package charon_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

func TestAuthFlowPasskey(t *testing.T) {
	t.Parallel()

	ts, service, _, _, _ := startTestServer(t) //nolint:dogsled

	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)

	authFlowPasskeyCreateStart, errE := service.ReverseAPI("AuthFlowPasskeyCreateStart", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Start passkey create.
	resp, err := ts.Client().Post(ts.URL+authFlowPasskeyCreateStart, "application/json", strings.NewReader(`{}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authFlowResponse charon.AuthFlowResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, []charon.Provider{charon.ProviderPasskey}, authFlowResponse.Providers)
	require.NotNil(t, authFlowResponse.Passkey)
	require.NotNil(t, authFlowResponse.Passkey.CreateOptions)

	userID, err := base64.RawURLEncoding.DecodeString(authFlowResponse.Passkey.CreateOptions.Response.User.ID.(string)) //nolint:errcheck,forcetypeassert
	require.NoError(t, err)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available, current provider is passkey.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		// Passkey create options are provided only in the response to the passkey create start call.
		assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{}, []charon.Provider{charon.ProviderPasskey}, "", assertCharonDashboard)
	}

	authFlowPasskeyCreateComplete, errE := service.ReverseAPI("AuthFlowPasskeyCreateComplete", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	authFlowPasskeyCreateCompleteRequest, rsaKey, publicKeyID, credentialID, rawAuthData := createMockPasskeyCredential(t, ts, authFlowResponse.Passkey)

	data, errE := x.MarshalWithoutEscapeHTML(authFlowPasskeyCreateCompleteRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Complete passkey create.
	resp, err = ts.Client().Post(ts.URL+authFlowPasskeyCreateComplete, "application/json", bytes.NewReader(data)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	assertSignedUser(t, charon.CompletedSignup, flowID, resp)

	// Flow is available and CompletedSignup is completed.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	require.NoError(t, err)
	oid := assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{charon.CompletedSignup}, []charon.Provider{charon.ProviderPasskey}, "", assertCharonDashboard)

	chooseIdentity(t, ts, service, oid, flowID, "Charon", "Dashboard", charon.CompletedSignup, []charon.Provider{charon.ProviderPasskey}, 1, "username")
	accessToken := doRedirectAndAccessToken(t, ts, service, oid, flowID, "Charon", "Dashboard", nonce, state, pkceVerifier, config, verifier, charon.CompletedSignup, []charon.Provider{charon.ProviderPasskey})

	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderPasskey}, 0, 1, 0, 1},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})

	accessToken = signinMockPasskeyCredential(t, ts, service, "username", rsaKey, publicKeyID, credentialID, rawAuthData, userID)

	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderPasskey}, 0, 1, 0, 1}, // Signin.
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderPasskey}, 0, 1, 0, 1},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})
}

func createMockPasskeyCredential(t *testing.T, ts *httptest.Server, authFlowResponsePasskey *charon.AuthFlowResponsePasskey) (charon.AuthFlowPasskeyCreateCompleteRequest, *rsa.PrivateKey, string, []byte, []byte) {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaPublicKeyData := webauthncose.RSAPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.RSAKey),
			Algorithm: int64(webauthncose.AlgRS256),
		},
		Modulus:  rsaKey.N.Bytes(),
		Exponent: binary.LittleEndian.AppendUint32(nil, uint32(rsaKey.E))[:3], //nolint:gosec
	}

	publicKeyBytes, err := webauthncbor.Marshal(rsaPublicKeyData)
	require.NoError(t, err)

	id := identifier.New()
	credentialID := id[:]
	publicKeyID := base64.RawURLEncoding.EncodeToString(credentialID)

	clientData := protocol.CollectedClientData{
		Type:         protocol.CreateCeremony,
		Challenge:    authFlowResponsePasskey.CreateOptions.Response.Challenge.String(),
		Origin:       ts.URL,
		TokenBinding: nil,
		Hint:         "",
	}
	byteClientDataJSON, errE := x.MarshalWithoutEscapeHTML(clientData)
	require.NoError(t, errE, "% -+#.1v", errE)

	rpIDHash := sha256.Sum256([]byte(authFlowResponsePasskey.CreateOptions.Response.RelyingParty.ID))

	rawAuthData := []byte{}
	// RPIDHash.
	rawAuthData = append(rawAuthData, rpIDHash[:]...)
	// Flags.
	rawAuthData = append(rawAuthData, byte(protocol.FlagUserPresent|protocol.FlagAttestedCredentialData|protocol.FlagUserVerified))
	// Counter.
	rawAuthData = binary.BigEndian.AppendUint32(rawAuthData, 0)
	// AAGUID.
	rawAuthData = append(rawAuthData, make([]byte, 16)...)
	// ID length.
	rawAuthData = binary.BigEndian.AppendUint16(rawAuthData, uint16(len(credentialID))) //nolint:gosec
	// CredentialID.
	rawAuthData = append(rawAuthData, credentialID...)
	// CredentialPublicKey.
	rawAuthData = append(rawAuthData, publicKeyBytes...)

	attestationObject := protocol.AttestationObject{
		AuthData:     protocol.AuthenticatorData{},
		RawAuthData:  rawAuthData,
		Format:       "none",
		AttStatement: nil,
	}
	byteAttObject, err := webauthncbor.Marshal(attestationObject)
	require.NoError(t, err)

	authFlowPasskeyCreateCompleteRequest := charon.AuthFlowPasskeyCreateCompleteRequest{
		CreateResponse: protocol.CredentialCreationResponse{
			PublicKeyCredential: protocol.PublicKeyCredential{
				Credential: protocol.Credential{
					Type: "public-key",
					ID:   publicKeyID,
				},
				RawID:                   credentialID,
				ClientExtensionResults:  nil,
				AuthenticatorAttachment: string(protocol.Platform),
			},
			AttestationResponse: protocol.AuthenticatorAttestationResponse{
				AuthenticatorResponse: protocol.AuthenticatorResponse{
					ClientDataJSON: byteClientDataJSON,
				},
				AttestationObject: byteAttObject,
				Transports:        []string{"fake"},
			},
		},
	}

	return authFlowPasskeyCreateCompleteRequest, rsaKey, publicKeyID, credentialID, rawAuthData
}

func signinMockPasskeyCredential(t *testing.T, ts *httptest.Server, service *charon.Service, expectedEmailOrUsername string, rsaKey *rsa.PrivateKey, publicKeyID string, credentialID []byte, rawAuthData []byte, userID []byte) string {
	t.Helper()

	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)

	authFlowPasskeyGetStart, errE := service.ReverseAPI("AuthFlowPasskeyGetStart", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Start passkey get.
	resp, err := ts.Client().Post(ts.URL+authFlowPasskeyGetStart, "application/json", strings.NewReader(`{}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	authFlowResponse := charon.AuthFlowResponse{}
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, []charon.Provider{charon.ProviderPasskey}, authFlowResponse.Providers)
	require.NotNil(t, authFlowResponse.Passkey)
	require.NotNil(t, authFlowResponse.Passkey.GetOptions)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available, current provider is passkey.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		// Passkey get options are provided only in the response to the passkey get start call.
		assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{}, []charon.Provider{charon.ProviderPasskey}, "", assertCharonDashboard)
	}

	authFlowPasskeyGetComplete, errE := service.ReverseAPI("AuthFlowPasskeyGetComplete", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	clientData := protocol.CollectedClientData{
		Type:         protocol.AssertCeremony,
		Challenge:    authFlowResponse.Passkey.GetOptions.Response.Challenge.String(),
		Origin:       ts.URL,
		TokenBinding: nil,
		Hint:         "",
	}
	byteClientDataJSON, errE := x.MarshalWithoutEscapeHTML(clientData)
	require.NoError(t, errE, "% -+#.1v", errE)

	clientDataHash := sha256.Sum256(byteClientDataJSON)
	sigData := []byte{}
	sigData = append(sigData, rawAuthData...)
	sigData = append(sigData, clientDataHash[:]...)
	sigDataHash := sha256.Sum256(sigData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, sigDataHash[:])
	require.NoError(t, err)

	authFlowPasskeyGetCompleteRequest := charon.AuthFlowPasskeyGetCompleteRequest{
		GetResponse: protocol.CredentialAssertionResponse{
			PublicKeyCredential: protocol.PublicKeyCredential{
				Credential: protocol.Credential{
					Type: "public-key",
					ID:   publicKeyID,
				},
				RawID:                   credentialID,
				ClientExtensionResults:  nil,
				AuthenticatorAttachment: string(protocol.Platform),
			},
			AssertionResponse: protocol.AuthenticatorAssertionResponse{
				AuthenticatorResponse: protocol.AuthenticatorResponse{
					ClientDataJSON: byteClientDataJSON,
				},
				AuthenticatorData: rawAuthData,
				Signature:         signature,
				UserHandle:        userID,
			},
		},
	}

	data, errE := x.MarshalWithoutEscapeHTML(authFlowPasskeyGetCompleteRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Complete passkey get.
	resp, err = ts.Client().Post(ts.URL+authFlowPasskeyGetComplete, "application/json", bytes.NewReader(data)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	assertSignedUser(t, charon.CompletedSignin, flowID, resp)

	// Flow is available and CompletedSignin is completed.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	require.NoError(t, err)
	oid := assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{charon.CompletedSignin}, []charon.Provider{charon.ProviderPasskey}, "", assertCharonDashboard)

	chooseIdentity(t, ts, service, oid, flowID, "Charon", "Dashboard", charon.CompletedSignin, []charon.Provider{charon.ProviderPasskey}, 1, expectedEmailOrUsername)
	return doRedirectAndAccessToken(t, ts, service, oid, flowID, "Charon", "Dashboard", nonce, state, pkceVerifier, config, verifier, charon.CompletedSignin, []charon.Provider{charon.ProviderPasskey})
}
