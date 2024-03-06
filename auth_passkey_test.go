package charon_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
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

func TestAuthFlowPasskey(t *testing.T) { //nolint:maintidx
	t.Parallel()

	ts, service, _, _ := startTestServer(t)

	flowID := createAuthFlow(t, ts, service)

	authFlowPasskeyCreateStart, errE := service.ReverseAPI("AuthFlowPasskeyCreateStart", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Start passkey create.
	resp, err := ts.Client().Post(ts.URL+authFlowPasskeyCreateStart, "application/json", strings.NewReader(`{}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authFlowResponse charon.AuthFlowResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, charon.TargetSession, authFlowResponse.Target)
	assert.Equal(t, charon.PasskeyProvider, authFlowResponse.Provider)
	require.NotNil(t, authFlowResponse.Passkey)
	require.NotNil(t, authFlowResponse.Passkey.CreateOptions)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available, current provider is passkey.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		// Passkey create options are provided only in the response to the passkey create start call.
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"passkey"}`, string(out))
	}

	authFlowPasskeyCreateComplete, errE := service.ReverseAPI("AuthFlowPasskeyCreateComplete", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaPublicKeyData := webauthncose.RSAPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.RSAKey),
			Algorithm: int64(webauthncose.AlgRS256),
		},
		Modulus:  rsaKey.PublicKey.N.Bytes(),
		Exponent: binary.LittleEndian.AppendUint32(nil, uint32(rsaKey.PublicKey.E))[:3],
	}

	publicKeyBytes, err := webauthncbor.Marshal(rsaPublicKeyData)
	require.NoError(t, err)

	id := identifier.New()
	credentialID := id[:]
	publicKeyID := base64.RawURLEncoding.EncodeToString(credentialID)

	clientData := protocol.CollectedClientData{
		Type:         protocol.CreateCeremony,
		Challenge:    authFlowResponse.Passkey.CreateOptions.Response.Challenge.String(),
		Origin:       ts.URL,
		TokenBinding: nil,
		Hint:         "",
	}
	byteClientDataJSON, errE := x.MarshalWithoutEscapeHTML(clientData)
	require.NoError(t, errE, "% -+#.1v", errE)

	rpIDHash := sha256.Sum256([]byte(authFlowResponse.Passkey.CreateOptions.Response.RelyingParty.ID))

	rawAuthData := []byte{}
	// RPIDHash.
	rawAuthData = append(rawAuthData, rpIDHash[:]...)
	// Flags.
	rawAuthData = append(rawAuthData, byte(protocol.FlagUserPresent|protocol.FlagAttestedCredentialData))
	// Counter.
	rawAuthData = binary.BigEndian.AppendUint32(rawAuthData, 0)
	// AAGUID.
	rawAuthData = append(rawAuthData, make([]byte, 16)...)
	// ID length.
	rawAuthData = binary.BigEndian.AppendUint16(rawAuthData, uint16(len(credentialID)))
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

	data, errE := x.MarshalWithoutEscapeHTML(authFlowPasskeyCreateCompleteRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Complete passkey create.
	resp, err = ts.Client().Post(ts.URL+authFlowPasskeyCreateComplete, "application/json", bytes.NewReader(data)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	authFlowResponse = charon.AuthFlowResponse{}
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Equal(t, charon.CompletedSignup, authFlowResponse.Completed)
	assert.Len(t, resp.Cookies(), 1)
	for _, cookie := range resp.Cookies() {
		assert.Equal(t, charon.SessionCookieName, cookie.Name)
	}

	// Flow is available and is completed.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"passkey","completed":"`+string(charon.CompletedSignup)+`","location":{"url":"/","replace":true}}`, string(out))
	}

	signoutUser(t, ts, service)

	// Start another flow.
	flowID = createAuthFlow(t, ts, service)

	authFlowPasskeyGetStart, errE := service.ReverseAPI("AuthFlowPasskeyGetStart", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Start passkey get.
	resp, err = ts.Client().Post(ts.URL+authFlowPasskeyGetStart, "application/json", strings.NewReader(`{}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	authFlowResponse = charon.AuthFlowResponse{}
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, charon.TargetSession, authFlowResponse.Target)
	assert.Equal(t, charon.PasskeyProvider, authFlowResponse.Provider)
	require.NotNil(t, authFlowResponse.Passkey)
	require.NotNil(t, authFlowResponse.Passkey.GetOptions)

	authFlowGet, errE = service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available, current provider is passkey.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		// Passkey get options are provided only in the response to the passkey get start call.
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"passkey"}`, string(out))
	}

	authFlowPasskeyGetComplete, errE := service.ReverseAPI("AuthFlowPasskeyGetComplete", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	clientData = protocol.CollectedClientData{
		Type:         protocol.AssertCeremony,
		Challenge:    authFlowResponse.Passkey.GetOptions.Response.Challenge.String(),
		Origin:       ts.URL,
		TokenBinding: nil,
		Hint:         "",
	}
	byteClientDataJSON, errE = x.MarshalWithoutEscapeHTML(clientData)
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
				UserHandle:        []byte{0},
			},
		},
	}

	data, errE = x.MarshalWithoutEscapeHTML(authFlowPasskeyGetCompleteRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Complete passkey get.
	resp, err = ts.Client().Post(ts.URL+authFlowPasskeyGetComplete, "application/json", bytes.NewReader(data)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	authFlowResponse = charon.AuthFlowResponse{}
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Equal(t, charon.CompletedSignin, authFlowResponse.Completed)
	assert.Len(t, resp.Cookies(), 1)
	for _, cookie := range resp.Cookies() {
		assert.Equal(t, charon.SessionCookieName, cookie.Name)
	}

	// Flow is available and is completed.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"passkey","completed":"`+string(charon.CompletedSignin)+`","location":{"url":"/","replace":true}}`, string(out))
	}
}
