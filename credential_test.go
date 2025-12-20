package charon_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/waf"

	"gitlab.com/tozd/identifier"

	"gitlab.com/charon/charon"
)

func verifyCredentialList(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, emailOrUsername string) {
	t.Helper()

	credentialRefs := credentialListGet(t, ts, service, accessToken, 2)

	for i := range credentialRefs {
		credential := credentialGet(t, ts, service, accessToken, credentialRefs[i].ID)

		switch credential.Provider {
		case charon.ProviderEmail:
			assert.Equal(t, emailOrUsername, credential.DisplayName)
			// Code verification marks email as verified.
			assert.True(t, credential.Verified)
		case charon.ProviderPassword:
			assert.Equal(t, "default password", credential.DisplayName)
			assert.False(t, credential.Verified)
		case charon.ProviderUsername, charon.ProviderPasskey, charon.ProviderCode:
			require.Fail(t, "unexpected credential provider", "provider: %s", credential.Provider)
		}
	}
}

func TestCredentialUsernameAccessControl(t *testing.T) {
	t.Parallel()

	ts, service, _, _, _ := startTestServer(t) //nolint:dogsled

	username := "username"

	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)
	accessToken, _ := signinUser(t, ts, service, username, charon.CompletedSignup, flowID, nonce, state, pkceVerifier, config, verifier)

	credentialRefs := credentialListGet(t, ts, service, accessToken, 2)

	// Get first existing credentialID to test access control.
	credentialID := credentialRefs[0].ID
	for i := range credentialRefs {
		credential := credentialGet(t, ts, service, accessToken, credentialRefs[i].ID)
		switch credential.Provider {
		case charon.ProviderUsername:
			assert.Equal(t, username, credential.DisplayName)
			assert.False(t, credential.Verified)
		case charon.ProviderPassword:
			assert.Equal(t, "default password", credential.DisplayName)
			assert.False(t, credential.Verified)
		case charon.ProviderEmail, charon.ProviderPasskey, charon.ProviderCode:
			require.Fail(t, "unexpected credential provider", "provider: %s", credential.Provider)
		}
	}

	signoutUser(t, ts, service, accessToken)

	username2 := "username2"
	flowID2, nonce2, state2, pkceVerifier2, config2, verifier2 := createAuthFlow(t, ts, service)
	accessToken2, _ := signinUser(t, ts, service, username2, charon.CompletedSignup, flowID2, nonce2, state2, pkceVerifier2, config2, verifier2)

	// Different user cannot access first user's credentials and HTTP response is 404 NotFound.
	credentialGet, errE := service.ReverseAPI("CredentialGet", waf.Params{"id": credentialID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+credentialGet, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken2)

	resp, err := ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
}

func TestCredentialManagement(t *testing.T) {
	t.Parallel()

	ts, service, _, _, _ := startTestServer(t) //nolint:dogsled

	// Signup with MockSAML.
	accessToken := mockSAMLSignin(t, ts, service, charon.CompletedSignup)

	credentialRefs := credentialListGet(t, ts, service, accessToken, 1)
	samlCredentialID := credentialRefs[0].ID

	// Identity is auto generated from mockSAML. We add username jackson,
	// so we can reuse signinUser(), which requires username matching expected identities' username.
	usernameCredentialID := credentialAddUsername(t, ts, service, accessToken, " jackson   ")
	emailCredentialID := credentialAddEmail(t, ts, service, accessToken, "  email@example.com ")
	passwordCredentialID := credentialAddPassword(t, ts, service, accessToken, []byte("test1234"), " My default password ")
	passkeyCredentialID := credentialAddPasskey(t, ts, service, accessToken, " My first passkey  ")

	credentialRefs = credentialListGet(t, ts, service, accessToken, 5)

	credentialMap := make(map[identifier.Identifier]charon.CredentialPublic)
	for _, credentialRef := range credentialRefs {
		credential := credentialGet(t, ts, service, accessToken, credentialRef.ID)

		credentialMap[credentialRef.ID] = credential
	}

	assert.Equal(t, "jackson@example.com", credentialMap[samlCredentialID].DisplayName)
	assert.Equal(t, "My default password", credentialMap[passwordCredentialID].DisplayName)
	assert.Equal(t, "My first passkey", credentialMap[passkeyCredentialID].DisplayName)

	credentialRename(t, ts, service, accessToken, samlCredentialID, " My SAML Login   ", false)
	credentialRename(t, ts, service, accessToken, passwordCredentialID, " My super secret password ", false)
	credentialRename(t, ts, service, accessToken, passkeyCredentialID, " My renamed passkey ", true)

	// Sign-out and sign-in with newly added credentials.
	signoutUser(t, ts, service, accessToken)
	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)
	accessToken, _ = signinUser(t, ts, service, "jackson", charon.CompletedSignin, flowID, nonce, state, pkceVerifier, config, verifier)

	// Update credentialMap after rename.
	for _, credentialRef := range credentialRefs {
		credential := credentialGet(t, ts, service, accessToken, credentialRef.ID)

		credentialMap[credentialRef.ID] = credential
	}
	assert.Len(t, credentialMap, 5)

	samlCred := credentialMap[samlCredentialID]
	assert.Equal(t, "mockSAML", string(samlCred.Provider))
	assert.Equal(t, "My SAML Login", samlCred.DisplayName)
	assert.False(t, samlCred.Verified)

	usernameCred := credentialMap[usernameCredentialID]
	assert.Equal(t, charon.ProviderUsername, usernameCred.Provider)
	assert.Equal(t, "jackson", usernameCred.DisplayName)
	assert.False(t, usernameCred.Verified)

	emailCred := credentialMap[emailCredentialID]
	assert.Equal(t, charon.ProviderEmail, emailCred.Provider)
	assert.Equal(t, "email@example.com", emailCred.DisplayName)
	// Email credential is initially added as unverified.
	assert.False(t, emailCred.Verified)
	// TODO: after adding email verification, verify email and test for verified true.

	passwordCred := credentialMap[passwordCredentialID]
	assert.Equal(t, charon.ProviderPassword, passwordCred.Provider)
	assert.Equal(t, "My super secret password", passwordCred.DisplayName)
	assert.False(t, passwordCred.Verified)

	passkeyCred := credentialMap[passkeyCredentialID]
	assert.Equal(t, charon.ProviderPasskey, passkeyCred.Provider)
	assert.Equal(t, "My renamed passkey", passkeyCred.DisplayName)
	assert.False(t, passkeyCred.Verified)

	credentialRemove(t, ts, service, accessToken, usernameCredentialID)
	credentialRemove(t, ts, service, accessToken, emailCredentialID)
	credentialRemove(t, ts, service, accessToken, samlCredentialID)

	// Test no-op w/ passkey rename.
	resp := credentialRenameStart(t, ts, service, accessToken, passkeyCredentialID, "My renamed passkey") //nolint:bodyclose

	var renameResponsePasskey charon.CredentialResponse
	errE := x.DecodeJSONWithoutUnknownFields(resp.Body, &renameResponsePasskey)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Empty(t, renameResponsePasskey.Error)
	assert.True(t, renameResponsePasskey.Success)
	assert.NotEmpty(t, renameResponsePasskey.Signal)

	credentialRemove(t, ts, service, accessToken, passkeyCredentialID)

	// Test ErrorCodeCredentialDisplayNameInUse.
	passwordCredentialID2 := credentialAddPassword(t, ts, service, accessToken, []byte("test4321"), " My second password ")
	resp = credentialRenameStart(t, ts, service, accessToken, passwordCredentialID2, "My super secret password") //nolint:bodyclose

	var renameResponsePassword charon.CredentialResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &renameResponsePassword)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.NotEmpty(t, renameResponsePassword.Error)
	assert.Equal(t, charon.ErrorCodeCredentialDisplayNameInUse, renameResponsePassword.Error)
	assert.False(t, renameResponsePassword.Success)
	assert.Empty(t, renameResponsePassword.Signal)

	credentialRemove(t, ts, service, accessToken, passwordCredentialID)
	credentialRemove(t, ts, service, accessToken, passwordCredentialID2)

	// Verify credential list is empty.
	credentialRefs = credentialListGet(t, ts, service, accessToken, 0)
	require.Empty(t, credentialRefs)
}

func credentialListGet(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, lenCredentials int) []charon.CredentialRef {
	t.Helper()

	credentialListGet, errE := service.ReverseAPI("CredentialList", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+credentialListGet, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var credentialsRef []charon.CredentialRef
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &credentialsRef)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Len(t, credentialsRef, lenCredentials)

	return credentialsRef
}

func credentialGet(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, credentialID identifier.Identifier) charon.CredentialPublic {
	t.Helper()

	credentialGet, errE := service.ReverseAPI("CredentialGet", waf.Params{"id": credentialID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+credentialGet, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var credential charon.CredentialPublic
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &credential)
	require.NoError(t, errE, "% -+#.1v", errE)

	return credential
}

func credentialAdd(t *testing.T, ts *httptest.Server, accessToken string, addRequest json.RawMessage, url string) charon.CredentialAddResponse {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+url, bytes.NewReader(addRequest))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var addResponse charon.CredentialAddResponse
	errE := x.DecodeJSONWithoutUnknownFields(resp.Body, &addResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Empty(t, addResponse.Error)

	return addResponse
}

func credentialAddEmail(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, email string) identifier.Identifier {
	t.Helper()
	credentialAddEmail, errE := service.ReverseAPI("CredentialAddEmail", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	addEmailRequest := charon.CredentialAddEmailRequest{
		Email: email,
	}
	data, errE := x.MarshalWithoutEscapeHTML(addEmailRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	addResponse := credentialAdd(t, ts, accessToken, data, credentialAddEmail)
	require.NotNil(t, addResponse.CredentialID)
	return *addResponse.CredentialID
}

func credentialAddUsername(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, username string) identifier.Identifier {
	t.Helper()

	credentialAddUsername, errE := service.ReverseAPI("CredentialAddUsername", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	addUsernameRequest := charon.CredentialAddUsernameRequest{
		Username: username,
	}
	data, errE := x.MarshalWithoutEscapeHTML(addUsernameRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	addResponse := credentialAdd(t, ts, accessToken, data, credentialAddUsername)
	require.NotNil(t, addResponse.CredentialID)
	return *addResponse.CredentialID
}

func credentialAddPassword(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, password []byte, displayName string) identifier.Identifier {
	t.Helper()

	credentialAddPasswordStartRequest, errE := service.ReverseAPI("CredentialAddPasswordStart", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	addPasswordStartRequest := charon.CredentialAddCredentialStartRequest{
		DisplayName: displayName,
	}
	data, errE := x.MarshalWithoutEscapeHTML(addPasswordStartRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	addPasswordStartResponse := credentialAdd(t, ts, accessToken, data, credentialAddPasswordStartRequest)
	require.NotNil(t, addPasswordStartResponse.SessionID)
	require.NotNil(t, addPasswordStartResponse.Password)

	publicKey, sealedPassword := encryptPassword(t, password, addPasswordStartResponse.Password.PublicKey, addPasswordStartResponse.Password.EncryptOptions.Nonce)

	credentialAddPasswordComplete, errE := service.ReverseAPI("CredentialAddPasswordComplete", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	addPasswordCompleteRequest := charon.CredentialAddPasswordCompleteRequest{
		AuthFlowPasswordCompleteRequest: charon.AuthFlowPasswordCompleteRequest{
			PublicKey: publicKey,
			Password:  sealedPassword,
		},
		SessionID: *addPasswordStartResponse.SessionID,
	}
	data, errE = x.MarshalWithoutEscapeHTML(addPasswordCompleteRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	addPasswordCompleteResponse := credentialAdd(t, ts, accessToken, data, credentialAddPasswordComplete)
	require.NotNil(t, addPasswordCompleteResponse.CredentialID)

	return *addPasswordCompleteResponse.CredentialID
}

func credentialAddPasskey(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken, displayName string) identifier.Identifier {
	t.Helper()

	credentialAddPasskeyStart, errE := service.ReverseAPI("CredentialAddPasskeyStart", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	addPasskeyStartRequest := charon.CredentialAddCredentialStartRequest{
		DisplayName: displayName,
	}
	data, errE := x.MarshalWithoutEscapeHTML(addPasskeyStartRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	addPasskeyStartResponse := credentialAdd(t, ts, accessToken, data, credentialAddPasskeyStart)
	require.NotNil(t, addPasskeyStartResponse.SessionID)
	require.NotNil(t, addPasskeyStartResponse.Passkey)

	AuthFlowPasskeyCreateCompleteRequest, _, _, _, _ := createMockPasskeyCredential(t, ts, addPasskeyStartResponse.Passkey) //nolint:dogsled

	credentialAddPasskeyComplete, errE := service.ReverseAPI("CredentialAddPasskeyComplete", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	addPasskeyCompleteRequest := charon.CredentialAddPasskeyCompleteRequest{
		AuthFlowPasskeyCreateCompleteRequest: AuthFlowPasskeyCreateCompleteRequest,
		SessionID:                            *addPasskeyStartResponse.SessionID,
	}
	data, errE = x.MarshalWithoutEscapeHTML(addPasskeyCompleteRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	addPasskeyCompleteResponse := credentialAdd(t, ts, accessToken, data, credentialAddPasskeyComplete)
	require.NotNil(t, addPasskeyCompleteResponse.CredentialID)

	return *addPasskeyCompleteResponse.CredentialID
}

func credentialRemove(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, credentialID identifier.Identifier) {
	t.Helper()

	credentialRemove, errE := service.ReverseAPI("CredentialRemove", waf.Params{"id": credentialID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+credentialRemove, strings.NewReader("{}"))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var removeResponse charon.CredentialResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &removeResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Empty(t, removeResponse.Error)
	assert.True(t, removeResponse.Success)
	assert.Empty(t, removeResponse.Signal)
}

func credentialRenameStart(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, credentialID identifier.Identifier, newDisplayName string) *http.Response {
	t.Helper()

	credentialRename, errE := service.ReverseAPI("CredentialRename", waf.Params{"id": credentialID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	renameRequest := charon.CredentialRenameRequest{
		DisplayName: newDisplayName,
	}
	data, errE := x.MarshalWithoutEscapeHTML(renameRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+credentialRename, bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	return resp
}

func credentialRename(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, credentialID identifier.Identifier, newDisplayName string, isPasskey bool) {
	t.Helper()

	resp := credentialRenameStart(t, ts, service, accessToken, credentialID, newDisplayName) //nolint:bodyclose

	var renameResponse charon.CredentialResponse
	errE := x.DecodeJSONWithoutUnknownFields(resp.Body, &renameResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Empty(t, renameResponse.Error)
	assert.True(t, renameResponse.Success)
	if isPasskey {
		assert.NotEmpty(t, renameResponse.Signal)
	} else {
		assert.Empty(t, renameResponse.Signal)
	}
}
