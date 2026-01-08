package charon_test

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
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

func assertEmailAndPasswordCredential(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, email string) []charon.CredentialRef {
	t.Helper()

	credentialRefs := credentialListGet(t, ts, service, accessToken, 2)

	for i := range credentialRefs {
		credential := credentialGet(t, ts, service, accessToken, credentialRefs[i].ID)

		switch credential.Provider {
		case charon.ProviderEmail:
			assert.Equal(t, email, credential.DisplayName)
			// Code verification marks email as verified.
			assert.True(t, credential.Verified)
		case charon.ProviderPassword:
			assert.Equal(t, "default password", credential.DisplayName)
			assert.False(t, credential.Verified)
		case charon.ProviderUsername, charon.ProviderPasskey, charon.ProviderCode:
			require.Fail(t, "unexpected credential provider", "provider: %s", credential.Provider)
		}
	}
	return credentialRefs
}

func TestCredentialEmailAccessControl(t *testing.T) {
	t.Parallel()

	user := identifier.New().String()
	email := user + "@example.com"

	ts, service, smtpServer, _, _ := startTestServer(t)

	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)

	// Start password authentication with e-mail address.
	resp := startPasswordSignin(t, ts, service, email, []byte("test1234"), nil, flowID, "Charon", "Dashboard") //nolint:bodyclose

	// Complete with user code.
	accessToken := completeUserCode(t, ts, service, smtpServer, resp, email, charon.CompletedSignup, []charon.Provider{charon.ProviderPassword, charon.ProviderCode}, nil, flowID, "Charon", "Dashboard", nonce, state, pkceVerifier, config, verifier)

	credentialRef := assertEmailAndPasswordCredential(t, ts, service, accessToken, email)

	signoutUser(t, ts, service, accessToken)

	username2 := "username2"
	flowID2, nonce2, state2, pkceVerifier2, config2, verifier2 := createAuthFlow(t, ts, service)
	accessToken2, _ := signinUser(t, ts, service, username2, username2, charon.CompletedSignup, flowID2, nonce2, state2, pkceVerifier2, config2, verifier2)

	for i := range credentialRef {
		// Different user cannot access first user's credentials and HTTP response is 404 NotFound.
		credentialGet, errE := service.ReverseAPI("CredentialGet", waf.Params{"id": credentialRef[i].ID.String()}, nil)
		require.NoError(t, errE, "% -+#.1v", errE)

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+credentialGet, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+accessToken2)

		resp, err = ts.Client().Do(req) //nolint:bodyclose
		require.NoError(t, err)
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
	}
}

func TestCredentialManagement(t *testing.T) {
	t.Parallel()

	ts, service, _, oidcTS, _ := startTestServer(t)

	// Signup with OIDC.
	accessToken, identityID := oidcSignin(t, ts, service, oidcTS, charon.CompletedSignup)

	credentialRefs := credentialListGet(t, ts, service, accessToken, 1)
	// OIDC is the only existing credential.
	oidcCredentialID := credentialRefs[0].ID

	usernameCredentialID := credentialAddUsername(t, ts, service, accessToken, " MyCustomUsErNaMe   ")
	emailCredentialID := credentialAddEmail(t, ts, service, accessToken, "  EmAiL@example.com ")
	passwordCredentialID := credentialAddPassword(t, ts, service, accessToken, []byte("test1234"), " My default password ")
	passkeyCredentialID, rsaKey, publicKeyID, credentialID, rawAuthData, userID := credentialAddPasskey(t, ts, service, accessToken, " My first passkey  ")

	credentialRefs = credentialListGet(t, ts, service, accessToken, 5)

	credentialMap := make(map[identifier.Identifier]charon.CredentialPublic)
	for _, credentialRef := range credentialRefs {
		credential := credentialGet(t, ts, service, accessToken, credentialRef.ID)

		credentialMap[credentialRef.ID] = credential
	}

	assert.Equal(t, "OIDCusername", credentialMap[oidcCredentialID].DisplayName)
	assert.Equal(t, "My default password", credentialMap[passwordCredentialID].DisplayName)
	assert.Equal(t, "My first passkey", credentialMap[passkeyCredentialID].DisplayName)

	credentialRename(t, ts, service, accessToken, oidcCredentialID, " My OIDC Login   ", false)
	credentialRename(t, ts, service, accessToken, passwordCredentialID, " My super secret password ", false)
	credentialRename(t, ts, service, accessToken, passkeyCredentialID, " My renamed passkey ", true)

	// TODO: After email verification is done, test signin with different case email and password as well.
	// Sign-out and sign-in with newly added credentials - username+password.
	signoutUser(t, ts, service, accessToken)
	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)
	// We test "MyCustomUsErNaMe" in a different case to verify that signin w/ username is case-insensitive.
	accessToken, identityID2 := signinUser(t, ts, service, "Mycustomusername", "OIDCusername", charon.CompletedSignin, flowID, nonce, state, pkceVerifier, config, verifier)
	assert.Equal(t, identityID, identityID2)
	// Sign-out and sign-in with newly added credentials - passkey.
	signoutUser(t, ts, service, accessToken)
	accessToken, identityID3 := signinMockPasskey(t, ts, service, "OIDCusername", rsaKey, publicKeyID, credentialID, rawAuthData, userID)
	assert.Equal(t, identityID, identityID3)

	// Update CredentialPublic in credentialMap after rename.
	for _, credentialRef := range credentialRefs {
		credential := credentialGet(t, ts, service, accessToken, credentialRef.ID)

		credentialMap[credentialRef.ID] = credential
	}
	assert.Len(t, credentialMap, 5)

	oidcCred := credentialMap[oidcCredentialID]
	assert.Equal(t, "oidcTesting", string(oidcCred.Provider))
	assert.Equal(t, "My OIDC Login", oidcCred.DisplayName)
	assert.False(t, oidcCred.Verified)

	usernameCred := credentialMap[usernameCredentialID]
	assert.Equal(t, charon.ProviderUsername, usernameCred.Provider)
	assert.Equal(t, "MyCustomUsErNaMe", usernameCred.DisplayName)
	assert.False(t, usernameCred.Verified)

	emailCred := credentialMap[emailCredentialID]
	assert.Equal(t, charon.ProviderEmail, emailCred.Provider)
	assert.Equal(t, "EmAiL@example.com", emailCred.DisplayName)
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

	credentialRemove(t, ts, service, accessToken, usernameCredentialID, false)
	credentialRemove(t, ts, service, accessToken, emailCredentialID, false)
	credentialRemove(t, ts, service, accessToken, oidcCredentialID, false)

	// Test no-op w/ passkey rename.
	resp := credentialRenameStart(t, ts, service, accessToken, passkeyCredentialID, "My renamed passkey") //nolint:bodyclose

	var renameResponsePasskey charon.CredentialResponse
	errE := x.DecodeJSONWithoutUnknownFields(resp.Body, &renameResponsePasskey)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Empty(t, renameResponsePasskey.Error)
	assert.True(t, renameResponsePasskey.Success)
	assert.NotEmpty(t, renameResponsePasskey.Signal)

	credentialRemove(t, ts, service, accessToken, passkeyCredentialID, true)

	// Test ErrorCodeCredentialDisplayNameInUse, add second credential that supports renaming.
	passwordCredentialID2 := credentialAddPassword(t, ts, service, accessToken, []byte("test4321"), " My second password ")
	resp = credentialRenameStart(t, ts, service, accessToken, passwordCredentialID2, "My super secret password") //nolint:bodyclose

	var renameResponsePassword charon.CredentialResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &renameResponsePassword)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.NotEmpty(t, renameResponsePassword.Error)
	assert.Equal(t, charon.ErrorCodeCredentialDisplayNameInUse, renameResponsePassword.Error)
	assert.False(t, renameResponsePassword.Success)
	assert.Empty(t, renameResponsePassword.Signal)

	credentialRemove(t, ts, service, accessToken, passwordCredentialID, false)
	credentialRemove(t, ts, service, accessToken, passwordCredentialID2, false)

	// TODO: We should probably not allow user to remove all credentials.
	//       So this part of the test will probably change in the future.
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

func credentialAddPasskey(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken, displayName string) (identifier.Identifier, *rsa.PrivateKey, string, []byte, []byte, []byte) {
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

	userID, err := base64.RawURLEncoding.DecodeString(addPasskeyStartResponse.Passkey.CreateOptions.Response.User.ID.(string)) //nolint:errcheck,forcetypeassert
	require.NoError(t, err)

	AuthFlowPasskeyCreateCompleteRequest, rsaKey, publicKeyID, credentialID, rawAuthData := createMockPasskeyCredential(t, ts, addPasskeyStartResponse.Passkey)

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
	return *addPasskeyCompleteResponse.CredentialID, rsaKey, publicKeyID, credentialID, rawAuthData, userID
}

func credentialRemove(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, credentialID identifier.Identifier, isPasskey bool) {
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
	if isPasskey {
		assert.Nil(t, removeResponse.Signal.Update)
		assert.NotNil(t, removeResponse.Signal.Remove)
	} else {
		assert.Nil(t, removeResponse.Signal)
	}
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
		assert.NotNil(t, renameResponse.Signal.Update)
		assert.Nil(t, renameResponse.Signal.Remove)
	} else {
		assert.Nil(t, renameResponse.Signal)
	}
}
