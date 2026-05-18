package charon_test

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	smtpmock "github.com/mocktools/go-smtp-mock/v2"
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
			// Code confirmation marks email as confirmed and stores the mapped address.
			assert.NotEmpty(t, credential.Confirmed)
		case charon.ProviderPassword:
			assert.Equal(t, "default password", credential.DisplayName)
			assert.Empty(t, credential.Confirmed)
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

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+credentialGet, nil)
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

	ts, service, smtpServer, oidcTS, _ := startTestServer(t)

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

	credentialMap := map[identifier.Identifier]charon.CredentialPublic{}
	for _, credentialRef := range credentialRefs {
		credential := credentialGet(t, ts, service, accessToken, credentialRef.ID)

		credentialMap[credentialRef.ID] = credential
	}

	// Email credential is initially added as unconfirmed.
	assert.Empty(t, credentialMap[emailCredentialID].Confirmed)
	assert.Equal(t, "OIDCusername", credentialMap[oidcCredentialID].DisplayName)
	assert.Equal(t, "My default password", credentialMap[passwordCredentialID].DisplayName)
	assert.Equal(t, "My first passkey", credentialMap[passkeyCredentialID].DisplayName)

	credentialConfirmEmail(t, ts, service, smtpServer, accessToken, emailCredentialID.String())
	credentialRename(t, ts, service, accessToken, oidcCredentialID, " My OIDC Login   ", false)
	credentialRename(t, ts, service, accessToken, passwordCredentialID, " My super secret password ", false)
	credentialRename(t, ts, service, accessToken, passkeyCredentialID, " My renamed passkey ", true)

	// Sign-out and sign-in with newly added credentials - e-mail+password.
	signoutUser(t, ts, service, accessToken)
	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)
	// We test "EmAiL@example.com" in a different case to verify that signin w/ e-mail is case-insensitive.
	accessToken, identityID2 := signinUser(t, ts, service, "Email@example.com", "OIDCusername", charon.CompletedSignin, flowID, nonce, state, pkceVerifier, config, verifier)
	assert.Equal(t, identityID, identityID2)
	// Sign-out and sign-in with newly added credentials - username+password.
	signoutUser(t, ts, service, accessToken)
	flowID, nonce, state, pkceVerifier, config, verifier = createAuthFlow(t, ts, service)
	// We test "MyCustomUsErNaMe" in a different case to verify that signin w/ username is case-insensitive.
	accessToken, identityID3 := signinUser(t, ts, service, "Mycustomusername", "OIDCusername", charon.CompletedSignin, flowID, nonce, state, pkceVerifier, config, verifier)
	assert.Equal(t, identityID, identityID3)
	// Sign-out and sign-in with newly added credentials - passkey.
	signoutUser(t, ts, service, accessToken)
	accessToken, identityID4 := signinMockPasskey(t, ts, service, "OIDCusername", rsaKey, publicKeyID, credentialID, rawAuthData, userID)
	assert.Equal(t, identityID, identityID4)

	// Update CredentialPublic in credentialMap after rename.
	for _, credentialRef := range credentialRefs {
		credential := credentialGet(t, ts, service, accessToken, credentialRef.ID)

		credentialMap[credentialRef.ID] = credential
	}
	assert.Len(t, credentialMap, 5)

	oidcCred := credentialMap[oidcCredentialID]
	assert.Equal(t, "oidcTesting", string(oidcCred.Provider))
	assert.Equal(t, "My OIDC Login", oidcCred.DisplayName)
	assert.Empty(t, oidcCred.Confirmed)

	usernameCred := credentialMap[usernameCredentialID]
	assert.Equal(t, charon.ProviderUsername, usernameCred.Provider)
	assert.Equal(t, "MyCustomUsErNaMe", usernameCred.DisplayName)
	assert.Empty(t, usernameCred.Confirmed)

	emailCred := credentialMap[emailCredentialID]
	assert.Equal(t, charon.ProviderEmail, emailCred.Provider)
	assert.Equal(t, "EmAiL@example.com", emailCred.DisplayName)
	// Confirmed holds the mapped (lowercased) form once the address is confirmed.
	assert.Equal(t, "email@example.com", emailCred.Confirmed)

	passwordCred := credentialMap[passwordCredentialID]
	assert.Equal(t, charon.ProviderPassword, passwordCred.Provider)
	assert.Equal(t, "My super secret password", passwordCred.DisplayName)
	assert.Empty(t, passwordCred.Confirmed)

	passkeyCred := credentialMap[passkeyCredentialID]
	assert.Equal(t, charon.ProviderPasskey, passkeyCred.Provider)
	assert.Equal(t, "My renamed passkey", passkeyCred.DisplayName)
	assert.Empty(t, passkeyCred.Confirmed)

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

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+credentialListGet, nil)
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

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+credentialGet, nil)
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

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+url, bytes.NewReader(addRequest))
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

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+credentialRemove, strings.NewReader("{}"))
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

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+credentialRename, bytes.NewReader(data))
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

func credentialConfirmEmail(t *testing.T, ts *httptest.Server, service *charon.Service, smtpServer *smtpmock.Server, accessToken string, emailCredentialID string) {
	t.Helper()

	credentialConfirmEmail, errE := service.ReverseAPI("CredentialConfirmEmail", waf.Params{"id": emailCredentialID}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+credentialConfirmEmail, strings.NewReader(`{}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var confirmResponse charon.CredentialResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &confirmResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Empty(t, confirmResponse.Error)
	assert.True(t, confirmResponse.Success)
	assert.Nil(t, confirmResponse.Signal)

	messages, err := smtpServer.WaitForMessagesAndPurge(1, time.Second)
	require.NoError(t, err)
	require.Len(t, messages, 1)

	nonAPICredentialConfirmEmail, errE := service.Reverse("CredentialConfirmEmail", waf.Params{"id": emailCredentialID}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Different regex pattern compared to auth_code due to longer route name, which causes line break.
	r, err := regexp.Compile(regexp.QuoteMeta(fmt.Sprintf("%s%s", ts.URL, nonAPICredentialConfirmEmail)) + `#code=\s*=3D(\d+)`)
	require.NoError(t, err)

	match := r.FindStringSubmatch(messages[len(messages)-1].MsgRequest())
	require.NotNil(t, match)
	code := match[1]

	credentialConfirmEmailComplete, errE := service.ReverseAPI("CredentialConfirmEmailComplete", waf.Params{"id": emailCredentialID}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	completeRequest := charon.CredentialConfirmEmailCompleteRequest{
		Code: code,
	}
	data, errE := x.MarshalWithoutEscapeHTML(completeRequest)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err = http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+credentialConfirmEmailComplete, bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var completeResponse charon.CredentialResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &completeResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Empty(t, completeResponse.Error)
	assert.True(t, completeResponse.Success)
	assert.Nil(t, completeResponse.Signal)
}

func TestCredentialRemoveEmailRemovesAddressFromIdentities(t *testing.T) {
	t.Parallel()

	user := identifier.New().String()
	email := user + "@example.com"
	_, mappedEmail, errE := charon.TestingValidateEmailOrUsername(email, charon.TestingEmailOrUsernameCheckEmail)
	require.NoError(t, errE, "% -+#.1v", errE)

	ts, service, smtpServer, _, _ := startTestServer(t)

	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)

	// Sign up via password+code so the account ends up with both a password credential
	// and a confirmed email credential, and the auto-created identity has Email set.
	resp := startPasswordSignin(t, ts, service, email, []byte("test1234"), nil, flowID, "Charon", "Dashboard") //nolint:bodyclose
	accessToken := completeUserCode(t, ts, service, smtpServer, resp, email, charon.CompletedSignup, []charon.Provider{charon.ProviderPassword, charon.ProviderCode}, nil, flowID, "Charon", "Dashboard", nonce, state, pkceVerifier, config, verifier)

	ctx := t.Context()
	accountID, errE := service.TestingGetAccountIDFromFlow(ctx, flowID)
	require.NoError(t, errE, "% -+#.1v", errE)

	access, errE := service.TestingGetIdentitiesAccess(accountID)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Len(t, access, 1)
	var identityRef charon.IdentityRef
	for ref := range access {
		identityRef = ref
	}

	ctx = service.TestingWithAccountID(ctx, accountID)
	ctx = service.TestingWithIdentityID(ctx, identityRef.ID)

	identity, _, errE := service.TestingGetIdentity(ctx, identityRef.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Equal(t, mappedEmail, identity.Email, "auto-created identity should have mapped email set after signup")

	// Look up the email and password credential IDs.
	credentialRefs := credentialListGet(t, ts, service, accessToken, 2)
	var emailCredentialID, passwordCredentialID identifier.Identifier
	var foundEmail, foundPassword bool
	for _, ref := range credentialRefs {
		cred := credentialGet(t, ts, service, accessToken, ref.ID)
		switch cred.Provider {
		case charon.ProviderEmail:
			emailCredentialID = ref.ID
			foundEmail = true
		case charon.ProviderPassword:
			passwordCredentialID = ref.ID
			foundPassword = true
		case charon.ProviderUsername, charon.ProviderPasskey, charon.ProviderCode:
			require.Fail(t, "unexpected credential provider", "provider: %s", cred.Provider)
		}
	}
	require.True(t, foundEmail, "expected email credential")
	require.True(t, foundPassword, "expected password credential")

	// Removing a non-email credential must not touch identity.Email.
	credentialRemove(t, ts, service, accessToken, passwordCredentialID, false)
	identity, _, errE = service.TestingGetIdentity(ctx, identityRef.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, mappedEmail, identity.Email, "non-email credential removal must not clear identity.Email")

	// Snapshot activities before the e-mail credential removal so we can isolate
	// what the removal logs.
	activitiesBefore, errE := service.TestingListActivities(t.Context())
	require.NoError(t, errE, "% -+#.1v", errE)

	// Removing the email credential must clear identity.Email.
	credentialRemove(t, ts, service, accessToken, emailCredentialID, false)
	identity, _, errE = service.TestingGetIdentity(ctx, identityRef.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Empty(t, identity.Email, "identity email should be removed after email credential removal")

	account, errE := service.TestingGetAccount(ctx, accountID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Empty(t, account.Credentials[charon.ProviderEmail], "email credential should be gone")

	// The removal must log an ActivityIdentityUpdate for I with ActivityChangeOtherData.
	activitiesAfter, errE := service.TestingListActivities(t.Context())
	require.NoError(t, errE, "% -+#.1v", errE)
	diffActivities := newActivities(activitiesBefore, activitiesAfter)
	require.Len(t, diffActivities, 1, "expected one activity")
	newActivity := diffActivities[0]
	assert.Equal(t, charon.ActivityIdentityUpdate, newActivity.Type)
	assert.Equal(t, []charon.ActivityChangeType{charon.ActivityChangeOtherData}, newActivity.Changes)
	require.Len(t, newActivity.Identities, 1)
	assert.Equal(t, identityRef, newActivity.Identities[0].Identity)
}

// newActivities returns activities present in after that were not in before,
// keyed by ID. Activity order across calls is unspecified.
func newActivities(before, after []*charon.Activity) []*charon.Activity {
	beforeIDs := map[identifier.Identifier]bool{}
	for _, a := range before {
		beforeIDs[*a.ID] = true
	}
	var added []*charon.Activity
	for _, a := range after {
		if !beforeIDs[*a.ID] {
			added = append(added, a)
		}
	}
	return added
}

// TestCredentialRemoveEmailRemovesAddressFromSharedIdentities verifies that even an
// identity which has been shared with additional admins has its Email cleared when the
// original creator removes their e-mail credential. Confirmed e-mail addresses are
// unique across accounts, so the removed credential was the only confirmation backing
// identity.Email anywhere; leaving the value would expose a globally-unconfirmed
// address as if it were verified.
func TestCredentialRemoveEmailRemovesAddressFromSharedIdentities(t *testing.T) {
	t.Parallel()

	user := identifier.New().String()
	email := user + "@example.com"
	_, mappedEmail, errE := charon.TestingValidateEmailOrUsername(email, charon.TestingEmailOrUsernameCheckEmail)
	require.NoError(t, errE, "% -+#.1v", errE)

	ts, service, smtpServer, _, _ := startTestServer(t)

	// Account A signs up via password+code with the e-mail; identity I is auto-created
	// with I.Email set to the mapped address.
	flowIDA, nonceA, stateA, pkceVerifierA, configA, verifierA := createAuthFlow(t, ts, service)
	respA := startPasswordSignin(t, ts, service, email, []byte("test1234"), nil, flowIDA, "Charon", "Dashboard") //nolint:bodyclose
	accessTokenA := completeUserCode(t, ts, service, smtpServer, respA, email, charon.CompletedSignup, []charon.Provider{charon.ProviderPassword, charon.ProviderCode}, nil, flowIDA, "Charon", "Dashboard", nonceA, stateA, pkceVerifierA, configA, verifierA)

	ctx := t.Context()
	accountIDA, errE := service.TestingGetAccountIDFromFlow(ctx, flowIDA)
	require.NoError(t, errE, "% -+#.1v", errE)

	accessA, errE := service.TestingGetIdentitiesAccess(accountIDA)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Len(t, accessA, 1)
	var identityRefA charon.IdentityRef
	for ref := range accessA {
		identityRefA = ref
	}

	signoutUser(t, ts, service, accessTokenA)

	// Account B signs up via username only. Gives us a second account whose identity Q
	// can be added to I.Admins via the real update path.
	otherUser := "other" + identifier.New().String()
	flowIDB, nonceB, stateB, pkceVerifierB, configB, verifierB := createAuthFlow(t, ts, service)
	accessTokenB, identityIDB := signinUser(t, ts, service, otherUser, otherUser, charon.CompletedSignup, flowIDB, nonceB, stateB, pkceVerifierB, configB, verifierB)
	signoutUser(t, ts, service, accessTokenB)

	// Share I with B by adding B's identity Q as an admin of I, going through the same
	// update + validation path the API would use.
	ctxA := service.TestingWithAccountID(t.Context(), accountIDA)
	ctxA = service.TestingWithIdentityID(ctxA, identityRefA.ID)
	ctxA = service.TestingWithSessionID(ctxA)
	ctxA = service.TestingWithRequestID(ctxA)

	identityA, _, errE := service.TestingGetIdentity(ctxA, identityRefA.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Equal(t, mappedEmail, identityA.Email)
	require.Equal(t, []charon.IdentityRef{identityRefA}, identityA.Admins, "fresh sign-up identity should be its own only admin")

	identityA.Admins = append(identityA.Admins, charon.IdentityRef{ID: identityIDB})
	errE = service.TestingUpdateIdentity(ctxA, identityA)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Confirm the share actually landed: I.Admins contains both A's self-admin and Q.
	identityA, _, errE = service.TestingGetIdentity(ctxA, identityRefA.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.ElementsMatch(t, []charon.IdentityRef{identityRefA, {ID: identityIDB}}, identityA.Admins)

	// Sign back in as A to drive the credential removal through the real API.
	flowIDA2, nonceA2, stateA2, pkceVerifierA2, configA2, verifierA2 := createAuthFlow(t, ts, service)
	accessTokenA, _ = signinUser(t, ts, service, email, email, charon.CompletedSignin, flowIDA2, nonceA2, stateA2, pkceVerifierA2, configA2, verifierA2)

	credentialRefs := credentialListGet(t, ts, service, accessTokenA, 2)
	var emailCredentialID identifier.Identifier
	var found bool
	for _, ref := range credentialRefs {
		cred := credentialGet(t, ts, service, accessTokenA, ref.ID)
		if cred.Provider == charon.ProviderEmail {
			emailCredentialID = ref.ID
			found = true
			break
		}
	}
	require.True(t, found, "expected email credential")

	activitiesBefore, errE := service.TestingListActivities(t.Context())
	require.NoError(t, errE, "% -+#.1v", errE)

	credentialRemove(t, ts, service, accessTokenA, emailCredentialID, false)

	// Even though I is now shared with B, the removed credential was the only confirmation
	// for this address anywhere, so clearing identity.Email is correct.
	identityA, _, errE = service.TestingGetIdentity(ctxA, identityRefA.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Empty(t, identityA.Email, "shared identity should be cleared because confirmed emails are globally unique")

	activitiesAfter, errE := service.TestingListActivities(t.Context())
	require.NoError(t, errE, "% -+#.1v", errE)
	diffActivities := newActivities(activitiesBefore, activitiesAfter)
	require.Len(t, diffActivities, 1)
	newActivity := diffActivities[0]
	assert.Equal(t, charon.ActivityIdentityUpdate, newActivity.Type)
	assert.Equal(t, []charon.ActivityChangeType{charon.ActivityChangeOtherData}, newActivity.Changes)
	require.Len(t, newActivity.Identities, 1)
	assert.Equal(t, identityRefA, newActivity.Identities[0].Identity)
}

// TestCredentialRemoveEmailRemovesAddressFromTransferredIdentity covers the case that
// the original creator's admin entry on the identity is removed (ownership transferred
// to another account) and only then they remove their e-mail credential. The removal has
// to clear the e-mail even on identities the credential-removing account no longer admins,
// because confirmed e-mail addresses are globally unique and the removed credential was
// the only confirmation backing the address anywhere.
func TestCredentialRemoveEmailRemovesAddressFromTransferredIdentity(t *testing.T) {
	t.Parallel()

	user := identifier.New().String()
	email := user + "@example.com"
	_, mappedEmail, errE := charon.TestingValidateEmailOrUsername(email, charon.TestingEmailOrUsernameCheckEmail)
	require.NoError(t, errE, "% -+#.1v", errE)

	ts, service, smtpServer, _, _ := startTestServer(t)

	// Account A signs up with the e-mail; identity I is auto-created as I's own only admin.
	flowIDA, nonceA, stateA, pkceVerifierA, configA, verifierA := createAuthFlow(t, ts, service)
	respA := startPasswordSignin(t, ts, service, email, []byte("test1234"), nil, flowIDA, "Charon", "Dashboard") //nolint:bodyclose
	accessTokenA := completeUserCode(t, ts, service, smtpServer, respA, email, charon.CompletedSignup, []charon.Provider{charon.ProviderPassword, charon.ProviderCode}, nil, flowIDA, "Charon", "Dashboard", nonceA, stateA, pkceVerifierA, configA, verifierA)

	ctx := t.Context()
	accountIDA, errE := service.TestingGetAccountIDFromFlow(ctx, flowIDA)
	require.NoError(t, errE, "% -+#.1v", errE)

	accessA, errE := service.TestingGetIdentitiesAccess(accountIDA)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Len(t, accessA, 1)
	var identityRefA charon.IdentityRef
	for ref := range accessA {
		identityRefA = ref
	}

	// Sign A out so the later sign-in (after the ownership transfer) starts cleanly.
	signoutUser(t, ts, service, accessTokenA)

	// Account B signs up so we have a real identity to share I with. We don't sign A out;
	// A's bearer access token stays valid even though ts.Client() cookies become B's.
	otherUser := "other" + identifier.New().String()
	flowIDB, nonceB, stateB, pkceVerifierB, configB, verifierB := createAuthFlow(t, ts, service)
	accessTokenB, identityIDB := signinUser(t, ts, service, otherUser, otherUser, charon.CompletedSignup, flowIDB, nonceB, stateB, pkceVerifierB, configB, verifierB)
	accountIDB, errE := service.TestingGetAccountIDFromFlow(ctx, flowIDB)
	require.NoError(t, errE, "% -+#.1v", errE)
	signoutUser(t, ts, service, accessTokenB)

	// As A: add B's identity Q to I.Admins (sharing).
	ctxA := service.TestingWithAccountID(t.Context(), accountIDA)
	ctxA = service.TestingWithIdentityID(ctxA, identityRefA.ID)
	ctxA = service.TestingWithSessionID(ctxA)
	ctxA = service.TestingWithRequestID(ctxA)

	identityA, _, errE := service.TestingGetIdentity(ctxA, identityRefA.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	identityA.Admins = append(identityA.Admins, charon.IdentityRef{ID: identityIDB})
	errE = service.TestingUpdateIdentity(ctxA, identityA)
	require.NoError(t, errE, "% -+#.1v", errE)

	// As B: drop A's self-admin entry, leaving I.Admins = [Q]. A is no longer admin of I.
	ctxB := service.TestingWithAccountID(t.Context(), accountIDB)
	ctxB = service.TestingWithIdentityID(ctxB, identityIDB)
	ctxB = service.TestingWithSessionID(ctxB)
	ctxB = service.TestingWithRequestID(ctxB)

	identityFromB, _, errE := service.TestingGetIdentity(ctxB, identityRefA.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	identityFromB.Admins = []charon.IdentityRef{{ID: identityIDB}}
	errE = service.TestingUpdateIdentity(ctxB, identityFromB)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Confirm the transfer landed: I.Admins is now exactly [Q].
	identityFromB, _, errE = service.TestingGetIdentity(ctxB, identityRefA.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Equal(t, []charon.IdentityRef{{ID: identityIDB}}, identityFromB.Admins)

	// A no longer has access to I.
	_, _, errE = service.TestingGetIdentity(ctxA, identityRefA.ID)
	require.ErrorIs(t, errE, charon.ErrIdentityUnauthorized)

	// Sign A back in. A has 0 identities accessible after the transfer, so chooseIdentity
	// will auto-create a new one for A - that becomes the active identity in A's session
	// and will be the actor recorded on the new activity.
	flowIDA2, nonceA2, stateA2, pkceVerifierA2, configA2, verifierA2 := createAuthFlow(t, ts, service)
	accessTokenA2, newIdentityIDA := signinUser(t, ts, service, email, email, charon.CompletedSignin, flowIDA2, nonceA2, stateA2, pkceVerifierA2, configA2, verifierA2)

	// chooseIdentity's auto-create helper adds a "user@example.com" e-mail credential to
	// A's account so the new identity passes validation, so A now has password + 2 emails.
	credentialRefs := credentialListGet(t, ts, service, accessTokenA2, 3)
	var emailCredentialID identifier.Identifier
	var found bool
	for _, ref := range credentialRefs {
		cred := credentialGet(t, ts, service, accessTokenA2, ref.ID)
		// Pick the original e-mail credential (the one whose mapped form matches I's e-mail),
		// not the helper-added "user@example.com".
		if cred.Provider == charon.ProviderEmail && cred.Confirmed == mappedEmail {
			emailCredentialID = ref.ID
			found = true
			break
		}
	}
	require.True(t, found, "expected original email credential")

	activitiesBefore, errE := service.TestingListActivities(t.Context())
	require.NoError(t, errE, "% -+#.1v", errE)

	credentialRemove(t, ts, service, accessTokenA2, emailCredentialID, false)

	// Verify from B's perspective (A no longer has access) that I.Email was cleared.
	identityFromB, _, errE = service.TestingGetIdentity(ctxB, identityRefA.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Empty(t, identityFromB.Email, "transferred identity should be cleared even though A no longer admins it")

	// The removal logs ActivityIdentityUpdate against I (the affected identity) with
	// A's currently-active identity (the freshly-created one) as the actor.
	activitiesAfter, errE := service.TestingListActivities(t.Context())
	require.NoError(t, errE, "% -+#.1v", errE)
	diffActivities := newActivities(activitiesBefore, activitiesAfter)
	require.Len(t, diffActivities, 1)
	newActivity := diffActivities[0]
	assert.Equal(t, charon.ActivityIdentityUpdate, newActivity.Type)
	assert.Equal(t, []charon.ActivityChangeType{charon.ActivityChangeOtherData}, newActivity.Changes)
	require.Len(t, newActivity.Identities, 1)
	assert.Equal(t, identityRefA, newActivity.Identities[0].Identity)
	require.NotNil(t, newActivity.Actor)
	assert.Equal(t, newIdentityIDA, newActivity.Actor.Identity.ID, "actor should be A's new active identity, not the transferred-away one")
}
