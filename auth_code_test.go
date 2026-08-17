package charon_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	smtpmock "github.com/mocktools/go-smtp-mock/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
	"golang.org/x/oauth2"

	"gitlab.com/charon/charon"
)

func TestAuthFlowCodeOnly(t *testing.T) {
	t.Parallel()

	user := identifier.New().String()
	email := user + "@example.com"

	ts, service, smtpServer, _, _ := startTestServer(t)

	accessToken := signinUserCode(t, ts, service, smtpServer, email, charon.CompletedSignup)

	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderCode}, 0, 1, 0, 1},
		{charon.ActivityOrganizationUpdate, []charon.ActivityChangeType{charon.ActivityChangePermissionsAdded}, nil, 1, 1, 0, 0},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})

	signoutUser(t, ts, service, accessToken)

	accessToken = signinUserCode(t, ts, service, smtpServer, email, charon.CompletedSignin)

	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderCode}, 0, 1, 0, 1}, // Second signin.
		{charon.ActivitySignOut, nil, nil, 0, 0, 0, 0},                                   // Signout.
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderCode}, 0, 1, 0, 1},
		{charon.ActivityOrganizationUpdate, []charon.ActivityChangeType{charon.ActivityChangePermissionsAdded}, nil, 1, 1, 0, 0},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})
}

func TestAuthFlowPasswordAndCode(t *testing.T) {
	t.Parallel()

	user := identifier.New().String()
	email := user + "@example.com"

	ts, service, smtpServer, _, _ := startTestServer(t)

	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)

	// Start password authentication with e-mail address.
	resp := startPasswordSignin(t, ts, service, email, []byte("test1234"), nil, flowID, "Charon", "Dashboard") //nolint:bodyclose

	// Complete with user code.
	accessToken := completeUserCode(t, ts, service, smtpServer, resp, email, charon.CompletedSignup, []charon.Provider{charon.ProviderPassword, charon.ProviderCode}, nil, flowID, "Charon", "Dashboard", nonce, state, pkceVerifier, config, verifier)

	// Check that confirmed email and password credentials are listed.
	assertEmailAndPasswordCredential(t, ts, service, accessToken, email)

	// Verify complete activity sequence for signup.
	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderPassword, charon.ProviderCode}, 0, 1, 0, 1},
		{charon.ActivityOrganizationUpdate, []charon.ActivityChangeType{charon.ActivityChangePermissionsAdded}, nil, 1, 1, 0, 0},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})

	signoutUser(t, ts, service, accessToken)

	// Signed-up user can authenticate with code only.
	accessToken = signinUserCode(t, ts, service, smtpServer, email, charon.CompletedSignin)

	signoutUser(t, ts, service, accessToken)

	// Signed-up user can authenticate with password only.
	flowID, nonce, state, pkceVerifier, config, verifier = createAuthFlow(t, ts, service)
	accessToken, _ = signinUser(t, ts, service, email, email, charon.CompletedSignin, flowID, nonce, state, pkceVerifier, config, verifier)

	signoutUser(t, ts, service, accessToken)

	// Sign-in with invalid password is the same as sign-up.
	flowID, nonce, state, pkceVerifier, config, verifier = createAuthFlow(t, ts, service)
	resp = startPasswordSignin(t, ts, service, email, []byte("test4321"), nil, flowID, "Charon", "Dashboard") //nolint:bodyclose

	// Complete with user code.
	accessToken = completeUserCode(t, ts, service, smtpServer, resp, email, charon.CompletedSignin, []charon.Provider{charon.ProviderPassword, charon.ProviderCode}, nil, flowID, "Charon", "Dashboard", nonce, state, pkceVerifier, config, verifier)

	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderPassword, charon.ProviderCode}, 0, 1, 0, 1}, // Final signin (password with wrong password -> code).
		{charon.ActivitySignOut, nil, nil, 0, 0, 0, 0},                                                            // Signout after password-only auth.
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderPassword}, 0, 1, 0, 1},                      // Signin password-only.
		{charon.ActivitySignOut, nil, nil, 0, 0, 0, 0},                                                            // Signout after code-only auth.
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderCode}, 0, 1, 0, 1},                          // Signin code-only.
		{charon.ActivitySignOut, nil, nil, 0, 0, 0, 0},                                                            // Signout after initial password+code.
		{charon.ActivitySignIn, nil, []charon.Provider{charon.ProviderPassword, charon.ProviderCode}, 0, 1, 0, 1},
		{charon.ActivityOrganizationUpdate, []charon.ActivityChangeType{charon.ActivityChangePermissionsAdded}, nil, 1, 1, 0, 0},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})
}

func signinUserCode(t *testing.T, ts *httptest.Server, service *charon.Service, smtpServer *smtpmock.Server, emailOrUsername string, signinOrSignout charon.Completed) string {
	t.Helper()

	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)

	authFlowCodeStart, errE := service.ReverseAPI("AuthFlowCodeStart", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Start code authentication.
	resp, err := ts.Client().Post(ts.URL+authFlowCodeStart, "application/json", strings.NewReader(`{"emailOrUsername":"`+emailOrUsername+`"}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)

	return completeUserCode(t, ts, service, smtpServer, resp, emailOrUsername, signinOrSignout, []charon.Provider{charon.ProviderCode}, nil, flowID, "Charon", "Dashboard", nonce, state, pkceVerifier, config, verifier)
}

func completeUserCode(t *testing.T, ts *httptest.Server, service *charon.Service, smtpServer *smtpmock.Server, resp *http.Response, emailOrUsername string, signinOrSignout charon.Completed, providers []charon.Provider, organizationID *identifier.Identifier, flowID identifier.Identifier, organization, app, nonce, state, pkceVerifier string, config *oauth2.Config, verifier *oidc.IDTokenVerifier) string { //nolint:unparam
	t.Helper()

	assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{}, providers, emailOrUsername, assertAppName(t, organization, app))

	messages, err := smtpServer.WaitForMessagesAndPurge(1, time.Second)
	require.NoError(t, err)
	require.Len(t, messages, 1)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is still available.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, organizationID, []charon.Completed{}, providers, emailOrUsername, assertAppName(t, organization, app))
	}

	nonAPIAuthFlowGet, errE := service.Reverse("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	r, err := regexp.Compile(regexp.QuoteMeta(fmt.Sprintf("%s%s#code=3D", ts.URL, nonAPIAuthFlowGet)) + `(\d+)`)
	require.NoError(t, err)

	match := r.FindStringSubmatch(messages[len(messages)-1].MsgRequest())
	require.NotNil(t, match)

	authFlowCodeComplete, errE := service.ReverseAPI("AuthFlowCodeComplete", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Complete code authentication.
	resp, err = ts.Client().Post(ts.URL+authFlowCodeComplete, "application/json", strings.NewReader(`{"code":"`+match[1]+`"}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	assertSignedUser(t, signinOrSignout, flowID, resp)

	// Flow is available and signinOrSignout is completed.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	require.NoError(t, err)
	oid := assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{signinOrSignout}, providers, "", assertAppName(t, organization, app))

	chooseIdentity(t, ts, service, oid, flowID, organization, app, signinOrSignout, providers, 1, emailOrUsername)
	return doRedirectAndAccessToken(t, ts, service, oid, flowID, organization, app, nonce, state, pkceVerifier, config, verifier, signinOrSignout, providers)
}

// TestAuthFlowPasswordSignupRaceWithExistingAccount exercises the wide-window race
// in the email-based password sign-up: two flows start before any account exists,
// both pin flow.Code.AccountID = nil at password submit, both send codes to the
// same address. When the second flow's code is confirmed, AuthFlowCodeCompletePostAPI
// re-checks getAccountByCredential and pivots to the account created by the first
// flow, signing the user in instead of creating a duplicate account.
func TestAuthFlowPasswordSignupRaceWithExistingAccount(t *testing.T) {
	t.Parallel()

	user := identifier.New().String()
	email := user + "@example.com"

	ts, service, smtpServer, _, _ := startTestServer(t)

	// Two concurrent sign-up flows for the same address with different passwords.
	flowIDA, _, _, _, _, _ := createAuthFlow(t, ts, service) //nolint:dogsled
	flowIDB, _, _, _, _, _ := createAuthFlow(t, ts, service) //nolint:dogsled

	respA := startPasswordSignin(t, ts, service, email, []byte("passA1234"), nil, flowIDA, "Charon", "Dashboard")
	t.Cleanup(func() { _ = respA.Body.Close() })
	respB := startPasswordSignin(t, ts, service, email, []byte("passB1234"), nil, flowIDB, "Charon", "Dashboard")
	t.Cleanup(func() { _ = respB.Body.Close() })

	// Both flows have sent a code email to the same inbox.
	messages, err := smtpServer.WaitForMessagesAndPurge(2, 2*time.Second)
	require.NoError(t, err)
	require.Len(t, messages, 2)

	codeFor := func(flowID identifier.Identifier) string {
		t.Helper()
		nonAPIAuthFlowGet, errE := service.Reverse("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
		require.NoError(t, errE, "% -+#.1v", errE)
		r, err := regexp.Compile(regexp.QuoteMeta(fmt.Sprintf("%s%s#code=3D", ts.URL, nonAPIAuthFlowGet)) + `(\d+)`)
		require.NoError(t, err)
		for _, m := range messages {
			match := r.FindStringSubmatch(m.MsgRequest())
			if match != nil {
				return match[1]
			}
		}
		t.Fatalf("code not found for flow %s", flowID)
		return ""
	}
	codeA := codeFor(flowIDA)
	codeB := codeFor(flowIDB)

	submitCode := func(flowID identifier.Identifier, code string) *http.Response {
		t.Helper()
		authFlowCodeComplete, errE := service.ReverseAPI("AuthFlowCodeComplete", waf.Params{"id": flowID.String()}, nil)
		require.NoError(t, errE, "% -+#.1v", errE)
		resp, err := ts.Client().Post(ts.URL+authFlowCodeComplete, "application/json", strings.NewReader(`{"code":"`+code+`"}`)) //nolint:noctx
		require.NoError(t, err)
		return resp
	}

	// Flow A confirms first. Creates the account, signs up.
	assertSignedUser(t, charon.CompletedSignup, flowIDA, submitCode(flowIDA, codeA)) //nolint:bodyclose

	// Flow B confirms second. Must pivot to the account A just created, completing as a sign-in.
	assertSignedUser(t, charon.CompletedSignin, flowIDB, submitCode(flowIDB, codeB)) //nolint:bodyclose

	// Both flow sessions point at the same account: no duplicate was created.
	ctx := t.Context()
	accountIDA, errE := service.TestingGetAccountIDFromFlow(ctx, flowIDA)
	require.NoError(t, errE, "% -+#.1v", errE)
	accountIDB, errE := service.TestingGetAccountIDFromFlow(ctx, flowIDB)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, accountIDA, accountIDB)
}
