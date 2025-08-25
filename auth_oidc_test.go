package charon_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

const (
	oidcTestingClientID = "testing-client"
	oidcTestingSecret   = "testing-client-secret"
)

func startOIDCTestServer(t *testing.T) (*httptest.Server, *storage.MemoryStore) {
	t.Helper()

	var ts *httptest.Server
	var oauth2Provider fosite.OAuth2Provider

	store := storage.NewMemoryStore()

	privateKey, errE := charon.GenerateRSAKey()
	require.NoError(t, errE, "% -+#.1v", errE)

	// We use one unique subject per instance for testing.
	subject := identifier.New().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"issuer":"` + ts.URL + `",
			"authorization_endpoint":"` + ts.URL + `/auth",
			"token_endpoint":"` + ts.URL + `/token",
			"jwks_uri":"` + ts.URL + `/jwks",
			"id_token_signing_alg_values_supported":["RS256"],
			"code_challenge_methods_supported":["S256"]
		}`))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		keys := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{privateKey.Public()},
		}
		data, errE := x.MarshalWithoutEscapeHTML(keys)
		if errE != nil {
			http.Error(w, errE.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		ar, err := oauth2Provider.NewAuthorizeRequest(ctx, req)
		if err != nil {
			oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
			return
		}

		for _, audience := range ar.GetRequestedAudience() {
			ar.GrantAudience(audience)
		}
		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}

		session := openid.NewDefaultSession()
		session.SetSubject(subject)
		session.IDTokenClaims().Subject = subject
		session.IDTokenClaims().AuthTime = time.Now().UTC()

		response, err := oauth2Provider.NewAuthorizeResponse(ctx, ar, session)
		if err != nil {
			oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
			return
		}

		oauth2Provider.WriteAuthorizeResponse(ctx, w, ar, response)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()

		session := openid.NewDefaultSession()

		accessRequest, err := oauth2Provider.NewAccessRequest(ctx, req, session)
		if err != nil {
			oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		response, err := oauth2Provider.NewAccessResponse(ctx, accessRequest)
		if err != nil {
			oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		oauth2Provider.WriteAccessResponse(ctx, w, accessRequest, response)
	})

	ts = httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	secret := []byte("my super secret signing password")
	config := &fosite.Config{
		IDTokenIssuer:              ts.URL,
		SendDebugMessagesToClients: true,
		EnforcePKCE:                true,
		TokenURL:                   ts.URL + "/token",
		JWTScopeClaimKey:           jwt.JWTScopeFieldString,
		AccessTokenIssuer:          ts.URL,
		GlobalSecret:               secret,
	}

	oauth2Provider = compose.ComposeAllEnabled(config, store, privateKey)

	hashedSecret, err := config.GetSecretsHasher(context.Background()).Hash(context.Background(), []byte(oidcTestingSecret))
	require.NoError(t, err)

	// We set everything except the redirect. We set redirect in the caller of this function,
	// when the main testing server is running and we know its address.
	store.Clients[oidcTestingClientID] = &fosite.DefaultClient{
		ID:            oidcTestingClientID,
		Secret:        hashedSecret,
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		Public:        false,
	}

	return ts, store
}

func oidcSignin(t *testing.T, ts *httptest.Server, service *charon.Service, oidcTS *httptest.Server, signinOrSignout charon.Completed) string {
	t.Helper()

	oidcClient := oidcTS.Client()

	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)

	authFlowProviderStart, errE := service.ReverseAPI("AuthFlowProviderStart", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Start OIDC.
	resp, err := ts.Client().Post(ts.URL+authFlowProviderStart, "application/json", strings.NewReader(`{"provider":"testing"}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authFlowResponse charon.AuthFlowResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, []charon.Provider{"testing"}, authFlowResponse.Providers)
	require.NotNil(t, authFlowResponse.ThirdPartyProvider)
	require.True(t, strings.HasPrefix(authFlowResponse.ThirdPartyProvider.Location, oidcTS.URL), authFlowResponse.ThirdPartyProvider.Location)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available, current provider is testing.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{}, []charon.Provider{"testing"}, "", assertCharonDashboard)
	}

	// Redirect to our testing provider.
	resp, err = oidcClient.Get(authFlowResponse.ThirdPartyProvider.Location) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, string(out))
	require.True(t, strings.HasPrefix(resp.Header.Get("Location"), ts.URL), resp.Header.Get("Location"))
	location := resp.Header.Get("Location")

	// Flow has not yet changed, current provider is testing.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{}, []charon.Provider{"testing"}, "", assertCharonDashboard)
	}

	// Redirect to OIDC callback.
	resp, err = ts.Client().Get(location) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, string(out))
	location = resp.Header.Get("Location")
	assert.NotEmpty(t, location)

	route, errE := service.GetRoute(location, http.MethodGet)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, "AuthFlowGet", route.Name)

	// Flow is available and signinOrSignout is completed.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	require.NoError(t, err)
	oid := assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{signinOrSignout}, []charon.Provider{"testing"}, "", assertCharonDashboard)

	chooseIdentity(t, ts, service, oid, flowID, "Charon", "Dashboard", signinOrSignout, []charon.Provider{"testing"}, 1, "username")
	return doRedirectAndAccessToken(t, ts, service, oid, flowID, "Charon", "Dashboard", nonce, state, pkceVerifier, config, verifier, signinOrSignout, []charon.Provider{"testing"})
}

func TestAuthFlowOIDC(t *testing.T) {
	t.Parallel()

	ts, service, _, oidcTS := startTestServer(t)

	// Signup with OIDC.
	accessToken := oidcSignin(t, ts, service, oidcTS, charon.CompletedSignup)

	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{"testing"}, 0, 1, 0, 1},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})

	signoutUser(t, ts, service, accessToken)

	// Signin with OIDC.
	accessToken = oidcSignin(t, ts, service, oidcTS, charon.CompletedSignin)

	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{"testing"}, 0, 1, 0, 1}, // Signin.
		{charon.ActivitySignOut, nil, nil, 0, 0, 0, 0},                         // Signout.
		{charon.ActivitySignIn, nil, []charon.Provider{"testing"}, 0, 1, 0, 1},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})
}
