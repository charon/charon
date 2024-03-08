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

func oidcSignin(t *testing.T, ts *httptest.Server, service *charon.Service, oidcTS *httptest.Server, signinOrSignout charon.Completed) {
	t.Helper()

	oidcClient := oidcTS.Client()

	flowID := createAuthFlow(t, ts, service)

	authFlowProviderStart, errE := service.ReverseAPI("AuthFlowProviderStart", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Start OIDC.
	resp, err := ts.Client().Post(ts.URL+authFlowProviderStart, "application/json", strings.NewReader(`{"provider":"testing"}`)) //nolint:noctx,bodyclose
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
	assert.Equal(t, charon.Provider("testing"), authFlowResponse.Provider)
	require.NotNil(t, authFlowResponse.Location)
	assert.False(t, authFlowResponse.Location.Replace)
	require.True(t, strings.HasPrefix(authFlowResponse.Location.URL, oidcTS.URL), authFlowResponse.Location.URL)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available, current provider is testing.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"testing"}`, string(out))
	}

	// Redirect to our testing provider.
	resp, err = oidcClient.Get(authFlowResponse.Location.URL) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, string(out))
	require.True(t, strings.HasPrefix(resp.Header.Get("Location"), ts.URL), resp.Header.Get("Location"))
	location := resp.Header.Get("Location")

	// Flow has not yet changed, current provider is testing.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"testing"}`, string(out))
	}

	// Redirect to OIDC callback.
	resp, err = ts.Client().Get(location) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, string(out))
	location = resp.Header.Get("Location")
	assert.NotEmpty(t, location)

	route, errE := service.GetRoute(location, http.MethodGet)
	assert.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, "AuthFlowGet", route.Name)

	// Flow is available and is completed.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"testing","completed":"`+string(signinOrSignout)+`","location":{"url":"/","replace":true}}`, string(out))
	}
}

func TestAuthFlowOIDC(t *testing.T) {
	t.Parallel()

	ts, service, _, oidcTS := startTestServer(t)

	// Signup with OIDC.
	oidcSignin(t, ts, service, oidcTS, charon.CompletedSignup)

	signoutUser(t, ts, service)

	// Signin with OIDC.
	oidcSignin(t, ts, service, oidcTS, charon.CompletedSignin)
}
