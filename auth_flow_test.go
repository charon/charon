package charon_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func assertFlowResponse(t *testing.T, ts *httptest.Server, service *charon.Service, resp *http.Response, organizationID *identifier.Identifier, completed []charon.Completed, providers []charon.Provider, emailOrUsername string, assertApp func(t *testing.T, ts *httptest.Server, service *charon.Service, organizationID, appID identifier.Identifier)) identifier.Identifier {
	t.Helper()

	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var flowResponse charon.AuthFlowResponse
	errE := x.DecodeJSONWithoutUnknownFields(resp.Body, &flowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, completed, flowResponse.Completed)
	assert.Equal(t, providers, flowResponse.Providers)
	assert.Equal(t, emailOrUsername, flowResponse.EmailOrUsername)
	assert.Nil(t, flowResponse.OIDCProvider)
	assert.Nil(t, flowResponse.Passkey)
	assert.Nil(t, flowResponse.Password)
	assert.Empty(t, flowResponse.Error)
	assertApp(t, ts, service, flowResponse.OrganizationID, flowResponse.AppID)
	if organizationID != nil {
		assert.Equal(t, *organizationID, flowResponse.OrganizationID)
	}
	return flowResponse.OrganizationID
}

func assertAppName(t *testing.T, organizationName, appName string) func(t *testing.T, ts *httptest.Server, service *charon.Service, organizationID, appID identifier.Identifier) {
	t.Helper()

	return func(t *testing.T, ts *httptest.Server, service *charon.Service, organizationID, appID identifier.Identifier) {
		t.Helper()

		organizationGet, errE := service.ReverseAPI("OrganizationGet", waf.Params{"id": organizationID.String()}, nil)
		require.NoError(t, errE, "% -+#.1v", errE)

		resp, err := ts.Client().Get(ts.URL + organizationGet) //nolint:noctx,bodyclose
		require.NoError(t, err)
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		var organization charon.Organization
		errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &organization)
		require.NoError(t, errE, "% -+#.1v", errE)

		assert.Equal(t, organizationName, organization.Name)
		assert.Equal(t, organizationID, *organization.ID)

		organizationAppGet, errE := service.ReverseAPI("OrganizationApp", waf.Params{"id": organizationID.String(), "appId": appID.String()}, nil)
		require.NoError(t, errE, "% -+#.1v", errE)

		resp, err = ts.Client().Get(ts.URL + organizationAppGet) //nolint:noctx,bodyclose
		require.NoError(t, err)
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		var orgApp charon.OrganizationApplicationPublic
		errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &orgApp)
		require.NoError(t, errE, "% -+#.1v", errE)

		assert.True(t, orgApp.Active)
		assert.Equal(t, appName, orgApp.ApplicationTemplate.Name)
	}
}

func assertCharonDashboard(t *testing.T, ts *httptest.Server, service *charon.Service, organizationID, appID identifier.Identifier) {
	t.Helper()

	assertAppName(t, "Charon", "Dashboard")(t, ts, service, organizationID, appID)
}

func createAuthFlow(t *testing.T, ts *httptest.Server, service *charon.Service) (identifier.Identifier, string, string, string, *oauth2.Config, *oidc.IDTokenVerifier) {
	t.Helper()

	serviceContextPath, errE := service.Reverse("Context", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Get(ts.URL + serviceContextPath)
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var serviceContext struct {
		ClientID    string `json:"clientId"`
		RedirectURI string `json:"redirectUri"`
	}
	errE = x.DecodeJSON(resp.Body, &serviceContext)
	require.NoError(t, errE, "% -+#.1v", errE)

	ctx := oidc.ClientContext(context.Background(), ts.Client())
	provider, err := oidc.NewProvider(ctx, ts.URL)
	require.NoError(t, err)

	config := &oauth2.Config{
		ClientID:    serviceContext.ClientID,
		RedirectURL: serviceContext.RedirectURI,
		Endpoint:    provider.Endpoint(),
		Scopes:      []string{"openid", "profile", "email"},
	}

	nonce := identifier.New().String()
	state := identifier.New().String()
	pkceVerifier := oauth2.GenerateVerifier()

	opts := []oauth2.AuthCodeOption{}
	opts = append(opts, oidc.Nonce(nonce))
	opts = append(opts, oauth2.S256ChallengeOption(pkceVerifier))

	authURI := config.AuthCodeURL(state, opts...)
	resp, err = ts.Client().Get(authURI)
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	io.Copy(io.Discard, resp.Body)

	location := resp.Header.Get("Location")
	assert.NotEmpty(t, location)

	route, errE := service.GetRoute(location, http.MethodGet)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, "AuthFlowGet", route.Name)

	flowID, errE := identifier.FromString(route.Params["id"])
	require.NoError(t, errE, "% -+#.1v", errE)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available in initial state.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{}, nil, "", assertCharonDashboard)
	}

	return flowID, nonce, state, pkceVerifier, config, provider.Verifier(&oidc.Config{ClientID: serviceContext.ClientID})
}

func createIdentity(t *testing.T, ts *httptest.Server, service *charon.Service, flowID identifier.Identifier) charon.IdentityRef {
	t.Helper()

	identityCreate, errE := service.ReverseAPI("IdentityCreate", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	request, errE := x.MarshalWithoutEscapeHTML(charon.Identity{
		ID:            nil,
		Username:      "username",
		Email:         "user@example.com",
		GivenName:     "User",
		FullName:      "User Name",
		PictureURL:    "https://example.com/picture.png",
		Description:   "",
		Users:         nil,
		Admins:        nil,
		Organizations: nil,
	})
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Post(ts.URL+identityCreate+"?flow="+flowID.String(), "application/json", bytes.NewReader(request)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var identity charon.IdentityRef
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &identity)
	require.NoError(t, errE, "% -+#.1v", errE)

	return identity
}

func getIdentity(t *testing.T, ts *httptest.Server, service *charon.Service, identity charon.IdentityRef, flowID identifier.Identifier) charon.Identity {
	t.Helper()

	identityGet, errE := service.ReverseAPI("IdentityGet", waf.Params{"id": identity.ID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Get(ts.URL + identityGet + "?flow=" + flowID.String()) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var fullIdentity charon.Identity
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &fullIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	return fullIdentity
}

func chooseIdentity(t *testing.T, ts *httptest.Server, service *charon.Service, organizationID, flowID identifier.Identifier, organization, app string, signinOrSignout charon.Completed, providers []charon.Provider, expectedIdentities int, expectedIdentityUsername string) identifier.Identifier {
	t.Helper()

	identityList, errE := service.ReverseAPI("IdentityList", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Get(ts.URL + identityList + "?flow=" + flowID.String()) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var identities []charon.IdentityRef
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &identities)
	require.NoError(t, errE, "% -+#.1v", errE)

	var identity charon.IdentityRef
	if len(identities) < expectedIdentities {
		identity = createIdentity(t, ts, service, flowID)

		resp, err = ts.Client().Get(ts.URL + identityList + "?flow=" + flowID.String()) //nolint:noctx,bodyclose
		require.NoError(t, err)
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		identities = []charon.IdentityRef{}
		errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &identities)
		require.NoError(t, errE, "% -+#.1v", errE)
		require.Len(t, identities, expectedIdentities)
		require.Contains(t, identities, identity)
	} else {
		require.Len(t, identities, expectedIdentities)
		found := false
		for _, id := range identities {
			i := getIdentity(t, ts, service, id, flowID)
			if i.Username == expectedIdentityUsername {
				identity = id
				found = true
				break
			}
		}
		assert.True(t, found)
	}

	authFlowChooseIdentity, errE := service.ReverseAPI("AuthFlowChooseIdentity", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	request, errE := x.MarshalWithoutEscapeHTML(charon.AuthFlowChooseIdentityRequest{
		Identity: identity,
	})
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Post(ts.URL+authFlowChooseIdentity, "application/json", bytes.NewReader(request)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	assertFlowResponse(t, ts, service, resp, &organizationID, []charon.Completed{signinOrSignout, charon.CompletedIdentity}, providers, "", assertAppName(t, organization, app))

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, &organizationID, []charon.Completed{signinOrSignout, charon.CompletedIdentity}, providers, "", assertAppName(t, organization, app))
	}

	fullIdentity := getIdentity(t, ts, service, identity, flowID)

	for _, idOrg := range fullIdentity.Organizations {
		if idOrg.Organization.ID == organizationID {
			return *idOrg.ID
		}
	}

	require.Fail(t, "identity not used with organization")
	return identifier.Identifier{}
}

func doRedirect(t *testing.T, ts *httptest.Server, service *charon.Service, organizationID, flowID identifier.Identifier, organization, app string, signinOrSignout charon.Completed, providers []charon.Provider) string {
	t.Helper()

	authFlowRedirect, errE := service.ReverseAPI("AuthFlowRedirect", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Post(ts.URL+authFlowRedirect, "application/json", strings.NewReader(`{}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	assertFlowResponse(t, ts, service, resp, &organizationID, []charon.Completed{signinOrSignout, charon.CompletedIdentity, charon.CompletedFinishReady}, providers, "", assertAppName(t, organization, app))

	authFlowGetAPI, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Get(ts.URL + authFlowGetAPI) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, &organizationID, []charon.Completed{signinOrSignout, charon.CompletedIdentity, charon.CompletedFinishReady}, providers, "", assertAppName(t, organization, app))
	}

	authFlowGet, errE := service.Reverse("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, string(out))
	location := resp.Header.Get("Location")
	require.NotEmpty(t, location)

	return location
}

func doRedirectAndAccessToken(t *testing.T, ts *httptest.Server, service *charon.Service, organizationID, flowID identifier.Identifier, organization, app, nonce, state, pkceVerifier string, config *oauth2.Config, verifier *oidc.IDTokenVerifier, signinOrSignout charon.Completed, providers []charon.Provider) string {
	t.Helper()

	location := doRedirect(t, ts, service, organizationID, flowID, organization, app, signinOrSignout, providers)

	u, err := url.Parse(location)
	require.NoError(t, err)
	query := u.Query()
	assert.Equal(t, "openid profile email", query.Get("scope"))
	assert.Equal(t, state, query.Get("state"))

	ctx := oidc.ClientContext(context.Background(), ts.Client())
	opts := []oauth2.AuthCodeOption{}
	opts = append(opts, oauth2.VerifierOption(pkceVerifier))
	oauth2Token, err := config.Exchange(ctx, query.Get("code"), opts...)
	require.NoError(t, err)
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	require.True(t, ok)
	idToken, err := verifier.Verify(ctx, rawIDToken)
	require.NoError(t, err)
	assert.Equal(t, nonce, idToken.Nonce)

	authFlowGetAPI, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Get(ts.URL + authFlowGetAPI) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, &organizationID, []charon.Completed{signinOrSignout, charon.CompletedIdentity, charon.CompletedFinishReady, charon.CompletedFinished}, providers, "", assertAppName(t, organization, app))
	}

	require.NotEmpty(t, oauth2Token.AccessToken)
	return oauth2Token.AccessToken
}
