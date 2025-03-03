package charon_test

import (
	"bytes"
	"context"
	"io"
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

func assertFlowResponse(t *testing.T, ts *httptest.Server, service *charon.Service, resp *http.Response, completed []charon.Completed, providers []charon.Provider) {
	t.Helper()

	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var flowResponse struct {
		Completed      []charon.Completed    `json:"completed"`
		OrganizationID identifier.Identifier `json:"organizationId"`
		AppID          identifier.Identifier `json:"appId"`
		Providers      []charon.Provider     `json:"providers,omitempty"`
	}
	errE := x.DecodeJSONWithoutUnknownFields(resp.Body, &flowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, completed, flowResponse.Completed)
	assert.Equal(t, providers, flowResponse.Providers)
	assertCharonDashboard(t, ts, service, flowResponse.OrganizationID, flowResponse.AppID)
}

func assertCharonDashboard(t *testing.T, ts *httptest.Server, service *charon.Service, organizationID, appID identifier.Identifier) {
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

	assert.Equal(t, "Charon", organization.Name)
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
	assert.Equal(t, "Dashboard", orgApp.ApplicationTemplate.Name)
}

func createAuthFlow(t *testing.T, ts *httptest.Server, service *charon.Service) identifier.Identifier {
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
	verifier := oauth2.GenerateVerifier()

	opts := []oauth2.AuthCodeOption{}
	opts = append(opts, oidc.Nonce(nonce))
	opts = append(opts, oauth2.S256ChallengeOption(verifier))

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
		assertFlowResponse(t, ts, service, resp, []charon.Completed{}, nil)
	}

	return flowID
}

func createIdentity(t *testing.T, ts *httptest.Server, service *charon.Service) charon.IdentityRef {
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

	resp, err := ts.Client().Post(ts.URL+identityCreate, "application/json", bytes.NewReader(request)) //nolint:noctx,bodyclose
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

func chooseIdentity(t *testing.T, ts *httptest.Server, service *charon.Service, organizationID, flowID identifier.Identifier) identifier.Identifier {
	t.Helper()

	identity := createIdentity(t, ts, service)

	identityList, errE := service.ReverseAPI("IdentityList", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Get(ts.URL + identityList) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var identities []charon.IdentityRef
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &identities)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Len(t, identities, 2)
	require.Contains(t, identities, identity)

	authFlowChooseIdentity, errE := service.ReverseAPI("AuthFlowChooseIdentity", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	request, errE := x.MarshalWithoutEscapeHTML(charon.AuthFlowChooseIdentityRequest{
		Identity: identity,
	})
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Post(ts.URL+authFlowChooseIdentity, "application/json", bytes.NewReader(request)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, `{"target":"oidc","name":"Test application","homepage":"https://example.com","organizationId":"`+organizationID.String()+`","provider":"password","completed":"identity"}`, string(out))

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err = io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"oidc","name":"Test application","homepage":"https://example.com","organizationId":"`+organizationID.String()+`","provider":"password","completed":"identity"}`, string(out))
	}

	identityGet, errE := service.ReverseAPI("IdentityGet", waf.Params{"id": identity.ID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Get(ts.URL + identityGet) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var fullIdentity charon.Identity
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &fullIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	for _, idOrg := range fullIdentity.Organizations {
		if idOrg.Organization.ID == organizationID {
			return *idOrg.ID
		}
	}

	require.Fail(t, "identity not used with organization")
	return identifier.Identifier{}
}

func doRedirect(t *testing.T, ts *httptest.Server, service *charon.Service, organizationID, flowID identifier.Identifier) {
	t.Helper()

	authFlowRedirect, errE := service.ReverseAPI("AuthFlowRedirect", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Post(ts.URL+authFlowRedirect, "application/json", strings.NewReader(`{}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, `{"target":"oidc","name":"Test application","homepage":"https://example.com","organizationId":"`+organizationID.String()+`","provider":"password","completed":"identity"}`, string(out))

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"oidc","name":"Test application","homepage":"https://example.com","organizationId":"`+organizationID.String()+`","provider":"password","completed":"identity"}`, string(out))
	}
}
