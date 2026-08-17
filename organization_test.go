package charon_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/mohae/deepcopy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

const applicationClientSecret = "client-secret"

func getOrganization(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken, organizationID string) *charon.Organization {
	t.Helper()

	organizationGet, errE := service.ReverseAPI("OrganizationGet", waf.Params{"id": organizationID}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+organizationGet, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var organization charon.Organization
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &organization)
	require.NoError(t, errE, "% -+#.1v", errE)

	return &organization
}

func createOrganization(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, applicationTemplate *charon.ApplicationTemplate) *charon.Organization {
	t.Helper()

	organizationCreate, errE := service.ReverseAPI("OrganizationCreate", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	applications := []charon.OrganizationApplication{}
	if applicationTemplate != nil {
		hash, err := argon2id.CreateHash(applicationClientSecret, charon.TestingArgon2idParams())
		require.NoError(t, err)

		require.Empty(t, applicationTemplate.Variables)
		require.Empty(t, applicationTemplate.ClientsPublic)
		require.Len(t, applicationTemplate.ClientsBackend, 1)
		require.Empty(t, applicationTemplate.ClientsService)

		applications = append(applications, charon.OrganizationApplication{
			OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
				ID:                  nil,
				Base:                nil,
				Active:              true,
				ApplicationTemplate: applicationTemplate.ApplicationTemplatePublic,
				Values:              []charon.Value{},
			},
			ClientsPublic: []charon.OrganizationApplicationClientPublic{},
			ClientsBackend: []charon.OrganizationApplicationClientBackend{
				{
					ID:   nil,
					Base: nil,
					Client: charon.ClientRef{
						ID: *applicationTemplate.ClientsBackend[0].ID,
					},
					Secret: hash,
				},
			},
			ClientsService: []charon.OrganizationApplicationClientService{},
		})
	}

	organization := charon.Organization{
		OrganizationPublic: charon.OrganizationPublic{
			ID:          nil,
			Base:        nil,
			Name:        "Test organization",
			Description: "",
		},
		Admins:           nil,
		Applications:     applications,
		Roles:            nil,
		DefaultRoles:     nil,
		AllowedProviders: nil,
	}

	data, errE := x.MarshalWithoutEscapeHTML(organization)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+organizationCreate, bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:bodyclose

	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var organizationRef charon.OrganizationRef
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &organizationRef)
	require.NoError(t, errE, "% -+#.1v", errE)

	verifyLatestActivity(t, ts, service, accessToken, charon.ActivityOrganizationCreate, nil, nil, 0, 1, 0, 0)

	return getOrganization(t, ts, service, accessToken, organizationRef.ID.String())
}

func updateOrganization(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, organization *charon.Organization) *charon.Organization {
	t.Helper()

	data, errE := x.MarshalWithoutEscapeHTML(organization)
	require.NoError(t, errE, "% -+#.1v", errE)

	organizationUpdate, errE := service.ReverseAPI("OrganizationUpdate", waf.Params{"id": organization.ID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+organizationUpdate, bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:bodyclose

	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var organizationRef charon.OrganizationRef
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &organizationRef)
	require.NoError(t, errE, "% -+#.1v", errE)

	return getOrganization(t, ts, service, accessToken, organizationRef.ID.String())
}

func validateOrganizationIdentity(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken, organizationID string, identityID identifier.Identifier, expectedRoles []string) {
	t.Helper()

	organizationIdentityGet, errE := service.ReverseAPI("OrganizationIdentity", waf.Params{"id": organizationID, "identityId": identityID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+organizationIdentityGet, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var organizationIdentity charon.OrganizationIdentity
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &organizationIdentity)
	require.NoError(t, errE, "% -+#.1v", errE)

	assert.Equal(t, expectedRoles, organizationIdentity.Roles)
}

func doOIDCOrganizationFlow(
	t *testing.T, ts *httptest.Server, service *charon.Service,
	username, clientID string, organizationID identifier.Identifier, accessTokenLifespan time.Duration, nonce, requestedScope, expectedGrantedScope string,
) (string, string, string, identifier.Identifier, string, time.Time) {
	t.Helper()

	state := identifier.New().String()
	challenge := identifier.New().String() + identifier.New().String() + identifier.New().String()

	challengeHash := sha256.Sum256([]byte(challenge))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	qs := url.Values{
		"client_id":             []string{clientID},
		"redirect_uri":          []string{"https://example.com/redirect"},
		"scope":                 []string{requestedScope},
		"response_type":         []string{"code"},
		"response_mode":         []string{"query"},
		"code_challenge_method": []string{"S256"},
		"code_challenge":        []string{codeChallenge},
		"state":                 []string{state},
		"nonce":                 []string{nonce},
	}
	oidcAuthorize, errE := service.Reverse("OIDCAuthorize", nil, qs)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Get(ts.URL + oidcAuthorize) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, string(out))
	assert.Equal(t, 2, resp.ProtoMajor)
	location := resp.Header.Get("Location")
	assert.NotEmpty(t, location)

	route, errE := service.GetRoute(location, http.MethodGet)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, "AuthFlowGet", route.Name)

	flowID, errE := identifier.MaybeString(route.Params["id"])
	require.NoError(t, errE, "% -+#.1v", errE)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available, for created organization and app.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, &organizationID, []charon.Completed{}, nil, "", assertAppName(t, "Test organization", "Test application"))
	}

	resp = startPasswordSignin(t, ts, service, username, []byte("test1234"), &organizationID, flowID, "Test organization", "Test application") //nolint:bodyclose
	assertSignedUser(t, charon.CompletedSignin, flowID, resp)

	// Flow is available and CompletedSignin is completed.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	require.NoError(t, err)
	assertFlowResponse(t, ts, service, resp, &organizationID, []charon.Completed{charon.CompletedSignin}, []charon.Provider{charon.ProviderPassword}, "", assertAppName(t, "Test organization", "Test application"))

	identityID := chooseIdentity(t, ts, service, organizationID, flowID, "Test organization", "Test application", charon.CompletedSignin, []charon.Provider{charon.ProviderPassword}, 2, "username")

	location = doRedirect(t, ts, service, organizationID, flowID, "Test organization", "Test application", charon.CompletedSignin, []charon.Provider{charon.ProviderPassword})

	assert.True(t, strings.HasPrefix(location, "https://example.com/redirect?"), location)

	// Flow is available and is finished.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, &organizationID, []charon.Completed{charon.CompletedSignin, charon.CompletedIdentity, charon.CompletedFinishReady, charon.CompletedFinished}, []charon.Provider{charon.ProviderPassword}, "", assertAppName(t, "Test organization", "Test application"))
	}

	parsedLocation, err := url.Parse(location)
	require.NoError(t, err)
	locationQuery := parsedLocation.Query()
	code := locationQuery.Get("code")
	locationQuery.Del("code")
	assert.NotEmpty(t, code)
	assert.Equal(t, url.Values{"scope": []string{expectedGrantedScope}, "state": []string{state}}, locationQuery)

	// Introspection of the code should not be possible.
	oidcIntrospect, errE := service.ReverseAPI("OIDCIntrospect", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	data := url.Values{
		"token": []string{code},
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+oidcIntrospect, strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":chc-"+applicationClientSecret)))
	resp, err = ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json;charset=UTF-8", resp.Header.Get("Content-Type"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, `{"active":false}`+"\n", string(body))

	accessToken, idToken, refreshToken, now := exchangeCodeForTokens(t, ts, service, clientID, code, challenge, accessTokenLifespan, expectedGrantedScope)

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	cookies := ts.Client().Jar.Cookies(u)

	var sessionToken string
	for _, cookie := range cookies {
		if cookie.Name == charon.TestingSessionCookiePrefix()+flowID.String() {
			sessionToken = cookie.Value
			break
		}
	}
	require.NotEmpty(t, sessionToken)

	split := strings.Split(sessionToken, ".")
	require.Len(t, split, 2)

	secretID, err := base64.RawURLEncoding.DecodeString(split[1])
	require.NoError(t, err)
	session, errE := service.TestingGetSessionBySecretID(t.Context(), [32]byte(secretID))
	require.NoError(t, errE, "% -+#.1v", errE)

	sessionID := session.ID.String()

	return accessToken, idToken, refreshToken, identityID, sessionID, now
}

func TestOrganizationChanges(t *testing.T) { //nolint:maintidx
	t.Parallel()

	orgBase := []string{"example.com", "ORGANIZATION", identifier.New().String()}
	orgID := identifier.From(orgBase...)
	templateBase := []string{"example.com", "APPLICATION_TEMPLATE", identifier.New().String()}
	templateID := identifier.From(templateBase...)
	identity1ID := identifier.New()
	identity2ID := identifier.New()
	identity3ID := identifier.New()
	app1Base := append(slices.Clone(orgBase), "ORGANIZATION_APPLICATION", identifier.New().String())
	app1ID := identifier.From(app1Base...)
	app2Base := append(slices.Clone(orgBase), "ORGANIZATION_APPLICATION", identifier.New().String())
	app2ID := identifier.From(app2Base...)

	tests := []struct {
		name                           string
		existing                       *charon.Organization
		updated                        *charon.Organization
		expectedChanges                []charon.ActivityChangeType
		expectedAdminsChanged          []charon.IdentityRef
		expectedRolesIdentitiesChanged []charon.IdentityRef
		expectedApps                   []charon.OrganizationApplicationRef
	}{
		{
			name: "no changes",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "Test description",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:                  &app1ID,
							Base:                app1Base,
							Active:              true,
							ApplicationTemplate: charon.ApplicationTemplatePublic{},
							Values:              nil,
						},
						ClientsPublic:  nil,
						ClientsBackend: nil,
						ClientsService: nil,
					},
				},
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "Test description",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:                  &app1ID,
							Base:                app1Base,
							Active:              true,
							ApplicationTemplate: charon.ApplicationTemplatePublic{},
							Values:              nil,
						},
						ClientsPublic:  nil,
						ClientsBackend: nil,
						ClientsService: nil,
					},
				},
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges:                []charon.ActivityChangeType{},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
		{
			name: "name and description changed",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Old Name",
					Description: "Old description",
				},
				Admins:           nil,
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "New Name",
					Description: "New description",
				},
				Admins:           nil,
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangeOtherData},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
		{
			name: "admin added",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           []charon.IdentityRef{{ID: identity1ID}},
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           []charon.IdentityRef{{ID: identity1ID}, {ID: identity2ID}},
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangePermissionsAdded},
			expectedAdminsChanged:          []charon.IdentityRef{{ID: identity2ID}},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
		{
			name: "admin removed",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           []charon.IdentityRef{{ID: identity1ID}, {ID: identity2ID}},
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           []charon.IdentityRef{{ID: identity1ID}},
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangePermissionsRemoved},
			expectedAdminsChanged:          []charon.IdentityRef{{ID: identity2ID}},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
		{
			name: "application membership added",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           nil,
				Applications:     []charon.OrganizationApplication{},
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins: nil,
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:                  &app1ID,
							Base:                app1Base,
							Active:              true,
							ApplicationTemplate: charon.ApplicationTemplatePublic{},
							Values:              nil,
						},
						ClientsPublic:  nil,
						ClientsBackend: nil,
						ClientsService: nil,
					},
				},
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps: []charon.OrganizationApplicationRef{
				{
					Organization: charon.OrganizationRef{ID: orgID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app1ID},
				},
			},
		},
		{
			name: "application membership removed",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins: nil,
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:                  &app1ID,
							Base:                app1Base,
							Active:              true,
							ApplicationTemplate: charon.ApplicationTemplatePublic{},
							Values:              nil,
						},
						ClientsPublic:  nil,
						ClientsBackend: nil,
						ClientsService: nil,
					},
				},
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           nil,
				Applications:     []charon.OrganizationApplication{},
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangeMembershipRemoved},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps: []charon.OrganizationApplicationRef{
				{
					Organization: charon.OrganizationRef{ID: orgID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app1ID},
				},
			},
		},
		{ //nolint:dupl
			name: "application membership activated",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins: nil,
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:                  &app1ID,
							Base:                app1Base,
							Active:              false,
							ApplicationTemplate: charon.ApplicationTemplatePublic{},
							Values:              nil,
						},
						ClientsPublic:  nil,
						ClientsBackend: nil,
						ClientsService: nil,
					},
				},
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins: nil,
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:                  &app1ID,
							Base:                app1Base,
							Active:              true,
							ApplicationTemplate: charon.ApplicationTemplatePublic{},
							Values:              nil,
						},
						ClientsPublic:  nil,
						ClientsBackend: nil,
						ClientsService: nil,
					},
				},
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangeMembershipActivated},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps: []charon.OrganizationApplicationRef{
				{
					Organization: charon.OrganizationRef{ID: orgID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app1ID},
				},
			},
		},
		{ //nolint:dupl
			name: "application membership disabled",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins: nil,
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:                  &app1ID,
							Base:                app1Base,
							Active:              true,
							ApplicationTemplate: charon.ApplicationTemplatePublic{},
							Values:              nil,
						},
						ClientsPublic:  nil,
						ClientsBackend: nil,
						ClientsService: nil,
					},
				},
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins: nil,
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:                  &app1ID,
							Base:                app1Base,
							Active:              false,
							ApplicationTemplate: charon.ApplicationTemplatePublic{},
							Values:              nil,
						},
						ClientsPublic:  nil,
						ClientsBackend: nil,
						ClientsService: nil,
					},
				},
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangeMembershipDisabled},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps: []charon.OrganizationApplicationRef{
				{
					Organization: charon.OrganizationRef{ID: orgID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app1ID},
				},
			},
		},
		{
			name: "application membership changed",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins: nil,
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Base:   app1Base,
							Active: true,
							ApplicationTemplate: charon.ApplicationTemplatePublic{
								ID:               &templateID,
								Base:             templateBase,
								Name:             "Old Template",
								Description:      "Old description",
								HomepageTemplate: "",
								IDScopes:         nil,
								Roles:            nil,
								Variables:        nil,
								ClientsPublic:    nil,
								ClientsBackend:   nil,
								ClientsService:   nil,
							},
							Values: nil,
						},
						ClientsPublic:  nil,
						ClientsBackend: nil,
						ClientsService: nil,
					},
				},
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins: nil,
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Base:   app1Base,
							Active: true,
							ApplicationTemplate: charon.ApplicationTemplatePublic{
								ID:               &templateID,
								Base:             templateBase,
								Name:             "New Template",
								Description:      "New description",
								HomepageTemplate: "",
								IDScopes:         nil,
								Roles:            nil,
								Variables:        nil,
								ClientsPublic:    nil,
								ClientsBackend:   nil,
								ClientsService:   nil,
							},
							Values: nil,
						},
						ClientsPublic:  nil,
						ClientsBackend: nil,
						ClientsService: nil,
					},
				},
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangeMembershipChanged},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps: []charon.OrganizationApplicationRef{
				{
					Organization: charon.OrganizationRef{ID: orgID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app1ID},
				},
			},
		},
		{
			name: "roles assigned to identity",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           nil,
				Applications:     nil,
				Roles:            map[identifier.Identifier][]string{},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:       nil,
				Applications: nil,
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin"},
				},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangeRolesAdded},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{{ID: identity1ID}},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
		{
			name: "roles removed from identity",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:       nil,
				Applications: nil,
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin"},
				},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           nil,
				Applications:     nil,
				Roles:            map[identifier.Identifier][]string{},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangeRolesRemoved},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{{ID: identity1ID}},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
		{
			name: "same roles in different order do not produce changes",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:       nil,
				Applications: nil,
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin", "viewer"},
				},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:       nil,
				Applications: nil,
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"viewer", "admin"},
				},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges:                []charon.ActivityChangeType{},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
		{
			name: "roles changed for identity (one added, one removed)",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:       nil,
				Applications: nil,
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin"},
				},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:       nil,
				Applications: nil,
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"viewer"},
				},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges: []charon.ActivityChangeType{
				charon.ActivityChangeRolesAdded,
				charon.ActivityChangeRolesRemoved,
			},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{{ID: identity1ID}},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
		{
			name: "roles added to one identity and removed from another",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:       nil,
				Applications: nil,
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin"},
				},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:       nil,
				Applications: nil,
				Roles: map[identifier.Identifier][]string{
					identity1ID: {},
					identity2ID: {"viewer"},
				},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges: []charon.ActivityChangeType{
				charon.ActivityChangeRolesAdded,
				charon.ActivityChangeRolesRemoved,
			},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{{ID: identity1ID}, {ID: identity2ID}},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
		{
			name: "roles added to multiple identities yields single change entry",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           nil,
				Applications:     nil,
				Roles:            map[identifier.Identifier][]string{},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:       nil,
				Applications: nil,
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin"},
					identity2ID: {"viewer"},
					identity3ID: {"editor"},
				},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangeRolesAdded},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{{ID: identity1ID}, {ID: identity2ID}, {ID: identity3ID}},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
		{
			name: "complex scenario with multiple changes",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Old Name",
					Description: "Old description",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}, {ID: identity2ID}},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:                  &app1ID,
							Base:                app1Base,
							Active:              false,
							ApplicationTemplate: charon.ApplicationTemplatePublic{},
							Values:              nil,
						},
						ClientsPublic:  nil,
						ClientsBackend: nil,
						ClientsService: nil,
					},
				},
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin"},
				},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "New Name",
					Description: "New description",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}, {ID: identity3ID}},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:                  &app1ID,
							Base:                app1Base,
							Active:              true,
							ApplicationTemplate: charon.ApplicationTemplatePublic{},
							Values:              nil,
						},
						ClientsPublic:  nil,
						ClientsBackend: nil,
						ClientsService: nil,
					},
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:                  &app2ID,
							Base:                app2Base,
							Active:              true,
							ApplicationTemplate: charon.ApplicationTemplatePublic{},
							Values:              nil,
						},
						ClientsPublic:  nil,
						ClientsBackend: nil,
						ClientsService: nil,
					},
				},
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin", "viewer"},
				},
				DefaultRoles:     nil,
				AllowedProviders: nil,
			},
			expectedChanges: []charon.ActivityChangeType{
				charon.ActivityChangeOtherData,
				charon.ActivityChangePermissionsAdded,
				charon.ActivityChangePermissionsRemoved,
				charon.ActivityChangeRolesAdded,
				charon.ActivityChangeMembershipAdded,
				charon.ActivityChangeMembershipActivated,
			},
			expectedAdminsChanged:          []charon.IdentityRef{{ID: identity2ID}, {ID: identity3ID}},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{{ID: identity1ID}},
			expectedApps: []charon.OrganizationApplicationRef{
				{
					Organization: charon.OrganizationRef{ID: orgID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app1ID},
				},
				{
					Organization: charon.OrganizationRef{ID: orgID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app2ID},
				},
			},
		},
		{
			name: "allowed providers added (empty -> non-empty)",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           nil,
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: []charon.Provider{},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           nil,
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: []charon.Provider{charon.ProviderEmail, charon.ProviderPassword, charon.ProviderUsername},
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangeOtherData},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
		{
			name: "allowed providers removed (non-empty -> empty)",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           nil,
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: []charon.Provider{charon.ProviderEmail, charon.ProviderPassword, charon.ProviderUsername},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           nil,
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: []charon.Provider{},
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangeOtherData},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
		{
			name: "allowed providers same set reports no change",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           nil,
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: []charon.Provider{charon.ProviderEmail, charon.ProviderPassword, charon.ProviderUsername},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           nil,
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: []charon.Provider{charon.ProviderEmail, charon.ProviderPassword, charon.ProviderUsername},
			},
			expectedChanges:                []charon.ActivityChangeType{},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
		{
			name: "allowed providers extended with passkey",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           nil,
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: []charon.Provider{charon.ProviderEmail, charon.ProviderPassword, charon.ProviderUsername},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Base:        orgBase,
					Name:        "Test Org",
					Description: "",
				},
				Admins:           nil,
				Applications:     nil,
				Roles:            nil,
				DefaultRoles:     nil,
				AllowedProviders: []charon.Provider{charon.ProviderEmail, charon.ProviderPasskey, charon.ProviderPassword, charon.ProviderUsername},
			},
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangeOtherData},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps:                   []charon.OrganizationApplicationRef{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			changes, adminsChanged, rolesIdentitiesChanged, apps := tt.updated.Changes(tt.existing)

			// Sort expected slices to match deterministic ordering from Changes method.
			slices.SortFunc(tt.expectedAdminsChanged, charon.TestingIdentityRefCmp)
			slices.SortFunc(tt.expectedRolesIdentitiesChanged, charon.TestingIdentityRefCmp)
			slices.SortFunc(tt.expectedApps, charon.TestingOrganizationApplicationRefCmp)

			// Check all expected outputs with deterministic ordering.
			assert.Equal(t, tt.expectedChanges, changes, "Changes mismatch")
			assert.Equal(t, tt.expectedAdminsChanged, adminsChanged, "Admin identities mismatch")
			assert.Equal(t, tt.expectedRolesIdentitiesChanged, rolesIdentitiesChanged, "Role identities mismatch")
			assert.Equal(t, tt.expectedApps, apps, "Applications mismatch")
		})
	}
}

// TestUpdateOrganizationActivityIdentityScoping verifies that when updateOrganization writes
// an activity record, identities derived from admin changes are wrapped with the Charon organization
// (because Admin IdentityRefs are database ID which are also Charon organization-scoped IDs),
// while identities derived from role changes are wrapped with the organization being updated
// (because role map keys are organization-scoped identity IDs in that organization).
func TestUpdateOrganizationActivityIdentityScoping(t *testing.T) {
	t.Parallel()

	_, service, _, _, _ := startTestServer(t) //nolint:dogsled

	accountID := identifier.New()
	ctx := service.TestingWithAccountID(t.Context(), accountID)
	ctx = service.TestingWithSessionID(ctx)
	ctx = service.TestingWithRequestID(ctx)

	creatorID := createTestIdentity(t, service, ctx)
	ctx = service.TestingWithIdentityID(ctx, creatorID)

	// A second identity that we will add as an admin of a non-Charon organization.
	addedAdminID := createTestIdentity(t, service, ctx)

	organization := &charon.Organization{
		OrganizationPublic: charon.OrganizationPublic{
			ID:          nil,
			Base:        nil,
			Name:        "Activity Scoping Test Org",
			Description: "",
		},
		Admins:           []charon.IdentityRef{},
		Applications:     []charon.OrganizationApplication{},
		Roles:            nil,
		DefaultRoles:     nil,
		AllowedProviders: nil,
	}
	errE := service.TestingCreateOrganization(ctx, organization)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.NotNil(t, organization.ID)

	// Add the second identity as admin and update.
	organization.Admins = append(organization.Admins, charon.IdentityRef{ID: addedAdminID})
	errE = service.TestingUpdateOrganization(ctx, organization)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Find the OrganizationUpdate activity for this org.
	activities, errE := service.TestingListActivities(ctx)
	require.NoError(t, errE, "% -+#.1v", errE)

	var updateActivity *charon.Activity
	orgRef := charon.OrganizationRef{ID: *organization.ID}
	for _, a := range activities {
		if a.Type == charon.ActivityOrganizationUpdate && a.IsForOrganization(orgRef) {
			updateActivity = a
			break
		}
	}
	require.NotNil(t, updateActivity, "expected an OrganizationUpdate activity for the test org")

	// The activity must record the permission addition.
	assert.Contains(t, updateActivity.Changes, charon.ActivityChangePermissionsAdded)

	// The added-admin identity must appear in the activity's identities wrapped with Charon
	// (not with the updated organization), because Admin IdentityRefs are database IDs
	// which are also Charon organization-scoped IDs.
	charonID := service.TestingCharonOrganizationID()
	require.Len(t, updateActivity.Identities, 1)
	assert.Equal(t, charonID, updateActivity.Identities[0].Organization.ID)
	assert.Equal(t, addedAdminID, updateActivity.Identities[0].Identity.ID)
	assert.NotEqual(t, *organization.ID, updateActivity.Identities[0].Organization.ID)
}

// TestOrganizationValidateRoles covers role-related normalization and validation rules
// in Organization.validate that aren't reachable as a pure unit test (they need a real
// Service for hasIdentities and OrganizationApplication.Validate). Roles map keys are
// organization-scoped identity IDs in this organization, but the validator does not
// require those IDs to actually exist as IdentityOrganizations, so we use synthetic IDs.
func TestOrganizationValidateRoles(t *testing.T) {
	t.Parallel()

	_, service, _, _, _ := startTestServer(t) //nolint:dogsled

	accountID := identifier.New()
	ctx := service.TestingWithAccountID(t.Context(), accountID)
	ctx = service.TestingWithSessionID(ctx)
	ctx = service.TestingWithRequestID(ctx)

	adminID := createTestIdentity(t, service, ctx)
	ctx = service.TestingWithIdentityID(ctx, adminID)

	appTemplate := &charon.ApplicationTemplate{
		ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
			ID:               nil,
			Base:             nil,
			Name:             "Roles App",
			Description:      "",
			HomepageTemplate: "https://example.com",
			IDScopes:         nil,
			Roles: []charon.Role{
				{Key: "admin", Description: "Admin"},
				{Key: "viewer", Description: "Viewer"},
			},
			// Set Variables explicitly to empty so Validate does not auto-add the uriBase default;
			// we have no clients in OrganizationApplication so we do not need any variables.
			Variables:      []charon.Variable{},
			ClientsPublic:  []charon.ApplicationTemplateClientPublic{},
			ClientsBackend: []charon.ApplicationTemplateClientBackend{},
			ClientsService: []charon.ApplicationTemplateClientService{},
		},
		Admins: []charon.IdentityRef{},
	}
	errE := service.TestingCreateApplicationTemplate(ctx, appTemplate)
	require.NoError(t, errE, "% -+#.1v", errE)

	makeOrgApp := func(active bool) charon.OrganizationApplication {
		appTmpl := deepcopy.Copy(appTemplate.ApplicationTemplatePublic).(charon.ApplicationTemplatePublic) //nolint:forcetypeassert,errcheck
		return charon.OrganizationApplication{
			OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
				ID:                  nil,
				Base:                nil,
				Active:              active,
				ApplicationTemplate: appTmpl,
				Values:              []charon.Value{},
			},
			ClientsPublic:  []charon.OrganizationApplicationClientPublic{},
			ClientsBackend: []charon.OrganizationApplicationClientBackend{},
			ClientsService: []charon.OrganizationApplicationClientService{},
		}
	}

	t.Run("nil roles map normalized to empty", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Nil Roles Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{makeOrgApp(true)},
			Roles:              nil,
			DefaultRoles:       nil,
			AllowedProviders:   nil,
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.NotNil(t, org.Roles)
		assert.Empty(t, org.Roles)
	})

	t.Run("valid role assigned to identity", func(t *testing.T) {
		t.Parallel()
		targetID := identifier.New()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Valid Role Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{makeOrgApp(true)},
			Roles: map[identifier.Identifier][]string{
				targetID: {"admin"},
			},
			DefaultRoles:     nil,
			AllowedProviders: nil,
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Equal(t, []string{"admin"}, org.Roles[targetID])
	})

	t.Run("unknown role rejected on add", func(t *testing.T) {
		t.Parallel()
		targetID := identifier.New()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Unknown Role Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{makeOrgApp(true)},
			Roles: map[identifier.Identifier][]string{
				targetID: {"nonexistent"},
			},
			DefaultRoles:     nil,
			AllowedProviders: nil,
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.Error(t, errE)
		assert.ErrorIs(t, errE, charon.ErrOrganizationValidationFailed)
		assert.EqualError(t, errors.Cause(errE), "unknown roles")
	})

	t.Run("duplicate role keys deduplicated", func(t *testing.T) {
		t.Parallel()
		targetID := identifier.New()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Dup Roles Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{makeOrgApp(true)},
			Roles: map[identifier.Identifier][]string{
				targetID: {"admin", "viewer", "admin"},
			},
			DefaultRoles:     nil,
			AllowedProviders: nil,
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.ElementsMatch(t, []string{"admin", "viewer"}, org.Roles[targetID])
		assert.Len(t, org.Roles[targetID], 2)
	})

	t.Run("role from inactive app rejected on add", func(t *testing.T) {
		t.Parallel()
		targetID := identifier.New()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Inactive App Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{makeOrgApp(false)},
			Roles: map[identifier.Identifier][]string{
				targetID: {"admin"},
			},
			DefaultRoles:     nil,
			AllowedProviders: nil,
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.Error(t, errE)
		assert.ErrorIs(t, errE, charon.ErrOrganizationValidationFailed)
		assert.EqualError(t, errors.Cause(errE), "unknown roles")
	})

	t.Run("existing role tolerated when app deactivated", func(t *testing.T) {
		t.Parallel()
		targetID := identifier.New()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Escape Hatch Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{makeOrgApp(true)},
			Roles: map[identifier.Identifier][]string{
				targetID: {"admin"},
			},
			DefaultRoles:     nil,
			AllowedProviders: nil,
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)

		// Deactivate the app while keeping the role assignment.
		// The role is no longer valid (not in any active app), but it is in existing.Roles,
		// so it should be tolerated.
		org.Applications[0].Active = false
		errE = service.TestingUpdateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Equal(t, []string{"admin"}, org.Roles[targetID])
	})
}

// TestOrganizationValidateDefaultRoles covers the DefaultRoles rules in Organization.validate:
// nil normalization, dedupe + sort, rejection of role keys which are not provided by an active
// application of the organization, and the escape hatch which tolerates already stored default
// roles once their application is disabled.
func TestOrganizationValidateDefaultRoles(t *testing.T) {
	t.Parallel()

	_, service, _, _, _ := startTestServer(t) //nolint:dogsled

	accountID := identifier.New()
	ctx := service.TestingWithAccountID(t.Context(), accountID)
	ctx = service.TestingWithSessionID(ctx)
	ctx = service.TestingWithRequestID(ctx)

	adminID := createTestIdentity(t, service, ctx)
	ctx = service.TestingWithIdentityID(ctx, adminID)

	appTemplate := &charon.ApplicationTemplate{
		ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
			ID:               nil,
			Base:             nil,
			Name:             "Default Roles App",
			Description:      "",
			HomepageTemplate: "https://example.com",
			IDScopes:         nil,
			Roles: []charon.Role{
				{Key: "admin", Description: "Admin"},
				{Key: "viewer", Description: "Viewer"},
			},
			// Set Variables explicitly to empty so Validate does not auto-add the uriBase default;
			// we have no clients in OrganizationApplication so we do not need any variables.
			Variables:      []charon.Variable{},
			ClientsPublic:  []charon.ApplicationTemplateClientPublic{},
			ClientsBackend: []charon.ApplicationTemplateClientBackend{},
			ClientsService: []charon.ApplicationTemplateClientService{},
		},
		Admins: []charon.IdentityRef{},
	}
	errE := service.TestingCreateApplicationTemplate(ctx, appTemplate)
	require.NoError(t, errE, "% -+#.1v", errE)

	makeOrgApp := func(active bool) charon.OrganizationApplication {
		appTmpl := deepcopy.Copy(appTemplate.ApplicationTemplatePublic).(charon.ApplicationTemplatePublic) //nolint:forcetypeassert,errcheck
		return charon.OrganizationApplication{
			OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
				ID:                  nil,
				Base:                nil,
				Active:              active,
				ApplicationTemplate: appTmpl,
				Values:              []charon.Value{},
			},
			ClientsPublic:  []charon.OrganizationApplicationClientPublic{},
			ClientsBackend: []charon.OrganizationApplicationClientBackend{},
			ClientsService: []charon.OrganizationApplicationClientService{},
		}
	}

	t.Run("nil default roles normalized to empty", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Nil Default Roles Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{makeOrgApp(true)},
			Roles:              nil,
			DefaultRoles:       nil,
			AllowedProviders:   nil,
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.NotNil(t, org.DefaultRoles)
		assert.Empty(t, org.DefaultRoles)
	})

	t.Run("duplicates deduplicated and result sorted", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Duplicate Default Roles Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{makeOrgApp(true)},
			Roles:              nil,
			DefaultRoles:       []string{"viewer", "admin", "viewer"},
			AllowedProviders:   nil,
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Equal(t, []string{"admin", "viewer"}, org.DefaultRoles)
	})

	t.Run("unknown default role rejected on add", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Unknown Default Role Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{makeOrgApp(true)},
			Roles:              nil,
			DefaultRoles:       []string{"nonexistent"},
			AllowedProviders:   nil,
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.Error(t, errE)
		assert.ErrorIs(t, errE, charon.ErrOrganizationValidationFailed)
		assert.EqualError(t, errors.Cause(errE), "unknown default roles")
	})

	t.Run("default role from inactive app rejected on add", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Inactive App Default Role Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{makeOrgApp(false)},
			Roles:              nil,
			DefaultRoles:       []string{"admin"},
			AllowedProviders:   nil,
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.Error(t, errE)
		assert.ErrorIs(t, errE, charon.ErrOrganizationValidationFailed)
		assert.EqualError(t, errors.Cause(errE), "unknown default roles")
	})

	t.Run("existing default role tolerated when app deactivated", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Escape Hatch Default Roles Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{makeOrgApp(true)},
			Roles:              nil,
			DefaultRoles:       []string{"admin"},
			AllowedProviders:   nil,
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)

		// Deactivate the app while keeping the default role. The role is no longer valid
		// (not in any active app), but it is in existing.DefaultRoles, so it is tolerated.
		org.Applications[0].Active = false
		errE = service.TestingUpdateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Equal(t, []string{"admin"}, org.DefaultRoles)
	})
}

// TestOrganizationValidateAllowedProviders covers the AllowedProviders rules in
// Organization.validate: nil normalization, dedupe + sort, the all-or-explicit semantic
// (empty list = all providers allowed), the requirement that fixed built-in providers
// (username/email/password) are present when the list is explicit, and rejection of
// providers not exposed by getAvailableProviders.
func TestOrganizationValidateAllowedProviders(t *testing.T) {
	t.Parallel()

	_, service, _, _, _ := startTestServer(t) //nolint:dogsled

	accountID := identifier.New()
	ctx := service.TestingWithAccountID(t.Context(), accountID)
	ctx = service.TestingWithSessionID(ctx)
	ctx = service.TestingWithRequestID(ctx)

	adminID := createTestIdentity(t, service, ctx)
	ctx = service.TestingWithIdentityID(ctx, adminID)

	t.Run("nil AllowedProviders normalized to empty", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Nil Providers Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{},
			Roles:              nil,
			DefaultRoles:       nil,
			AllowedProviders:   nil,
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.NotNil(t, org.AllowedProviders)
		assert.Empty(t, org.AllowedProviders)
	})

	t.Run("empty AllowedProviders means all allowed (no validation)", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Empty Providers Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{},
			Roles:              nil,
			DefaultRoles:       nil,
			AllowedProviders:   []charon.Provider{},
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Empty(t, org.AllowedProviders)
	})

	t.Run("explicit list with all fixed built-ins succeeds", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Builtins Only Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{},
			Roles:              nil,
			DefaultRoles:       nil,
			AllowedProviders:   []charon.Provider{charon.ProviderUsername, charon.ProviderEmail, charon.ProviderPassword},
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)
		// Validate sorts the canonical form.
		assert.Equal(t, []charon.Provider{charon.ProviderEmail, charon.ProviderPassword, charon.ProviderUsername}, org.AllowedProviders)
	})

	t.Run("explicit list with passkey added succeeds", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Plus Passkey Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{},
			Roles:              nil,
			DefaultRoles:       nil,
			AllowedProviders:   []charon.Provider{charon.ProviderUsername, charon.ProviderEmail, charon.ProviderPassword, charon.ProviderPasskey},
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Equal(t, []charon.Provider{charon.ProviderEmail, charon.ProviderPasskey, charon.ProviderPassword, charon.ProviderUsername}, org.AllowedProviders)
	})

	t.Run("explicit list with configured third-party provider succeeds", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Plus OIDC Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{},
			Roles:              nil,
			DefaultRoles:       nil,
			AllowedProviders:   []charon.Provider{charon.ProviderUsername, charon.ProviderEmail, charon.ProviderPassword, "oidcTesting"},
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Contains(t, org.AllowedProviders, charon.Provider("oidcTesting"))
	})

	t.Run("missing fixed built-in provider rejected", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Missing Builtin Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{},
			Roles:              nil,
			// Missing ProviderUsername.
			DefaultRoles:     nil,
			AllowedProviders: []charon.Provider{charon.ProviderEmail, charon.ProviderPassword},
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.Error(t, errE)
		assert.ErrorIs(t, errE, charon.ErrOrganizationValidationFailed)
		assert.EqualError(t, errors.Cause(errE), "fixed built-in provider missing")
	})

	t.Run("unknown provider rejected", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Unknown Provider Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{},
			Roles:              nil,
			DefaultRoles:       nil,
			AllowedProviders:   []charon.Provider{charon.ProviderUsername, charon.ProviderEmail, charon.ProviderPassword, "doesNotExist"},
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.Error(t, errE)
		assert.ErrorIs(t, errE, charon.ErrOrganizationValidationFailed)
		assert.EqualError(t, errors.Cause(errE), "unknown provider")
	})

	t.Run("ProviderCode rejected as not user-selectable", func(t *testing.T) {
		t.Parallel()
		// ProviderCode is the email-code fallback; it is not part of getAvailableProviders
		// and so must be rejected as "unknown provider" when an admin tries to list it.
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Code Provider Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{},
			Roles:              nil,
			DefaultRoles:       nil,
			AllowedProviders:   []charon.Provider{charon.ProviderUsername, charon.ProviderEmail, charon.ProviderPassword, charon.ProviderCode},
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.Error(t, errE)
		assert.ErrorIs(t, errE, charon.ErrOrganizationValidationFailed)
		assert.EqualError(t, errors.Cause(errE), "unknown provider")
	})

	t.Run("duplicates deduplicated and result sorted", func(t *testing.T) {
		t.Parallel()
		org := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Duplicates Org", Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications:       []charon.OrganizationApplication{},
			Roles:              nil,
			// Out of order with duplicates.
			DefaultRoles:     nil,
			AllowedProviders: []charon.Provider{charon.ProviderPassword, charon.ProviderUsername, charon.ProviderEmail, charon.ProviderPassword, charon.ProviderUsername},
		}
		errE := service.TestingCreateOrganization(ctx, org)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Equal(t, []charon.Provider{charon.ProviderEmail, charon.ProviderPassword, charon.ProviderUsername}, org.AllowedProviders)
	})
}

// TestGetAvailableProviders verifies the provider set an organization admin can choose
// from: the four built-ins (username, email, password, passkey) plus any configured
// third-party site providers. ProviderCode is intentionally absent because it is the
// password-flow fallback and is not user-selectable.
func TestGetAvailableProviders(t *testing.T) {
	t.Parallel()

	_, service, _, _, _ := startTestServer(t) //nolint:dogsled

	got := service.TestingGetAvailableProviders()

	// Built-ins must always be present.
	assert.Contains(t, got, charon.ProviderUsername)
	assert.Contains(t, got, charon.ProviderEmail)
	assert.Contains(t, got, charon.ProviderPassword)
	assert.Contains(t, got, charon.ProviderPasskey)

	// startTestServer wires up oidcTesting and samlTesting as site providers.
	assert.Contains(t, got, charon.Provider("oidcTesting"))
	assert.Contains(t, got, charon.Provider("samlTesting"))

	// ProviderCode is intentionally not user-selectable.
	assert.NotContains(t, got, charon.ProviderCode)
}

// TestRolesInOrganizationIdentityAndTokens tests the full cycle of roles in organization
// for both re-authentication and refresh-token flows. Roles are negotiated via OIDC scopes:
// the client requests role.* to receive a role.<key> granted scope for each role the
// user currently holds in the organization.
func TestRolesInOrganizationIdentityAndTokens(t *testing.T) {
	t.Parallel()

	role := "viewer"

	for _, accessTokenType := range []charon.AccessTokenType{charon.AccessTokenHMAC, charon.AccessTokenJWT} {
		t.Run(string(accessTokenType), func(t *testing.T) {
			t.Parallel()

			ts, service, _, _, _ := startTestServer(t)

			username := identifier.New().String()
			flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)
			accessToken, _ := signinUser(t, ts, service, username, username, charon.CompletedSignup, flowID, nonce, state, pkceVerifier, config, verifier)

			days30 := 30 * 24 * time.Hour
			applicationTemplate := createApplicationTemplate(t, ts, service, accessToken, accessTokenType, time.Hour, time.Hour, &days30, []charon.Role{{Key: role, Description: ""}})
			organization := createOrganization(t, ts, service, accessToken, applicationTemplate)

			appID := organization.Applications[0].ID.String()
			clientID := organization.Applications[0].ClientsBackend[0].ID.String()
			organizationID := organization.ID.String()

			requestedScope := "openid profile email offline_access role.*"
			scopeWithoutRoles := "openid profile email offline_access"
			scopeWithRole := "openid profile email offline_access role." + role

			// After adding organization with applicationTemplate, organization.Roles are empty, no identity has a role assigned.
			// Requesting role.* therefore expands to no role.<key> grants.
			orgAccessToken, idToken, refreshToken, identityID, sessionID, now := doOIDCOrganizationFlow(t, ts, service, username, clientID, *organization.ID, time.Hour, nonce, requestedScope, scopeWithoutRoles)
			validateAccessToken(t, ts, service, now, clientID, appID, organizationID, sessionID, orgAccessToken, map[string]time.Time{}, identityID, accessTokenType, time.Hour, scopeWithoutRoles)
			validateIDToken(t, ts, service, now, clientID, appID, organizationID, sessionID, nonce, orgAccessToken, idToken, map[string]time.Time{}, identityID)
			validateUserInfo(t, ts, service, orgAccessToken, identityID)
			validateOrganizationIdentity(t, ts, service, orgAccessToken, organizationID, identityID, []string{})

			// Assign role.
			organization.Roles = map[identifier.Identifier][]string{identityID: {role}}
			organization = updateOrganization(t, ts, service, accessToken, organization)
			verifyLatestActivity(t, ts, service, accessToken, charon.ActivityOrganizationUpdate, []charon.ActivityChangeType{charon.ActivityChangeRolesAdded}, nil, 1, 1, 0, 0)

			// Added role must appear as a role.<key> scope in refreshed tokens.
			orgAccessToken, idToken, refreshToken, now = exchangeRefreshTokenForTokens(t, ts, service, clientID, refreshToken, orgAccessToken, time.Hour, scopeWithRole)
			validateAccessToken(t, ts, service, now, clientID, appID, organizationID, sessionID, orgAccessToken, map[string]time.Time{}, identityID, accessTokenType, time.Hour, scopeWithRole)
			validateIDToken(t, ts, service, now, clientID, appID, organizationID, sessionID, nonce, orgAccessToken, idToken, map[string]time.Time{}, identityID)
			validateUserInfo(t, ts, service, orgAccessToken, identityID)
			validateOrganizationIdentity(t, ts, service, orgAccessToken, organizationID, identityID, []string{role})

			// Re-auth, role must appear as a role.<key> scope in new session token.
			reauthAccessToken, reauthIDToken, _, _, reauthSessionID, reauthNow := doOIDCOrganizationFlow(t, ts, service, username, clientID, *organization.ID, time.Hour, nonce, requestedScope, scopeWithRole)
			validateAccessToken(t, ts, service, reauthNow, clientID, appID, organizationID, reauthSessionID, reauthAccessToken, map[string]time.Time{}, identityID, accessTokenType, time.Hour, scopeWithRole)
			validateIDToken(t, ts, service, reauthNow, clientID, appID, organizationID, reauthSessionID, nonce, reauthAccessToken, reauthIDToken, map[string]time.Time{}, identityID)
			validateUserInfo(t, ts, service, reauthAccessToken, identityID)
			validateOrganizationIdentity(t, ts, service, reauthAccessToken, organizationID, identityID, []string{role})

			// Remove role.
			organization.Roles = map[identifier.Identifier][]string{}
			organization = updateOrganization(t, ts, service, accessToken, organization)
			verifyLatestActivity(t, ts, service, accessToken, charon.ActivityOrganizationUpdate, []charon.ActivityChangeType{charon.ActivityChangeRolesRemoved}, nil, 1, 1, 0, 0)

			// Removed role must not appear in refreshed tokens.
			orgAccessToken, idToken, _, now = exchangeRefreshTokenForTokens(t, ts, service, clientID, refreshToken, orgAccessToken, time.Hour, scopeWithoutRoles)
			validateAccessToken(t, ts, service, now, clientID, appID, organizationID, sessionID, orgAccessToken, map[string]time.Time{}, identityID, accessTokenType, time.Hour, scopeWithoutRoles)
			validateIDToken(t, ts, service, now, clientID, appID, organizationID, sessionID, nonce, orgAccessToken, idToken, map[string]time.Time{}, identityID)
			validateUserInfo(t, ts, service, orgAccessToken, identityID)
			validateOrganizationIdentity(t, ts, service, orgAccessToken, organizationID, identityID, []string{})

			// Re-auth, role must not appear in new session token.
			reauthAccessToken, reauthIDToken, _, _, reauthSessionID, reauthNow = doOIDCOrganizationFlow(t, ts, service, username, clientID, *organization.ID, time.Hour, nonce, requestedScope, scopeWithoutRoles)
			validateAccessToken(t, ts, service, reauthNow, clientID, appID, organizationID, reauthSessionID, reauthAccessToken, map[string]time.Time{}, identityID, accessTokenType, time.Hour, scopeWithoutRoles)
			validateIDToken(t, ts, service, reauthNow, clientID, appID, organizationID, reauthSessionID, nonce, reauthAccessToken, reauthIDToken, map[string]time.Time{}, identityID)
			validateUserInfo(t, ts, service, reauthAccessToken, identityID)
			validateOrganizationIdentity(t, ts, service, reauthAccessToken, organizationID, identityID, []string{})
		})
	}
}

// TestOrganizationDefaultRolesOnJoin verifies that the organization's default roles are assigned to
// the user when they join the organization (when they first sign in into one of its applications),
// that the assigned roles are exposed as role.<key> scopes of the issued tokens, and that changing
// the default roles afterwards does not change roles of users who have already joined.
func TestOrganizationDefaultRolesOnJoin(t *testing.T) {
	t.Parallel()

	role := "viewer"

	ts, service, _, _, _ := startTestServer(t) //nolint:dogsled

	username := identifier.New().String()
	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)
	accessToken, _ := signinUser(t, ts, service, username, username, charon.CompletedSignup, flowID, nonce, state, pkceVerifier, config, verifier)

	days30 := 30 * 24 * time.Hour
	applicationTemplate := createApplicationTemplate(t, ts, service, accessToken, charon.AccessTokenHMAC, time.Hour, time.Hour, &days30, []charon.Role{{Key: role, Description: ""}})
	organization := createOrganization(t, ts, service, accessToken, applicationTemplate)

	clientID := organization.Applications[0].ClientsBackend[0].ID.String()
	organizationID := organization.ID.String()

	organization.DefaultRoles = []string{role}
	organization = updateOrganization(t, ts, service, accessToken, organization)
	assert.Equal(t, []string{role}, organization.DefaultRoles)
	verifyLatestActivity(t, ts, service, accessToken, charon.ActivityOrganizationUpdate, []charon.ActivityChangeType{charon.ActivityChangeOtherData}, nil, 0, 1, 0, 0)

	requestedScope := "openid profile email offline_access role.*"
	scopeWithRole := "openid profile email offline_access role." + role

	// The user has not been in the organization before, so they join it during the flow and the
	// default role is assigned to them, which makes role.* expand to the role.<key> grant.
	orgAccessToken, _, _, identityID, _, _ := doOIDCOrganizationFlow(t, ts, service, username, clientID, *organization.ID, time.Hour, nonce, requestedScope, scopeWithRole) //nolint:dogsled
	validateOrganizationIdentity(t, ts, service, orgAccessToken, organizationID, identityID, []string{role})

	// The default role has been materialized into the organization's roles for the joined user.
	organization = getOrganization(t, ts, service, accessToken, organizationID)
	assert.Equal(t, []string{role}, organization.Roles[identityID])

	// Removing the default role does not remove it from the user who has already joined.
	organization.DefaultRoles = []string{}
	organization = updateOrganization(t, ts, service, accessToken, organization)
	assert.Empty(t, organization.DefaultRoles)
	validateOrganizationIdentity(t, ts, service, orgAccessToken, organizationID, identityID, []string{role})
}

// TestOrganizationDefaultRolesOnIdentityAdded verifies that the organization's default roles are
// assigned also when an identity is added to the organization through an identity update (which is
// what happens when an admin adds one of their identities on the organization page) and when an
// identity is created already added to the organization. It also verifies that changing an existing
// membership does not assign the default roles again.
func TestOrganizationDefaultRolesOnIdentityAdded(t *testing.T) {
	t.Parallel()

	role := "viewer"

	_, service, _, _, _ := startTestServer(t) //nolint:dogsled

	accountID := identifier.New()
	ctx := service.TestingWithAccountID(t.Context(), accountID)
	ctx = service.TestingWithSessionID(ctx)
	ctx = service.TestingWithRequestID(ctx)

	adminID := createTestIdentity(t, service, ctx)
	ctx = service.TestingWithIdentityID(ctx, adminID)

	appTemplate := &charon.ApplicationTemplate{
		ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
			ID:               nil,
			Base:             nil,
			Name:             "Default Roles Join App",
			Description:      "",
			HomepageTemplate: "https://example.com",
			IDScopes:         nil,
			Roles:            []charon.Role{{Key: role, Description: "Viewer"}},
			// Set Variables explicitly to empty so Validate does not auto-add the uriBase default;
			// we have no clients in OrganizationApplication so we do not need any variables.
			Variables:      []charon.Variable{},
			ClientsPublic:  []charon.ApplicationTemplateClientPublic{},
			ClientsBackend: []charon.ApplicationTemplateClientBackend{},
			ClientsService: []charon.ApplicationTemplateClientService{},
		},
		Admins: []charon.IdentityRef{},
	}
	errE := service.TestingCreateApplicationTemplate(ctx, appTemplate)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Each subtest gets its own organization so that they can run in parallel.
	makeOrganization := func(t *testing.T, name string) *charon.Organization {
		t.Helper()

		appTmpl := deepcopy.Copy(appTemplate.ApplicationTemplatePublic).(charon.ApplicationTemplatePublic) //nolint:forcetypeassert,errcheck
		organization := &charon.Organization{
			OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: name, Description: ""},
			Admins:             []charon.IdentityRef{},
			Applications: []charon.OrganizationApplication{{
				OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
					ID:                  nil,
					Base:                nil,
					Active:              true,
					ApplicationTemplate: appTmpl,
					Values:              []charon.Value{},
				},
				ClientsPublic:  []charon.OrganizationApplicationClientPublic{},
				ClientsBackend: []charon.OrganizationApplicationClientBackend{},
				ClientsService: []charon.OrganizationApplicationClientService{},
			}},
			Roles:            nil,
			DefaultRoles:     []string{role},
			AllowedProviders: nil,
		}
		errE := service.TestingCreateOrganization(ctx, organization)
		require.NoError(t, errE, "% -+#.1v", errE)
		return organization
	}

	t.Run("identity updated to be added to the organization", func(t *testing.T) {
		t.Parallel()
		organization := makeOrganization(t, "Identity Update Join Org")
		identityID := createTestIdentity(t, service, ctx)
		identity, _, errE := service.TestingGetIdentity(ctx, identityID)
		require.NoError(t, errE, "% -+#.1v", errE)

		identity.Organizations = append(identity.Organizations, charon.IdentityOrganization{
			ID:           nil,
			Base:         nil,
			Active:       true,
			Organization: organization.Ref(),
			Applications: []charon.OrganizationApplicationApplicationRef{},
		})
		errE = service.TestingUpdateIdentity(ctx, identity)
		require.NoError(t, errE, "% -+#.1v", errE)

		orgIdentityID := *identity.Organizations[0].ID

		stored, errE := service.TestingGetOrganization(ctx, *organization.ID)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Equal(t, []string{role}, stored.Roles[orgIdentityID])

		// An admin removes the role again and disables the membership.
		delete(stored.Roles, orgIdentityID)
		errE = service.TestingUpdateOrganization(ctx, stored)
		require.NoError(t, errE, "% -+#.1v", errE)

		identity.Organizations[0].Active = false
		errE = service.TestingUpdateIdentity(ctx, identity)
		require.NoError(t, errE, "% -+#.1v", errE)

		// The membership is not new anymore, so the default role is not assigned again.
		stored, errE = service.TestingGetOrganization(ctx, *organization.ID)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Empty(t, stored.Roles[orgIdentityID])
	})

	t.Run("identity created already added to the organization", func(t *testing.T) {
		t.Parallel()
		organization := makeOrganization(t, "Identity Create Join Org")
		identity := &charon.Identity{
			IdentityPublic: charon.IdentityPublic{
				ID:         nil,
				Username:   identifier.New().String(),
				Email:      "",
				GivenName:  "",
				FullName:   "",
				PictureURL: "",
			},
			Base:        nil,
			Description: "",
			Users:       nil,
			Admins:      nil,
			Organizations: []charon.IdentityOrganization{{
				ID:           nil,
				Base:         nil,
				Active:       true,
				Organization: organization.Ref(),
				Applications: []charon.OrganizationApplicationApplicationRef{},
			}},
		}
		errE := service.TestingCreateIdentity(ctx, identity)
		require.NoError(t, errE, "% -+#.1v", errE)

		orgIdentityID := *identity.Organizations[0].ID

		stored, errE := service.TestingGetOrganization(ctx, *organization.ID)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Equal(t, []string{role}, stored.Roles[orgIdentityID])
	})

	// Adding an identity to an organization requires admin access only over the identity and not over
	// the organization, so anybody can add their identity to any organization this way.
	t.Run("identity of a user who is not an organization admin", func(t *testing.T) {
		t.Parallel()
		organization := makeOrganization(t, "Not An Admin Join Org")

		otherCtx := service.TestingWithAccountID(t.Context(), identifier.New())
		otherCtx = service.TestingWithSessionID(otherCtx)
		otherCtx = service.TestingWithRequestID(otherCtx)
		otherIdentityID := createTestIdentity(t, service, otherCtx)
		otherCtx = service.TestingWithIdentityID(otherCtx, otherIdentityID)

		identity, _, errE := service.TestingGetIdentity(otherCtx, otherIdentityID)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.False(t, organization.HasAdminAccess(identity.Ref()))

		identity.Organizations = append(identity.Organizations, charon.IdentityOrganization{
			ID:           nil,
			Base:         nil,
			Active:       true,
			Organization: organization.Ref(),
			Applications: []charon.OrganizationApplicationApplicationRef{},
		})
		errE = service.TestingUpdateIdentity(otherCtx, identity)
		require.NoError(t, errE, "% -+#.1v", errE)

		orgIdentityID := *identity.Organizations[0].ID

		stored, errE := service.TestingGetOrganization(otherCtx, *organization.ID)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Equal(t, []string{role}, stored.Roles[orgIdentityID])

		// The role assignment is logged for the organization, with the joined user as the actor
		// (organization-scoped, so that the activity does not link their Charon identity ID with
		// their organization-scoped identity ID).
		activities, errE := service.TestingListActivities(otherCtx)
		require.NoError(t, errE, "% -+#.1v", errE)
		var logged *charon.Activity
		for _, activity := range activities {
			if activity.Type == charon.ActivityOrganizationUpdate && activity.IsForOrganization(organization.Ref()) {
				logged = activity
				break
			}
		}
		require.NotNil(t, logged)
		assert.Equal(t, []charon.ActivityChangeType{charon.ActivityChangeRolesAdded}, logged.Changes)
		assert.Equal(t, []charon.OrganizationIdentityRef{{
			Organization: organization.Ref(),
			Identity:     charon.IdentityRef{ID: orgIdentityID},
		}}, logged.Identities)
		assert.Equal(t, &charon.OrganizationIdentityRef{
			Organization: organization.Ref(),
			Identity:     charon.IdentityRef{ID: orgIdentityID},
		}, logged.Actor)
	})
}

// TestIdentityJoinOrganizationBlocked verifies that a user who has been blocked in an organization
// cannot add their identity to it, neither by updating an existing identity nor by creating one
// already added to the organization. Anybody can add their identity to any organization, so this is
// the same restriction as the one applied when a user joins by signing in.
func TestIdentityJoinOrganizationBlocked(t *testing.T) {
	t.Parallel()

	_, service, _, _, _ := startTestServer(t) //nolint:dogsled

	ctx := service.TestingWithAccountID(t.Context(), identifier.New())
	ctx = service.TestingWithSessionID(ctx)
	ctx = service.TestingWithRequestID(ctx)
	adminID := createTestIdentity(t, service, ctx)
	ctx = service.TestingWithIdentityID(ctx, adminID)

	organization := &charon.Organization{
		OrganizationPublic: charon.OrganizationPublic{ID: nil, Base: nil, Name: "Blocked Join Org", Description: ""},
		Admins:             []charon.IdentityRef{},
		Applications:       []charon.OrganizationApplication{},
		Roles:              nil,
		DefaultRoles:       nil,
		AllowedProviders:   nil,
	}
	errE := service.TestingCreateOrganization(ctx, organization)
	require.NoError(t, errE, "% -+#.1v", errE)

	membership := func() charon.IdentityOrganization {
		return charon.IdentityOrganization{
			ID:           nil,
			Base:         nil,
			Active:       true,
			Organization: organization.Ref(),
			Applications: []charon.OrganizationApplicationApplicationRef{},
		}
	}

	// A user which is not an admin of the organization joins it.
	userCtx := service.TestingWithAccountID(t.Context(), identifier.New())
	userCtx = service.TestingWithSessionID(userCtx)
	userCtx = service.TestingWithRequestID(userCtx)
	userIdentityID := createTestIdentity(t, service, userCtx)
	userCtx = service.TestingWithIdentityID(userCtx, userIdentityID)

	identity, _, errE := service.TestingGetIdentity(userCtx, userIdentityID)
	require.NoError(t, errE, "% -+#.1v", errE)
	identity.Organizations = append(identity.Organizations, membership())
	errE = service.TestingUpdateIdentity(userCtx, identity)
	require.NoError(t, errE, "% -+#.1v", errE)

	// The organization admin blocks the user and all their accounts.
	errE = service.TestingBlockAccounts(ctx, identity, *organization.ID, *identity.Organizations[0].ID, "spam", "You have been blocked.")
	require.NoError(t, errE, "% -+#.1v", errE)

	// The user can still update their identity, including leaving the organization.
	identity.Organizations = nil
	errE = service.TestingUpdateIdentity(userCtx, identity)
	require.NoError(t, errE, "% -+#.1v", errE)

	// But they cannot add themselves back.
	identity.Organizations = []charon.IdentityOrganization{membership()}
	errE = service.TestingUpdateIdentity(userCtx, identity)
	assert.ErrorIs(t, errE, charon.ErrIdentityBlocked)
	assert.EqualError(t, errE, "identity blocked")

	// Nor can they join with a newly created identity.
	newIdentity := &charon.Identity{
		IdentityPublic: charon.IdentityPublic{
			ID:         nil,
			Username:   identifier.New().String(),
			Email:      "",
			GivenName:  "",
			FullName:   "",
			PictureURL: "",
		},
		Base:          nil,
		Description:   "",
		Users:         nil,
		Admins:        nil,
		Organizations: []charon.IdentityOrganization{membership()},
	}
	errE = service.TestingCreateIdentity(userCtx, newIdentity)
	assert.ErrorIs(t, errE, charon.ErrIdentityBlocked)
	assert.EqualError(t, errE, "identity blocked")
}
