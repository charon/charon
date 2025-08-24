package charon_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

func createApplicationTemplate(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, accessTokenType charon.AccessTokenType, accessTokenLifespan, idTokenLifespan time.Duration, refreshTokenLifespan *time.Duration) *charon.ApplicationTemplate {
	t.Helper()

	applicationTemplateCreate, errE := service.ReverseAPI("ApplicationTemplateCreate", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	applicationTemplate := charon.ApplicationTemplate{
		ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
			Name:             "Test application",
			Description:      "",
			HomepageTemplate: "https://example.com",
			IDScopes:         []string{"openid", "profile", "email", "offline_access"},
			Variables:        []charon.Variable{},
			ClientsPublic:    []charon.ApplicationTemplateClientPublic{},
			ClientsBackend: []charon.ApplicationTemplateClientBackend{
				{
					Description:             "",
					AdditionalScopes:        []string{},
					TokenEndpointAuthMethod: "client_secret_post",
					RedirectURITemplates:    []string{"https://example.com/redirect"},
					AccessTokenType:         accessTokenType,
					AccessTokenLifespan:     charon.Duration(accessTokenLifespan),
					IDTokenLifespan:         charon.Duration(idTokenLifespan),
					RefreshTokenLifespan:    (*charon.Duration)(refreshTokenLifespan),
				},
			},
			ClientsService: []charon.ApplicationTemplateClientService{},
		},
	}

	data, errE := x.MarshalWithoutEscapeHTML(applicationTemplate)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+applicationTemplateCreate, bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var applicationTemplateRef charon.ApplicationTemplateRef
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &applicationTemplateRef)
	require.NoError(t, errE, "% -+#.1v", errE)

	applicationTemplateGet, errE := service.ReverseAPI("ApplicationTemplateGet", waf.Params{"id": applicationTemplateRef.ID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+applicationTemplateGet, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var newApplicationTemplate charon.ApplicationTemplate
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &newApplicationTemplate)
	require.NoError(t, errE, "% -+#.1v", errE)

	verifyLatestActivity(t, ts, service, accessToken, charon.ActivityApplicationTemplateCreate, nil, 0, 0, 1, 0)

	return &newApplicationTemplate
}

func TestApplicationTemplateChanges(t *testing.T) {
	t.Parallel()

	appID := identifier.New()
	identity1ID := identifier.New()
	identity2ID := identifier.New()
	identity3ID := identifier.New()

	tests := []struct {
		name               string
		existing           *charon.ApplicationTemplate
		updated            *charon.ApplicationTemplate
		expectedChanges    []charon.ActivityChangeType
		expectedIdentities []charon.IdentityRef
	}{
		{
			name: "no changes",
			existing: &charon.ApplicationTemplate{
				ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
					ID:          &appID,
					Name:        "Test App",
					Description: "Test description",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}},
			},
			updated: &charon.ApplicationTemplate{
				ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
					ID:          &appID,
					Name:        "Test App",
					Description: "Test description",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}},
			},
			expectedChanges:    []charon.ActivityChangeType{},
			expectedIdentities: []charon.IdentityRef{},
		},
		{
			name: "name changed",
			existing: &charon.ApplicationTemplate{
				ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
					ID:          &appID,
					Name:        "Old Name",
					Description: "Test description",
				},
			},
			updated: &charon.ApplicationTemplate{
				ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
					ID:          &appID,
					Name:        "New Name",
					Description: "Test description",
				},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeOtherData},
			expectedIdentities: []charon.IdentityRef{},
		},
		{
			name: "description changed",
			existing: &charon.ApplicationTemplate{
				ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
					ID:          &appID,
					Name:        "Test App",
					Description: "Old description",
				},
			},
			updated: &charon.ApplicationTemplate{
				ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
					ID:          &appID,
					Name:        "Test App",
					Description: "New description",
				},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeOtherData},
			expectedIdentities: []charon.IdentityRef{},
		},
		{
			name: "admin added",
			existing: &charon.ApplicationTemplate{
				ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
					ID:   &appID,
					Name: "Test App",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}},
			},
			updated: &charon.ApplicationTemplate{
				ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
					ID:   &appID,
					Name: "Test App",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}, {ID: identity2ID}},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangePermissionsAdded},
			expectedIdentities: []charon.IdentityRef{{ID: identity2ID}},
		},
		{
			name: "admin removed",
			existing: &charon.ApplicationTemplate{
				ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
					ID:   &appID,
					Name: "Test App",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}, {ID: identity2ID}},
			},
			updated: &charon.ApplicationTemplate{
				ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
					ID:   &appID,
					Name: "Test App",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangePermissionsRemoved},
			expectedIdentities: []charon.IdentityRef{{ID: identity2ID}},
		},
		{
			name: "complex scenario with multiple changes",
			existing: &charon.ApplicationTemplate{
				ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
					ID:          &appID,
					Name:        "Old Name",
					Description: "Old description",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}, {ID: identity2ID}},
			},
			updated: &charon.ApplicationTemplate{
				ApplicationTemplatePublic: charon.ApplicationTemplatePublic{
					ID:          &appID,
					Name:        "New Name",
					Description: "New description",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}, {ID: identity3ID}},
			},
			expectedChanges: []charon.ActivityChangeType{
				charon.ActivityChangeOtherData,
				charon.ActivityChangePermissionsAdded,
				charon.ActivityChangePermissionsRemoved,
			},
			expectedIdentities: []charon.IdentityRef{{ID: identity2ID}, {ID: identity3ID}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			changes, identities := tt.updated.Changes(tt.existing)

			// Sort expected slices to match deterministic ordering from Changes method.
			slices.SortFunc(tt.expectedIdentities, charon.TestingIdentityRefCmp)

			// Check all expected outputs with deterministic ordering.
			assert.Equal(t, tt.expectedChanges, changes, "Changes mismatch")
			assert.Equal(t, tt.expectedIdentities, identities, "Identities mismatch")
		})
	}
}
