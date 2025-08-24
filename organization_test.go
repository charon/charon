package charon_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/alexedwards/argon2id"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

const applicationClientSecret = "client-secret"

func createOrganization(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string, applicationTemplate *charon.ApplicationTemplate) *charon.Organization {
	t.Helper()

	organizationCreate, errE := service.ReverseAPI("OrganizationCreate", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	applications := []charon.OrganizationApplication{}
	if applicationTemplate != nil {
		hash, err := argon2id.CreateHash(applicationClientSecret, &charon.Argon2idParams)
		require.NoError(t, err)

		require.Empty(t, applicationTemplate.Variables)
		require.Empty(t, applicationTemplate.ClientsPublic)
		require.Len(t, applicationTemplate.ClientsBackend, 1)
		require.Empty(t, applicationTemplate.ClientsService)

		applications = append(applications, charon.OrganizationApplication{
			OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
				Active:              true,
				ApplicationTemplate: applicationTemplate.ApplicationTemplatePublic,
				Values:              []charon.Value{},
			},
			ClientsPublic: []charon.OrganizationApplicationClientPublic{},
			ClientsBackend: []charon.OrganizationApplicationClientBackend{
				{
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
			Name:        "Test organization",
			Description: "",
		},
		Applications: applications,
	}

	data, errE := x.MarshalWithoutEscapeHTML(organization)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+organizationCreate, bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:bodyclose

	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var organizationRef charon.Organization
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &organizationRef)
	require.NoError(t, errE, "% -+#.1v", errE)

	organizationGet, errE := service.ReverseAPI("OrganizationGet", waf.Params{"id": organizationRef.ID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+organizationGet, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var newOrganization charon.Organization
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &newOrganization)
	require.NoError(t, errE, "% -+#.1v", errE)

	return &newOrganization
}

func TestOrganizationChanges(t *testing.T) { //nolint:maintidx
	t.Parallel()

	orgID := identifier.New()
	identity1ID := identifier.New()
	identity2ID := identifier.New()
	identity3ID := identifier.New()
	app1ID := identifier.New()
	app2ID := identifier.New()

	tests := []struct {
		name               string
		existing           *charon.Organization
		updated            *charon.Organization
		expectedChanges    []charon.ActivityChangeType
		expectedIdentities []charon.IdentityRef
		expectedApps       []charon.OrganizationApplicationRef
	}{
		{
			name: "no changes",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Name:        "Test Org",
					Description: "Test description",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Active: true,
						},
					},
				},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Name:        "Test Org",
					Description: "Test description",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Active: true,
						},
					},
				},
			},
			expectedChanges:    []charon.ActivityChangeType{},
			expectedIdentities: []charon.IdentityRef{},
			expectedApps:       []charon.OrganizationApplicationRef{},
		},
		{
			name: "name and description changed",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Name:        "Old Name",
					Description: "Old description",
				},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Name:        "New Name",
					Description: "New description",
				},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeOtherData},
			expectedIdentities: []charon.IdentityRef{},
			expectedApps:       []charon.OrganizationApplicationRef{},
		},
		{
			name: "admin added",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}, {ID: identity2ID}},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangePermissionsAdded},
			expectedIdentities: []charon.IdentityRef{{ID: identity2ID}},
			expectedApps:       []charon.OrganizationApplicationRef{},
		},
		{
			name: "admin removed",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}, {ID: identity2ID}},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangePermissionsRemoved},
			expectedIdentities: []charon.IdentityRef{{ID: identity2ID}},
			expectedApps:       []charon.OrganizationApplicationRef{},
		},
		{
			name: "application membership added",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Applications: []charon.OrganizationApplication{},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Active: true,
						},
					},
				},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded},
			expectedIdentities: []charon.IdentityRef{},
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
					ID:   &orgID,
					Name: "Test Org",
				},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Active: true,
						},
					},
				},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Applications: []charon.OrganizationApplication{},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeMembershipRemoved},
			expectedIdentities: []charon.IdentityRef{},
			expectedApps: []charon.OrganizationApplicationRef{
				{
					Organization: charon.OrganizationRef{ID: orgID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app1ID},
				},
			},
		},
		{
			name: "application membership activated",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Active: false,
						},
					},
				},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Active: true,
						},
					},
				},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeMembershipActivated},
			expectedIdentities: []charon.IdentityRef{},
			expectedApps: []charon.OrganizationApplicationRef{
				{
					Organization: charon.OrganizationRef{ID: orgID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app1ID},
				},
			},
		},
		{
			name: "application membership disabled",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Active: true,
						},
					},
				},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Active: false,
						},
					},
				},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeMembershipDisabled},
			expectedIdentities: []charon.IdentityRef{},
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
					ID:   &orgID,
					Name: "Test Org",
				},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Active: true,
							ApplicationTemplate: charon.ApplicationTemplatePublic{
								Name:        "Old Template",
								Description: "Old description",
							},
						},
					},
				},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Active: true,
							ApplicationTemplate: charon.ApplicationTemplatePublic{
								Name:        "New Template",
								Description: "New description",
							},
						},
					},
				},
			},
			expectedChanges:    []charon.ActivityChangeType{charon.ActivityChangeMembershipChanged},
			expectedIdentities: []charon.IdentityRef{},
			expectedApps: []charon.OrganizationApplicationRef{
				{
					Organization: charon.OrganizationRef{ID: orgID},
					Application:  charon.OrganizationApplicationApplicationRef{ID: app1ID},
				},
			},
		},
		{
			name: "complex scenario with multiple changes",
			existing: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Name:        "Old Name",
					Description: "Old description",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}, {ID: identity2ID}},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Active: false,
						},
					},
				},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:          &orgID,
					Name:        "New Name",
					Description: "New description",
				},
				Admins: []charon.IdentityRef{{ID: identity1ID}, {ID: identity3ID}},
				Applications: []charon.OrganizationApplication{
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app1ID,
							Active: true,
						},
					},
					{
						OrganizationApplicationPublic: charon.OrganizationApplicationPublic{
							ID:     &app2ID,
							Active: true,
						},
					},
				},
			},
			expectedChanges: []charon.ActivityChangeType{
				charon.ActivityChangeOtherData,
				charon.ActivityChangePermissionsAdded,
				charon.ActivityChangePermissionsRemoved,
				charon.ActivityChangeMembershipAdded,
				charon.ActivityChangeMembershipActivated,
			},
			expectedIdentities: []charon.IdentityRef{{ID: identity2ID}, {ID: identity3ID}},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			changes, identities, apps := tt.updated.Changes(tt.existing)

			// Sort expected slices to match deterministic ordering from Changes method.
			slices.SortFunc(tt.expectedIdentities, charon.TestingIdentityRefCmp)
			slices.SortFunc(tt.expectedApps, charon.TestingOrganizationApplicationRefCmp)

			// Check all expected outputs with deterministic ordering.
			assert.Equal(t, tt.expectedChanges, changes, "Changes mismatch")
			assert.Equal(t, tt.expectedIdentities, identities, "Identities mismatch")
			assert.Equal(t, tt.expectedApps, apps, "Applications mismatch")
		})
	}
}
