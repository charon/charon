package charon_test

import (
	"bytes"
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
		hash, err := argon2id.CreateHash(applicationClientSecret, charon.TestingArgon2idParams())
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
	var organizationRef charon.Organization
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &organizationRef)
	require.NoError(t, errE, "% -+#.1v", errE)

	organizationGet, errE := service.ReverseAPI("OrganizationGet", waf.Params{"id": organizationRef.ID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+organizationGet, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var newOrganization charon.Organization
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &newOrganization)
	require.NoError(t, errE, "% -+#.1v", errE)

	verifyLatestActivity(t, ts, service, accessToken, charon.ActivityOrganizationCreate, nil, nil, 0, 1, 0, 0)

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
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangeOtherData},
			expectedAdminsChanged:          []charon.IdentityRef{},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps:                   []charon.OrganizationApplicationRef{},
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
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangePermissionsAdded},
			expectedAdminsChanged:          []charon.IdentityRef{{ID: identity2ID}},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps:                   []charon.OrganizationApplicationRef{},
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
			expectedChanges:                []charon.ActivityChangeType{charon.ActivityChangePermissionsRemoved},
			expectedAdminsChanged:          []charon.IdentityRef{{ID: identity2ID}},
			expectedRolesIdentitiesChanged: []charon.IdentityRef{},
			expectedApps:                   []charon.OrganizationApplicationRef{},
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
					ID:   &orgID,
					Name: "Test Org",
				},
				Roles: map[identifier.Identifier][]string{},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin"},
				},
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
					ID:   &orgID,
					Name: "Test Org",
				},
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin"},
				},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Roles: map[identifier.Identifier][]string{},
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
					ID:   &orgID,
					Name: "Test Org",
				},
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin", "viewer"},
				},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"viewer", "admin"},
				},
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
					ID:   &orgID,
					Name: "Test Org",
				},
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin"},
				},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"viewer"},
				},
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
					ID:   &orgID,
					Name: "Test Org",
				},
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin"},
				},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Roles: map[identifier.Identifier][]string{
					identity1ID: {},
					identity2ID: {"viewer"},
				},
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
					ID:   &orgID,
					Name: "Test Org",
				},
				Roles: map[identifier.Identifier][]string{},
			},
			updated: &charon.Organization{
				OrganizationPublic: charon.OrganizationPublic{
					ID:   &orgID,
					Name: "Test Org",
				},
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin"},
					identity2ID: {"viewer"},
					identity3ID: {"editor"},
				},
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
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin"},
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
				Roles: map[identifier.Identifier][]string{
					identity1ID: {"admin", "viewer"},
				},
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
// (because Admin IdentityRefs are Charon organization-scoped IDs), while identities derived from
// role changes are wrapped with the organization being updated (because role map keys are scoped
// to that organization).
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
			Name:        "Activity Scoping Test Org",
			Description: "",
		},
		Admins:       []charon.IdentityRef{},
		Applications: []charon.OrganizationApplication{},
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
	// (not with the updated organization), because Admin IdentityRefs are Charon organization-scoped IDs.
	charonID := service.TestingCharonOrganizationID()
	require.Len(t, updateActivity.Identities, 1)
	assert.Equal(t, charonID, updateActivity.Identities[0].Organization.ID)
	assert.Equal(t, addedAdminID, updateActivity.Identities[0].Identity.ID)
	assert.NotEqual(t, *organization.ID, updateActivity.Identities[0].Organization.ID)
}
