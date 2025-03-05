package charon_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexedwards/argon2id"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
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
	resp, err := ts.Client().Do(req) //nolint:noctx,bodyclose

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
	resp, err = ts.Client().Do(req) //nolint:noctx,bodycloseodyclose
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
