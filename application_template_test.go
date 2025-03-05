package charon_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

func createApplicationTemplate(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string) *charon.ApplicationTemplate {
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

	return &newApplicationTemplate
}
