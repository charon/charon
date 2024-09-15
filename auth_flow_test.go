package charon_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

func createAuthFlow(t *testing.T, ts *httptest.Server, service *charon.Service) identifier.Identifier {
	t.Helper()

	authFlowCreate, errE := service.ReverseAPI("AuthFlowCreate", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Start the session target auth flow.
	resp, err := ts.Client().Post(ts.URL+authFlowCreate, "application/json", strings.NewReader(`{"location":"/"}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authFlowCreateResponse charon.AuthFlowCreateResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowCreateResponse)
	require.NoError(t, errE, "% -+#.1v", errE)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": authFlowCreateResponse.ID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available in initial state.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard"}`, string(out))
	}

	return authFlowCreateResponse.ID
}

func chooseIdentity(t *testing.T, ts *httptest.Server, service *charon.Service, organizationID, flowID identifier.Identifier) {
	t.Helper()

	identityListGet, errE := service.ReverseAPI("IdentityList", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Get(ts.URL + identityListGet) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var identities []charon.IdentityRef
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &identities)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Len(t, identities, 1)

	authFlowChooseIdentity, errE := service.ReverseAPI("AuthFlowChooseIdentity", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	request, errE := x.MarshalWithoutEscapeHTML(charon.AuthFlowChooseIdentityRequest{
		Identity: identities[0],
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
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"oidc","name":"Test application","homepage":"https://example.com","organizationId":"`+organizationID.String()+`","provider":"password","completed":"identity"}`, string(out))
	}
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
