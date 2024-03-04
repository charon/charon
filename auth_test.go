package charon_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"

	"gitlab.com/charon/charon"
)

func signoutUser(t *testing.T, ts *httptest.Server, service *charon.Service) {
	t.Helper()

	authSignout, errE := service.ReverseAPI("AuthSignout", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Post(ts.URL+authSignout, "application/json", strings.NewReader(`{"location":"/"}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authSignoutResponse charon.AuthSignoutResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authSignoutResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, "/", authSignoutResponse.URL)
}
