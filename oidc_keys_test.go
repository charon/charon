package charon_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"

	"gitlab.com/charon/charon"
)

func getKeys(t *testing.T, ts *httptest.Server, service *charon.Service) jose.JSONWebKeySet {
	oidcKeys, errE := service.Reverse("OIDCKeys", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Get(ts.URL + oidcKeys) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var keySet jose.JSONWebKeySet
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &keySet)
	require.NoError(t, errE, "% -+#.1v", errE)

	return keySet
}
