package charon_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/charon/charon"
	"gitlab.com/tozd/go/x"
)

type userInfoResponse struct {
	Subject string `json:"sub"`
}

func validateUserInfo(t *testing.T, ts *httptest.Server, service *charon.Service, token string) {
	t.Helper()

	oidcUserInfo, errE := service.ReverseAPI("OIDCUserInfo", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	data := url.Values{
		"access_token": []string{token},
	}

	resp, err := ts.Client().Post(ts.URL+oidcUserInfo, "application/x-www-form-urlencoded", strings.NewReader(data.Encode())) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json;charset=UTF-8", resp.Header.Get("Content-Type"))

	var response userInfoResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &response)
	require.NoError(t, errE, "% -+#.1v", errE)

	// TODO: Check exact value of the subject.
	assert.NotEmpty(t, response.Subject)
}
