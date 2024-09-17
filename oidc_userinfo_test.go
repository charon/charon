package charon_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"

	"gitlab.com/charon/charon"
)

//nolint:tagliatelle
type userInfoResponse struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	GivenName         string `json:"given_name"`
	Name              string `json:"name"`
	Picture           string `json:"picture"`
	PreferredUsername string `json:"preferred_username"`
}

func validateUserInfo(t *testing.T, ts *httptest.Server, service *charon.Service, token string, identityID identifier.Identifier) {
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
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var response userInfoResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &response)
	require.NoError(t, errE, "% -+#.1v", errE)

	assert.Equal(t, identityID.String(), response.Subject)
	assert.Equal(t, "user@example.com", response.Email)
	assert.True(t, response.EmailVerified)
	assert.Equal(t, "User", response.GivenName)
	assert.Equal(t, "User Name", response.Name)
	assert.Equal(t, "https://example.com/picture.png", response.Picture)
	assert.Equal(t, "username", response.PreferredUsername)
}
