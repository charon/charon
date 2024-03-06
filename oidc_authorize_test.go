package charon_test

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

func TestOIDCAuthorize(t *testing.T) {
	t.Parallel()

	ts, service, _, _ := startTestServer(t)

	username := identifier.New().String()
	state := identifier.New().String()
	nonce := identifier.New().String()
	challenge := identifier.New().String() + identifier.New().String() + identifier.New().String()

	challengeHash := sha256.Sum256([]byte(challenge))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	flowID := createAuthFlow(t, ts, service)
	signinUser(t, ts, service, username, charon.CompletedSignup, nil, flowID, charon.TargetSession)

	applicationTemplate := createApplicationTemplate(t, ts, service)

	organization := createOrganization(t, ts, service, applicationTemplate)

	qs := url.Values{
		"client_id":             []string{organization.Applications[0].ClientsBackend[0].ID.String()},
		"redirect_uri":          []string{"https://example.com/redirect"},
		"scope":                 []string{"openid"},
		"response_type":         []string{"code"},
		"response_mode":         []string{"query"},
		"code_challenge_method": []string{"S256"},
		"code_challenge":        []string{codeChallenge},
		"state":                 []string{state},
		"nonce":                 []string{nonce},
	}
	oidcAuthorize, errE := service.Reverse("OIDCAuthorize", nil, qs)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Get(ts.URL + oidcAuthorize)
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, string(out))
	location := resp.Header.Get("Location")
	assert.NotEmpty(t, location)

	route, errE := service.GetRoute(location, http.MethodGet)
	require.NoError(t, errE, "% -+#.1v", errE)

	flowID, errE = identifier.FromString(route.Params["id"])
	require.NoError(t, errE, "% -+#.1v", errE)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available, target is oidc.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"oidc","name":"Test application","homepage":"https://example.com","organizationId":"`+organization.ID.String()+`"}`, string(out))
	}

	signinUser(t, ts, service, username, charon.CompletedSignin, organization.ID, flowID, charon.TargetOIDC)

	chooseIdentity(t, ts, service, *organization.ID, flowID)
}
