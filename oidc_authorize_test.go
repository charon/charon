package charon_test

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

func TestOIDCAuthorizeAndToken(t *testing.T) {
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

	applicationID := organization.Applications[0].ID.String()
	clientID := organization.Applications[0].ClientsBackend[0].ID.String()

	qs := url.Values{
		"client_id":             []string{clientID},
		"redirect_uri":          []string{"https://example.com/redirect"},
		"scope":                 []string{"openid offline_access"},
		"response_type":         []string{"code"},
		"response_mode":         []string{"query"},
		"code_challenge_method": []string{"S256"},
		"code_challenge":        []string{codeChallenge},
		"state":                 []string{state},
		"nonce":                 []string{nonce},
	}
	oidcAuthorize, errE := service.Reverse("OIDCAuthorize", nil, qs)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Get(ts.URL + oidcAuthorize) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, string(out))
	assert.Equal(t, 2, resp.ProtoMajor)
	location := resp.Header.Get("Location")
	assert.NotEmpty(t, location)

	route, errE := service.GetRoute(location, http.MethodGet)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, "AuthFlowGet", route.Name)

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

	doRedirect(t, ts, service, *organization.ID, flowID)

	nonAPIAuthFlowGet, errE := service.Reverse("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Get(ts.URL + nonAPIAuthFlowGet) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, string(out))
	assert.Equal(t, 2, resp.ProtoMajor)
	location = resp.Header.Get("Location")
	assert.NotEmpty(t, location)
	assert.True(t, strings.HasPrefix(location, "https://example.com/redirect?"), location)

	// Flow is available and is completed.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"oidc","name":"Test application","homepage":"https://example.com","organizationId":"`+organization.ID.String()+`","provider":"password","completed":"redirect"}`, string(out))
	}

	parsedLocation, err := url.Parse(location)
	require.NoError(t, err)
	locationQuery := parsedLocation.Query()
	code := locationQuery.Get("code")
	locationQuery.Del("code")
	assert.NotEmpty(t, code)
	assert.Equal(t, url.Values{"scope": []string{"openid offline_access"}, "state": []string{state}}, locationQuery)

	accessToken, idToken, refreshToken := exchangeCodeForTokens(t, ts, service, clientID, code, challenge)

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	cookies := ts.Client().Jar.Cookies(u)

	var session string
	for _, cookie := range cookies {
		if cookie.Name == charon.SessionCookieName {
			session = cookie.Value
			break
		}
	}
	require.NotEmpty(t, session)

	now := time.Now()
	accessTokenLastTimestamps := map[string]time.Time{}
	idTokenLastTimestamps := map[string]time.Time{}

	uniqueStrings := mapset.NewThreadUnsafeSet[string]()
	assert.True(t, uniqueStrings.Add(validateAccessToken(t, ts, service, clientID, applicationID, session, accessToken, accessTokenLastTimestamps)))
	assert.True(t, uniqueStrings.Add(validateIDToken(t, ts, service, clientID, applicationID, nonce, accessToken, idToken, idTokenLastTimestamps)))
	validateIntrospect(t, ts, service, now, clientID, applicationID, session, refreshToken, "refresh_token")

	for i := 0; i < 3; i++ {
		// We sleep for a second so that all timestamps increase (they are at second granularity).
		time.Sleep(time.Second)

		accessToken, idToken, refreshToken = exchangeRefreshTokenForTokens(t, ts, service, clientID, refreshToken, accessToken)

		assert.True(t, uniqueStrings.Add(validateAccessToken(t, ts, service, clientID, applicationID, session, accessToken, accessTokenLastTimestamps)))
		assert.True(t, uniqueStrings.Add(validateIDToken(t, ts, service, clientID, applicationID, nonce, accessToken, idToken, idTokenLastTimestamps)))
		validateIntrospect(t, ts, service, now, clientID, applicationID, session, refreshToken, "refresh_token")
	}
}
