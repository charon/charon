package charon_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	smtpmock "github.com/mocktools/go-smtp-mock/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

func TestAuthFlowCodeOnly(t *testing.T) {
	t.Parallel()

	user := identifier.New().String()
	email := user + "@example.com"

	ts, service, smtpServer, _ := startTestServer(t)

	signinUserCode(t, ts, service, smtpServer, email, charon.CompletedSignup)

	signoutUser(t, ts, service)

	signinUserCode(t, ts, service, smtpServer, email, charon.CompletedSignin)
}

func TestAuthFlowPasswordAndCode(t *testing.T) {
	t.Parallel()

	user := identifier.New().String()
	email := user + "@example.com"

	ts, service, smtpServer, _ := startTestServer(t)

	flowID := createAuthFlow(t, ts, service)

	// Start password authentication with e-mail address.
	resp := startPasswordSignin(t, ts, service, email, nil, flowID, charon.TargetSession) //nolint:bodyclose

	// Complete with user code.
	completeUserCode(t, ts, service, smtpServer, resp, email, charon.CompletedSignup, flowID)

	signoutUser(t, ts, service)

	// Signed-up user can authenticate with code only.
	signinUserCode(t, ts, service, smtpServer, email, charon.CompletedSignin)

	signoutUser(t, ts, service)

	// Signed-up user can authenticate with password only.
	flowID = createAuthFlow(t, ts, service)
	signinUser(t, ts, service, email, charon.CompletedSignin, nil, flowID, charon.TargetSession)
}

func signinUserCode(t *testing.T, ts *httptest.Server, service *charon.Service, smtpServer *smtpmock.Server, emailOrUsername string, signinOrSignout charon.Completed) {
	t.Helper()

	flowID := createAuthFlow(t, ts, service)

	authFlowCodeStart, errE := service.ReverseAPI("AuthFlowCodeStart", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Start code authentication.
	resp, err := ts.Client().Post(ts.URL+authFlowCodeStart, "application/json", strings.NewReader(`{"emailOrUsername":"`+emailOrUsername+`"}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)

	completeUserCode(t, ts, service, smtpServer, resp, emailOrUsername, signinOrSignout, flowID)
}

func completeUserCode(t *testing.T, ts *httptest.Server, service *charon.Service, smtpServer *smtpmock.Server, resp *http.Response, emailOrUsername string, signinOrSignout charon.Completed, flowID identifier.Identifier) {
	t.Helper()

	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"code","emailOrUsername":"`+emailOrUsername+`"}`, string(out))

	messages := smtpServer.MessagesAndPurge()

	require.Len(t, messages, 1)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available, current provider is code.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"code","emailOrUsername":"`+emailOrUsername+`"}`, string(out))
	}

	nonAPIAuthFlowGet, errE := service.Reverse("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	r, err := regexp.Compile(regexp.QuoteMeta(fmt.Sprintf("%s%s#code=3D", ts.URL, nonAPIAuthFlowGet)) + `(\d+)`)
	require.NoError(t, err)

	match := r.FindStringSubmatch(messages[len(messages)-1].MsgRequest())
	require.NotNil(t, match)

	authFlowCodeComplete, errE := service.ReverseAPI("AuthFlowCodeComplete", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Complete code authentication.
	resp, err = ts.Client().Post(ts.URL+authFlowCodeComplete, "application/json", strings.NewReader(`{"code":"`+match[1]+`"}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authFlowResponse charon.AuthFlowResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.Equal(t, signinOrSignout, authFlowResponse.Completed)
	assert.Len(t, resp.Cookies(), 1)
	for _, cookie := range resp.Cookies() {
		assert.Equal(t, charon.SessionCookieName, cookie.Name)
	}

	// Flow is available and is completed.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		// There is no username or e-mail address in the response after the flow completes.
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"code","completed":"`+string(signinOrSignout)+`","location":{"url":"/","replace":true}}`, string(out))
	}
}
