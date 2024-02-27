package charon_test

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

func TestAuthFlowCode(t *testing.T) {
	t.Parallel()

	ts, service, smtpServer := startTestServer(t)

	authFlowCreate, errE := service.ReverseAPI("AuthFlowCreate", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

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

	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard"}`, string(out))
	}

	authFlowCodeStart, errE := service.ReverseAPI("AuthFlowCodeStart", waf.Params{"id": authFlowCreateResponse.ID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err = ts.Client().Post(ts.URL+authFlowCodeStart, "application/json", strings.NewReader(`{"emailOrUsername":"test@example.com"}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"code","emailOrUsername":"test@example.com"}`, string(out))

	messages := smtpServer.Messages()

	require.Len(t, messages, 1)

	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body) //nolint:govet
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"code","emailOrUsername":"test@example.com"}`, string(out))
	}

	nonAPIAuthFlowGet, errE := service.Reverse("AuthFlowGet", waf.Params{"id": authFlowCreateResponse.ID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	r, err := regexp.Compile(regexp.QuoteMeta(fmt.Sprintf("%s%s#code=3D", ts.URL, nonAPIAuthFlowGet)) + `(\d+)`)
	require.NoError(t, err)

	match := r.FindStringSubmatch(messages[0].MsgRequest())
	require.NotNil(t, match)

	authFlowCodeComplete, errE := service.ReverseAPI("AuthFlowCodeComplete", waf.Params{"id": authFlowCreateResponse.ID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

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
	require.Equal(t, charon.CompletedSignup, authFlowResponse.Completed)
	assert.Len(t, resp.Cookies(), 1)
	for _, cookie := range resp.Cookies() {
		assert.Equal(t, charon.SessionCookieName, cookie.Name)
	}

	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, `{"target":"session","name":"Charon Dashboard","provider":"code","completed":"`+string(charon.CompletedSignup)+`","location":{"url":"/","replace":true}}`, string(out))
	}
}
