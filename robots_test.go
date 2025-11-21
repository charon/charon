package charon_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/temoto/robotstxt"
)

func TestRobotsTxt(t *testing.T) {
	t.Parallel()

	ts, _, _, _, _ := startTestServer(t) //nolint:dogsled

	expected, err := testFiles.ReadFile("dist/robots.txt")
	require.NoError(t, err)

	resp, err := ts.Client().Get(ts.URL + "/robots.txt") //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
		assert.Equal(t, string(expected), string(out))
	}

	robots, err := robotstxt.FromBytes(expected)
	require.NoError(t, err)

	assert.True(t, robots.TestAgent("/", "FooBot"))
	assert.False(t, robots.TestAgent("/auth/123", "FooBot"))
	assert.True(t, robots.TestAgent("/api", "FooBot"))
	assert.True(t, robots.TestAgent("/api/auth/123", "FooBot"))
}
