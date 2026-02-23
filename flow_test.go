package charon_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

func TestStore(t *testing.T) {
	t.Parallel()

	_, service, _, _, _ := startTestServer(t) //nolint:dogsled

	ctx := context.Background()
	f := &charon.TestingFlow{
		ID: identifier.New(),
	}
	errE := service.TestingSetFlow(ctx, f)
	require.NoError(t, errE, "% -+#.1v", errE)
	f2, errE := service.TestingGetFlow(ctx, f.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, f, f2)
	assert.Nil(t, f2.OIDCAuthorizeRequest)
}

func TestAuthFlowExpiredPasswordAndCode(t *testing.T) {
	t.Parallel()

	user := identifier.New().String()
	email := user + "@example.com"

	ts, service, _, _, _ := startTestServer(t) //nolint:dogsled

	flowID, _, _, _, _, _ := createAuthFlow(t, ts, service) //nolint:dogsled

	// Start password authentication with e-mail address.
	startPasswordSignin(t, ts, service, email, []byte("test1234"), nil, flowID, "Charon", "Dashboard") //nolint:bodyclose

	// Change the flow's CreatedAt to more than 24 hours ago to simulate flow's expiration.
	flow, errE := service.TestingGetFlow(context.Background(), flowID)
	require.NoError(t, errE, "% -+#.1v", errE)
	flow.CreatedAt = flow.CreatedAt.Add(-25 * time.Hour)
	errE = service.TestingSetFlow(context.Background(), flow)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is now expired, so the next step should return 404 Not Found.
	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp)) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
}
