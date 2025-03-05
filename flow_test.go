package charon_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/identifier"

	"gitlab.com/charon/charon"
)

func TestStore(t *testing.T) {
	t.Parallel()

	_, service, _, _ := startTestServer(t)

	ctx := context.Background()
	f := &charon.Flow{
		ID: identifier.New(),
	}
	errE := service.SetFlow(ctx, f)
	require.NoError(t, errE, "% -+#.1v", errE)
	f2, errE := service.GetFlow(ctx, f.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, f, f2)
	assert.Nil(t, f2.OIDCAuthorizeRequest)
}
