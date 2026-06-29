package charon_test

import (
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

	ctx := t.Context()
	f := &charon.TestingFlow{
		ID:                   identifier.New(),
		CreatedAt:            time.Now().UTC(),
		Completed:            nil,
		AuthTime:             nil,
		OrganizationID:       identifier.Identifier{},
		AppID:                identifier.Identifier{},
		SessionID:            nil,
		Identity:             nil,
		OIDCAuthorizeRequest: nil,
		UILocale:             "",
		AuthAttempts:         0,
		Providers:            nil,
		AllowedProviders:     nil,
		EmailOrUsername:      "",
		OIDCProvider:         nil,
		SAMLProvider:         nil,
		Passkey:              nil,
		Password:             nil,
		Code:                 nil,
	}
	errE := service.TestingSetFlow(ctx, f)
	require.NoError(t, errE, "% -+#.1v", errE)
	f2, errE := service.TestingGetFlow(ctx, f.ID)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, f, f2)
	assert.Nil(t, f2.OIDCAuthorizeRequest)
}

func TestFlowIsProviderAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		allowed  []charon.Provider
		query    charon.Provider
		expected bool
	}{
		{"empty AllowedProviders means all are allowed", nil, charon.ProviderPasskey, true},
		{"empty slice (zero-length) is also permissive", []charon.Provider{}, "oidcTesting", true},
		{"non-empty list contains provider", []charon.Provider{charon.ProviderUsername, charon.ProviderEmail, charon.ProviderPassword, charon.ProviderPasskey}, charon.ProviderPasskey, true},
		{"non-empty list does not contain provider", []charon.Provider{charon.ProviderUsername, charon.ProviderEmail, charon.ProviderPassword}, charon.ProviderPasskey, false},
		{"non-empty list does not contain third-party", []charon.Provider{charon.ProviderUsername, charon.ProviderEmail, charon.ProviderPassword}, "oidcTesting", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := &charon.TestingFlow{
				ID:                   identifier.New(),
				CreatedAt:            time.Now().UTC(),
				Completed:            nil,
				AuthTime:             nil,
				OrganizationID:       identifier.Identifier{},
				AppID:                identifier.Identifier{},
				SessionID:            nil,
				Identity:             nil,
				OIDCAuthorizeRequest: nil,
				UILocale:             "",
				AuthAttempts:         0,
				Providers:            nil,
				AllowedProviders:     tt.allowed,
				EmailOrUsername:      "",
				OIDCProvider:         nil,
				SAMLProvider:         nil,
				Passkey:              nil,
				Password:             nil,
				Code:                 nil,
			}
			assert.Equal(t, tt.expected, charon.TestingFlowIsProviderAllowed(f, tt.query))
		})
	}
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
	flow, errE := service.TestingGetFlow(t.Context(), flowID)
	require.NoError(t, errE, "% -+#.1v", errE)
	flow.CreatedAt = flow.CreatedAt.Add(-25 * time.Hour)
	errE = service.TestingSetFlow(t.Context(), flow)
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
