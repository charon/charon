package charon_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

func signoutUser(t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string) {
	t.Helper()

	authSignout, errE := service.ReverseAPI("AuthSignout", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+authSignout, strings.NewReader(`{"location":"/"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authSignoutResponse charon.AuthSignoutResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authSignoutResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, "/", authSignoutResponse.Location)
}

// verifyLatestActivity verifies that the most recent activity for a user matches expected criteria.
// This function only checks the latest activity, not the total count of activities.
func verifyLatestActivity(
	t *testing.T, ts *httptest.Server, service *charon.Service, accessToken string,
	expectedType charon.ActivityType, expectedChanges []charon.ActivityChangeType,
	expectedIdentitiesCount, expectedOrgsCount, expectedAppTemplatesCount, expectedOrgAppsCount int,
) {
	t.Helper()

	activityListGet, errE := service.ReverseAPI("ActivityList", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+activityListGet, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var activityRefs []charon.ActivityRef
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &activityRefs)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.NotEmpty(t, activityRefs, "Expected at least one activity")

	// Get the most recent activity (first in the list as they're sorted by timestamp desc).
	latestActivityID := activityRefs[0].ID

	activityGet, errE := service.ReverseAPI("ActivityGet", waf.Params{"id": latestActivityID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+activityGet, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = ts.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var activity charon.Activity
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &activity)
	require.NoError(t, errE, "% -+#.1v", errE)

	assert.Equal(t, expectedType, activity.Type, "Latest activity type mismatch")
	assert.Equal(t, expectedChanges, activity.Changes, "Latest activity changes mismatch")
	assert.Len(t, activity.Identities, expectedIdentitiesCount, "Latest activity identities count mismatch")
	assert.Len(t, activity.Organizations, expectedOrgsCount, "Latest activity organizations count mismatch")
	assert.Len(t, activity.ApplicationTemplates, expectedAppTemplatesCount, "Latest activity application templates count mismatch")
	assert.Len(t, activity.OrganizationApplications, expectedOrgAppsCount, "Latest activity organization applications count mismatch")
}
