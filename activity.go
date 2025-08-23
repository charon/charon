package charon

import (
	"context"
	"net/http"
	"slices"
	"time"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/go/zerolog"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

var (
	ErrActivityNotFound         = errors.Base("activity not found")
	ErrActivityValidationFailed = errors.Base("activity validation failed")
)

// ActivityType represents the type of activity performed.
type ActivityType string

const (
	ActivitySignIn                    ActivityType = "signIn"
	ActivitySignOut                   ActivityType = "signOut"
	ActivityIdentityCreate            ActivityType = "identityCreate"
	ActivityIdentityUpdate            ActivityType = "identityUpdate"
	ActivityOrganizationCreate        ActivityType = "organizationCreate"
	ActivityOrganizationUpdate        ActivityType = "organizationUpdate"
	ActivityApplicationTemplateCreate ActivityType = "applicationTemplateCreate"
	ActivityApplicationTemplateUpdate ActivityType = "applicationTemplateUpdate"
)

// ActivityChangeType represents the type of change performed during an activity.
type ActivityChangeType string

// TODO: Log also activity of changing credentials for an account.

const (
	// PublicData represents changes to public data.
	ActivityChangePublicData ActivityChangeType = "publicData"
	// PermissionsAdded represents adding new permissions/access rights.
	ActivityChangePermissionsAdded ActivityChangeType = "permissionsAdded"
	// PermissionsRemoved represents removing permissions/access rights.
	ActivityChangePermissionsRemoved ActivityChangeType = "permissionsRemoved"
	// PermissionsChanged represents modifying existing permissions/access rights.
	ActivityChangePermissionsChanged ActivityChangeType = "permissionsChanged"
	// MembershipAdded represents joining an organization or adding an application.
	ActivityChangeMembershipAdded ActivityChangeType = "membershipAdded"
	// MembershipRemoved represents leaving an organization or removing an application.
	ActivityChangeMembershipRemoved ActivityChangeType = "membershipRemoved"
	// MembershipChanged represents modifying existing membership.
	ActivityChangeMembershipChanged ActivityChangeType = "membershipChanged"
	// StatusActivated represents activation/enabling a membership.
	ActivityChangeMembershipActivated ActivityChangeType = "membershipActivated"
	// StatusDisabled represents deactivation/disabling a membership.
	ActivityChangeMembershipDisabled ActivityChangeType = "membershipDisabled"
)

type Time time.Time

func (t Time) MarshalJSON() ([]byte, error) {
	// We want only millisecond precision to minimize any side channels.
	return x.MarshalWithoutEscapeHTML(time.Time(t).Format(zerolog.TimeFieldFormat))
}

func (t *Time) UnmarshalJSON(data []byte) error {
	var tt time.Time
	errE := x.UnmarshalWithoutUnknownFields(data, &tt)
	if errE != nil {
		return errE
	}
	*t = Time(tt)
	return nil
}

// Activity represents a user activity record.
type Activity struct {
	ID        *identifier.Identifier `json:"id"`
	Timestamp Time                   `json:"timestamp"`
	Type      ActivityType           `json:"type"`

	// The identity that performed this activity.
	Actor IdentityRef `json:"actor"`

	// Optional references to documents that were affected by the activity.
	Identities           []IdentityRef            `json:"identities,omitempty"`
	Organizations        []OrganizationRef        `json:"organizations,omitempty"`
	ApplicationTemplates []ApplicationTemplateRef `json:"applicationTemplates,omitempty"`

	// Optional application ID for sign-in activities.
	AppID *identifier.Identifier `json:"appId,omitempty"`

	// For sign-in activities, this is the list of providers that were used to authenticate the user.
	Providers []Provider `json:"providers,omitempty"`

	// Details about what was changed during this activity.
	Changes []ActivityChangeType `json:"changes,omitempty"`

	// Session and request IDs from the WAF framework.
	SessionID identifier.Identifier `json:"sessionId"`
	RequestID identifier.Identifier `json:"requestId"`
}

func (a *Activity) Validate(_ context.Context, existing *Activity) errors.E {
	if existing == nil {
		if a.ID != nil {
			errE := errors.New("ID provided for new document")
			errors.Details(errE)["id"] = *a.ID
			return errE
		}
		id := identifier.New()
		a.ID = &id
	} else if a.ID == nil {
		// This should not really happen because we fetch existing based on a.ID.
		return errors.New("ID missing for existing document")
	} else if existing.ID == nil {
		// This should not really happen because we always store documents with ID.
		return errors.New("ID missing for existing document")
	} else if *a.ID != *existing.ID {
		// This should not really happen because we fetch existing based on a.ID.
		errE := errors.New("payload ID does not match existing ID")
		errors.Details(errE)["payload"] = *a.ID
		errors.Details(errE)["existing"] = *existing.ID
		return errE
	}

	if time.Time(a.Timestamp).IsZero() {
		a.Timestamp = Time(time.Now().UTC())

	}

	if a.Type == "" {
		return errors.New("activity type is required")
	}

	return nil
}

type ActivityRef struct {
	ID identifier.Identifier `json:"id"`
}

func (s *Service) getActivity(_ context.Context, id identifier.Identifier) (*Activity, errors.E) {
	s.activitiesMu.RLock()
	defer s.activitiesMu.RUnlock()

	data, ok := s.activities[id]
	if !ok {
		return nil, errors.WithDetails(ErrActivityNotFound, "id", id)
	}
	var activity Activity
	errE := x.UnmarshalWithoutUnknownFields(data, &activity)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, errE
	}
	return &activity, nil
}

func (s *Service) createActivity(ctx context.Context, activity *Activity) errors.E {
	errE := activity.Validate(ctx, nil)
	if errE != nil {
		return errors.WrapWith(errE, ErrActivityValidationFailed)
	}

	data, errE := x.MarshalWithoutEscapeHTML(activity)
	if errE != nil {
		return errE
	}

	s.activitiesMu.Lock()
	defer s.activitiesMu.Unlock()

	s.activities[*activity.ID] = data
	return nil
}

// Helper functions for detecting granular changes.

// detectSliceChanges compares two slices and returns what types of changes occurred.
func detectSliceChanges[T comparable](old, new []T) (added, removed, changed bool) {
	oldSet := make(map[T]bool)
	newSet := make(map[T]bool)

	for _, item := range old {
		oldSet[item] = true
	}
	for _, item := range new {
		newSet[item] = true
	}

	// Check for additions
	for item := range newSet {
		if !oldSet[item] {
			added = true
			break
		}
	}

	// Check for removals
	for item := range oldSet {
		if !newSet[item] {
			removed = true
			break
		}
	}

	// For now, we don't detect "changed" for simple slices as items are either added or removed.
	// "changed" would be more relevant for complex structures where an item's properties change.

	return added, removed, changed
}

// logActivity creates a new activity record for the current user.
func (s *Service) logActivity(
	ctx context.Context, activityType ActivityType, identities []IdentityRef, organizations []OrganizationRef,
	applicationTemplates []ApplicationTemplateRef, appID *identifier.Identifier, changes []ActivityChangeType, providers []Provider,
) errors.E {
	actorID := mustGetIdentityID(ctx)
	sessionID := mustGetSessionID(ctx)

	var requestID identifier.Identifier
	if i, ok := ctx.Value("test-request-id").(identifier.Identifier); ok {
		// During tests we set our own request ID.
		requestID = i
	} else {
		requestID = waf.MustRequestID(ctx)
	}

	activity := &Activity{
		// Validate will populate these.
		ID:        nil,
		Timestamp: Time{},

		Type:                 activityType,
		Actor:                IdentityRef{ID: actorID},
		AppID:                appID,
		Providers:            providers,
		Changes:              changes,
		SessionID:            sessionID,
		RequestID:            requestID,
		Identities:           nil,
		Organizations:        nil,
		ApplicationTemplates: nil,
	}

	if len(identities) > 0 {
		activity.Identities = identities
	}
	if len(organizations) > 0 {
		activity.Organizations = organizations
	}
	if len(applicationTemplates) > 0 {
		activity.ApplicationTemplates = applicationTemplates
	}

	return s.createActivity(ctx, activity)
}

// Activity view handlers.
func (s *Service) ActivityList(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

// API handlers.
func (s *Service) ActivityListGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	currentIdentityID := mustGetIdentityID(ctx)
	result := []ActivityRef{}

	s.activitiesMu.RLock()
	defer s.activitiesMu.RUnlock()

	// Collect activities for the current user only.
	activities := make([]*Activity, 0)
	for id, data := range s.activities {
		var activity Activity
		errE := x.UnmarshalWithoutUnknownFields(data, &activity)
		if errE != nil {
			errors.Details(errE)["id"] = id
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		// Only include activities for the current user.
		if activity.Actor.ID == currentIdentityID {
			activities = append(activities, &activity)
		}
	}

	// Sort activities by timestamp (newest first).
	slices.SortFunc(activities, func(a, b *Activity) int {
		return time.Time(b.Timestamp).Compare(time.Time(a.Timestamp))
	})

	// Convert to refs.
	for _, activity := range activities {
		result = append(result, ActivityRef{ID: *activity.ID})
	}

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) ActivityGetGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	activityID, errE := identifier.MaybeString(params["id"])
	if errE != nil {
		s.NotFoundWithError(w, req, errE)
		return
	}

	activity, errE := s.getActivity(ctx, activityID)
	if errors.Is(errE, ErrActivityNotFound) {
		s.NotFound(w, req)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	currentIdentityID := mustGetIdentityID(ctx)

	// Only allow users to see their own activities.
	if activity.Actor.ID != currentIdentityID {
		s.NotFound(w, req)
		return
	}

	s.WriteJSON(w, req, activity, nil)
}
