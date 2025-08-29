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
	ActivityIdentityBlocked           ActivityType = "identityBlocked"
	ActivityIdentityUnblocked         ActivityType = "identityUnblocked"
	ActivityAccountBlocked            ActivityType = "accountBlocked"
)

// ActivityChangeType represents the type of change performed during an activity.
type ActivityChangeType string

// TODO: Log also activity of changing credentials for an account.

const (
	// ActivityChangeOtherData represents changes to other data.
	ActivityChangeOtherData ActivityChangeType = "otherData"
	// ActivityChangePermissionsAdded represents adding new permissions/access rights.
	ActivityChangePermissionsAdded ActivityChangeType = "permissionsAdded"
	// ActivityChangePermissionsRemoved represents removing permissions/access rights.
	ActivityChangePermissionsRemoved ActivityChangeType = "permissionsRemoved"
	// ActivityChangeMembershipAdded represents joining an organization or adding an application.
	ActivityChangeMembershipAdded ActivityChangeType = "membershipAdded"
	// ActivityChangeMembershipRemoved represents leaving an organization or removing an application.
	ActivityChangeMembershipRemoved ActivityChangeType = "membershipRemoved"
	// ActivityChangeMembershipChanged represents modifying existing membership.
	ActivityChangeMembershipChanged ActivityChangeType = "membershipChanged"
	// ActivityChangeMembershipActivated represents activation/enabling a membership.
	ActivityChangeMembershipActivated ActivityChangeType = "membershipActivated"
	// ActivityChangeMembershipDisabled represents deactivation/disabling a membership.
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
	Actor *IdentityRef `json:"actor,omitempty"`

	// Optional references to documents that were affected by the activity.
	Identities               []IdentityRef                `json:"identities,omitempty"`
	Organizations            []OrganizationRef            `json:"organizations,omitempty"`
	ApplicationTemplates     []ApplicationTemplateRef     `json:"applicationTemplates,omitempty"`
	OrganizationApplications []OrganizationApplicationRef `json:"organizationApplications,omitempty"`
	Accounts                 []AccountRef                 `json:"-"`

	// For sign-in activities, this is the list of providers that were used to authenticate the user.
	Providers []Provider `json:"providers,omitempty"`

	// Details about what was changed during this activity.
	Changes []ActivityChangeType `json:"changes,omitempty"`

	// Session and request IDs from the WAF framework.
	SessionID identifier.Identifier `json:"sessionId"`
	RequestID identifier.Identifier `json:"requestId"`
}

func (a *Activity) IsForOrganization(organization *Organization) bool {
	// Check if activity includes only one organization.
	if len(a.Organizations) != 1 {
		return false
	}

	// Check if activity includes this organization.
	if a.Organizations[0].ID != *organization.ID {
		return false
	}

	return true
}

func (a *Activity) IsForUser(identity IdentityRef, account AccountRef) bool {
	return (a.Actor != nil && *a.Actor == identity) ||
		slices.Contains(a.Identities, identity) ||
		slices.Contains(a.Accounts, account)
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

func (s *Service) getActivityFromID(ctx context.Context, value string) (*Activity, errors.E) {
	id, errE := identifier.MaybeString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrActivityNotFound)
	}

	return s.getActivity(ctx, id)
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

// logActivity creates a new activity record for the current user.
func (s *Service) logActivity(
	ctx context.Context, activityType ActivityType, identities []IdentityRef, organizations []OrganizationRef,
	applicationTemplates []ApplicationTemplateRef, organizationApplications []OrganizationApplicationRef,
	accounts []AccountRef, changes []ActivityChangeType, providers []Provider,
) errors.E {
	currentIdentityID := mustGetIdentityID(ctx)
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
		Timestamp: Time{}, //nolint:exhaustruct

		Type:                     activityType,
		Actor:                    &IdentityRef{ID: currentIdentityID},
		Providers:                providers,
		Changes:                  changes,
		SessionID:                sessionID,
		RequestID:                requestID,
		Identities:               nil,
		Organizations:            nil,
		ApplicationTemplates:     nil,
		OrganizationApplications: nil,
		Accounts:                 nil,
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
	if len(organizationApplications) > 0 {
		activity.OrganizationApplications = organizationApplications
	}
	if len(accounts) > 0 {
		activity.Accounts = accounts
	}

	return s.createActivity(ctx, activity)
}

func (s *Service) ActivityList(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) ActivityListGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	currentAccountID := mustGetAccountID(ctx)
	currentIdentityID := mustGetIdentityID(ctx)

	result := []ActivityRef{}

	s.activitiesMu.RLock()
	defer s.activitiesMu.RUnlock()

	// Collect activities for the current user only (identity or account).
	activities := make([]*Activity, 0)
	for id, data := range s.activities {
		var activity Activity
		errE := x.UnmarshalWithoutUnknownFields(data, &activity)
		if errE != nil {
			errors.Details(errE)["id"] = id
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		if activity.IsForUser(IdentityRef{ID: currentIdentityID}, AccountRef{ID: currentAccountID}) {
			continue
		}

		activities = append(activities, &activity)
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

	activity, errE := s.getActivityFromID(ctx, params["id"])
	if errors.Is(errE, ErrActivityNotFound) {
		s.NotFoundWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	currentAccountID := mustGetAccountID(ctx)
	currentIdentityID := mustGetIdentityID(ctx)

	// Verify this activity is for this user (identity or account).
	if !activity.IsForUser(IdentityRef{ID: currentIdentityID}, AccountRef{ID: currentAccountID}) {
		s.NotFound(w, req)
		return
	}

	if activity.Type == ActivityIdentityBlocked || activity.Type == ActivityIdentityUnblocked || activity.Type == ActivityAccountBlocked {
		// We do not want to expose the actor in these activities.
		activity.Actor = nil
	}

	// We never expose accounts.
	activity.Accounts = nil

	s.WriteJSON(w, req, activity, nil)
}

func (s *Service) OrganizationActivity(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) OrganizationActivityGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	organization, errE := s.getOrganizationFromID(ctx, params["id"])
	if errors.Is(errE, ErrOrganizationNotFound) {
		s.NotFoundWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if !organization.HasAdminAccess(IdentityRef{ID: mustGetIdentityID(ctx)}) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	}

	result := []ActivityRef{}

	s.activitiesMu.RLock()
	defer s.activitiesMu.RUnlock()

	// Collect activities that include this organization exactly (not spanning multiple organizations).
	activities := make([]*Activity, 0)
	for id, data := range s.activities {
		var activity Activity
		errE := x.UnmarshalWithoutUnknownFields(data, &activity)
		if errE != nil {
			errors.Details(errE)["id"] = id
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		if !activity.IsForOrganization(organization) {
			continue
		}

		activities = append(activities, &activity)
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

func (s *Service) OrganizationActivityGetGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	organization, errE := s.getOrganizationFromID(ctx, params["id"])
	if errors.Is(errE, ErrOrganizationNotFound) {
		s.NotFoundWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if !organization.HasAdminAccess(IdentityRef{ID: mustGetIdentityID(ctx)}) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	}

	activity, errE := s.getActivityFromID(ctx, params["activityId"])
	if errors.Is(errE, ErrActivityNotFound) {
		s.NotFoundWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// Verify this activity is for this organization.
	if !activity.IsForOrganization(organization) {
		s.NotFound(w, req)
		return
	}

	// Map actor identity ID to organization-scoped ID.
	actorIdentity, errE := s.getIdentityWithoutAccessCheck(ctx, activity.Actor.ID)
	if errors.Is(errE, ErrActivityNotFound) {
		// It should not really happen that we cannot get the identity because
		// currently we do not support deleting identities.
		// TODO: Once we do support deleting identities AND have identity refs with basic information, we should remove just the ID and keep basic information.
		activity.Actor = nil
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	idOrg := actorIdentity.GetOrganization(organization.ID)
	if idOrg == nil || !idOrg.Active {
		// TODO: Once we have identity refs with basic information, we should remove just the ID and keep basic information.
		activity.Actor = nil
	} else {
		activity.Actor.ID = *idOrg.ID
	}

	// Map identity IDs in the Identities slice to organization-scoped IDs.
	scopedIdentities := []IdentityRef{}
	for _, identityRef := range activity.Identities {
		identity, errE := s.getIdentityWithoutAccessCheck(ctx, identityRef.ID)
		if errors.Is(errE, ErrActivityNotFound) {
			// It should not really happen that we cannot get the identity because
			// currently we do not support deleting identities.
			// TODO: Once we do support deleting identities AND have identity refs with basic information, we should remove just the ID and keep basic information.
			continue
		} else if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		idOrg := identity.GetOrganization(organization.ID)
		if idOrg == nil || !idOrg.Active {
			// TODO: Once we have identity refs with basic information, we should remove just the ID and keep basic information.
			continue
		}

		identityRef.ID = *idOrg.ID
		scopedIdentities = append(scopedIdentities, identityRef)
	}

	if len(scopedIdentities) == 0 {
		scopedIdentities = nil
	}
	activity.Identities = scopedIdentities

	s.WriteJSON(w, req, activity, nil)
}
