package charon

import (
	"context"
	"net/http"
	"slices"
	"time"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

var (
	ErrActivityNotFound         = errors.Base("activity not found")
	ErrActivityValidationFailed = errors.Base("activity validation failed")
)

// ActivityType represents the type of activity performed.
type ActivityType string

// ActivityType values.
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
	// ActivityChangeRolesAdded represents adding new roles.
	ActivityChangeRolesAdded ActivityChangeType = "rolesAdded"
	// ActivityChangeRolesRemoved represents removing roles.
	ActivityChangeRolesRemoved ActivityChangeType = "rolesRemoved"
)

// ActivityPublic represents public fields of the activity. Handlers expose activities
// over the API only through ActivityPublic.
type ActivityPublic struct {
	ID *identifier.Identifier `json:"id"`
	// Base is the slice of strings from which the document ID is derived.
	Base []string `json:"base"`

	Timestamp x.Time       `json:"timestamp"`
	Type      ActivityType `json:"type"`

	// The identity that performed this activity.
	Actor *OrganizationIdentityRef `json:"actor,omitempty"`

	// Optional references to documents that were affected by the activity.
	Identities               []OrganizationIdentityRef    `json:"identities,omitempty"`
	Organizations            []OrganizationRef            `json:"organizations,omitempty"`
	ApplicationTemplates     []ApplicationTemplateRef     `json:"applicationTemplates,omitempty"`
	OrganizationApplications []OrganizationApplicationRef `json:"organizationApplications,omitempty"`
	Roles                    []string                     `json:"roles,omitempty"`

	// For sign-in activities, this is the list of providers that were used to authenticate the user.
	Providers []Provider `json:"providers,omitempty"`

	// Details about what was changed during this activity.
	Changes []ActivityChangeType `json:"changes,omitempty"`

	// Session and request IDs from the waf framework.
	SessionID identifier.Identifier `json:"sessionId"`
	RequestID identifier.Identifier `json:"requestId"`
}

// Activity represents a user activity record.
type Activity struct {
	ActivityPublic

	// Accounts is persisted so that stored activities can be matched to the account, but it is private:
	// it is not in ActivityPublic so it is never exposed over the API because that would allow linking
	// identities to accounts.
	Accounts []AccountRef `json:"accounts,omitempty"`
}

// IsForOrganization returns true if activity is for the given organization.
func (a *Activity) IsForOrganization(organization OrganizationRef) bool {
	return slices.Contains(a.Organizations, organization)
}

// IsForUser returns true if activity is for the given identity or account.
//
// Identity ID is not organization-scoped.
func (a *Activity) IsForUser(ctx context.Context, service *Service, identity, account identifier.Identifier) (bool, errors.E) {
	// This is the first because it is the fastest to check.
	if slices.Contains(a.Accounts, AccountRef{ID: account}) {
		return true, nil
	}

	// Actor is always set. It is potentially nil only when Activity is send over the API.
	actor, _, errE := service.getIdentityFromOrganization(ctx, a.Actor.Organization.ID, a.Actor.Identity.ID)
	if errors.Is(errE, ErrIdentityNotFound) { //nolint:revive
		// TODO: This should not really happen because we do not support deleting identities.
		// We do nothing.
	} else if errE != nil {
		return false, errE
	} else if *actor.ID == identity {
		return true, nil
	}

	identities, errE := service.limitIdentitiesForUser(ctx, a.Identities, identity)
	if errE != nil {
		return false, errE
	}

	if len(identities) > 0 {
		return true, nil
	}

	return false, nil
}

// Validate validates the Activity struct.
func (a *Activity) Validate(_ context.Context, existing *Activity, service *Service) errors.E {
	var existingID *identifier.Identifier
	var existingBase []string
	if existing != nil {
		existingID = existing.ID
		existingBase = existing.Base
	}
	errE := validateIDBase(service.newBase("ACTIVITY"), &a.ID, &a.Base, existing != nil, existingID, existingBase)
	if errE != nil {
		return errE
	}

	if time.Time(a.Timestamp).IsZero() {
		a.Timestamp = x.Time(time.Now().UTC())
	}

	if a.Type == "" {
		return errors.New("activity type is required")
	}

	return nil
}

// Ref returns the activity reference.
func (a *ActivityPublic) Ref() ActivityRef {
	return ActivityRef{ID: *a.ID}
}

// ActivityRef is a reference to an activity.
type ActivityRef struct {
	ID identifier.Identifier `json:"id"`
}

func (s *Service) getActivity(_ context.Context, id identifier.Identifier) (*Activity, errors.E) {
	s.activities.RLock()
	defer s.activities.RUnlock()

	data, ok := s.activities.Get(id)
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
	// TODO: Establish a total order of activities instead of ordering them by their timestamp alone.
	//       Timestamps are stored with millisecond resolution and activities are collected by iterating
	//       a map, so activities recorded inside the same millisecond end up in an arbitrary order in
	//       the activity log. Tests set activityTimestampStep to a millisecond to work around that and
	//       observe activities in the order in which they happened, moving every next timestamp further
	//       into the future instead of really waiting between activities. A sequence number (or a finer
	//       timestamp) used as a secondary sort key would order them deterministically for everybody,
	//       and this could then be removed.
	if s.activityTimestampStep > 0 {
		steps := s.activityTimestampSteps.Add(1)
		activity.Timestamp = x.Time(time.Now().UTC().Add(time.Duration(steps * int64(s.activityTimestampStep))))
	}

	errE := activity.Validate(ctx, nil, s)
	if errE != nil {
		return errors.WrapWith(errE, ErrActivityValidationFailed)
	}

	data, errE := x.MarshalWithoutEscapeHTML(activity)
	if errE != nil {
		return errE
	}

	s.activities.Lock()
	defer s.activities.Unlock()

	return s.activities.Set(*activity.ID, data)
}

// logActivity creates a new activity record for the current user.
func (s *Service) logActivity(
	ctx context.Context, activityType ActivityType, identities []OrganizationIdentityRef, organizations []OrganizationRef,
	applicationTemplates []ApplicationTemplateRef, organizationApplications []OrganizationApplicationRef,
	accounts []AccountRef, changes []ActivityChangeType, providers []Provider, currentOrganization OrganizationRef,
) errors.E {
	co := s.charonOrganization()

	currentIdentityID := mustGetIdentityID(ctx)
	sessionID := mustGetSessionID(ctx)

	var requestID identifier.Identifier
	if i, ok := ctx.Value("test-request-id").(identifier.Identifier); ok {
		// During tests we set our own request ID.
		requestID = i
	} else {
		requestID = waf.MustRequestID(ctx)
	}

	currentIdentity, errE := s.getIdentityWithoutAccessCheck(ctx, currentIdentityID)
	if errE != nil {
		return errE
	}
	actor := currentIdentity.OrganizationIdentityRef(currentOrganization)
	if actor == nil {
		if activityType == ActivityIdentityCreate && len(accounts) > 0 && co.ID == currentOrganization.ID {
			// The identity has been created during the sign-up flow. We record the identity itself as the actor.
			actor = &OrganizationIdentityRef{
				Organization: currentOrganization,
				Identity:     IdentityRef{ID: currentIdentityID},
			}
		} else {
			// User has made an activity without being added to the organization. This can
			// happen if user is an admin of the organization but has not yet signed in
			// into the organization. In this case we add the user now (as active).
			currentIdentity.Organizations = append(currentIdentity.Organizations, IdentityOrganization{
				ID:           nil,
				Base:         nil,
				Active:       true,
				Organization: currentOrganization,
				Applications: []OrganizationApplicationApplicationRef{},
			})

			errE := s.updateIdentity(ctx, currentIdentity)
			if errE != nil {
				return errE
			}

			// Now we should be able to find the organization identity.
			actor = currentIdentity.OrganizationIdentityRef(currentOrganization)
			if actor == nil {
				// This should not happen.
				return errors.New("unable to find organization identity")
			}
		}
	}

	activity := &Activity{
		ActivityPublic: ActivityPublic{
			// Validate will populate these.
			ID:        nil,
			Base:      nil,
			Timestamp: x.Time{},

			Type:                     activityType,
			Actor:                    actor,
			Providers:                providers,
			Changes:                  changes,
			SessionID:                sessionID,
			RequestID:                requestID,
			Identities:               nil,
			Organizations:            nil,
			ApplicationTemplates:     nil,
			OrganizationApplications: nil,
			Roles:                    nil,
		},
		Accounts: nil,
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

// ActivityListGet is the frontend handler for listing activities.
func (s *Service) ActivityListGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

// ActivityListGetAPI is the API handler for listing activities, GET request.
func (s *Service) ActivityListGetAPI(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	currentAccountID := mustGetAccountID(ctx)
	currentIdentityID := mustGetIdentityID(ctx)

	result := []ActivityRef{}

	s.activities.RLock()
	defer s.activities.RUnlock()

	// Collect activities for the current user only (identity or account).
	activities := []*Activity{}
	for id, data := range s.activities.All() {
		var activity Activity
		errE := x.UnmarshalWithoutUnknownFields(data, &activity)
		if errE != nil {
			errors.Details(errE)["id"] = id
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		ok, errE := activity.IsForUser(ctx, s, currentIdentityID, currentAccountID)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		if !ok {
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
		result = append(result, activity.Ref())
	}

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) limitIdentitiesForUser(
	ctx context.Context, identities []OrganizationIdentityRef, limitToID identifier.Identifier,
) ([]OrganizationIdentityRef, errors.E) {
	limitedIdentities := []OrganizationIdentityRef{}

	for _, identityOrganization := range identities {
		identity, _, errE := s.getIdentityFromOrganization(ctx, identityOrganization.Organization.ID, identityOrganization.Identity.ID)
		if errors.Is(errE, ErrIdentityNotFound) {
			// TODO: This should not really happen because we do not support deleting identities.
			continue
		} else if errE != nil {
			return nil, errE
		}
		if *identity.ID == limitToID {
			limitedIdentities = append(limitedIdentities, identityOrganization)
		}
	}

	return limitedIdentities, nil
}

// ActivityGetGetAPI is the API handler for getting the activity, GET request.
func (s *Service) ActivityGetGetAPI(w http.ResponseWriter, req *http.Request, params waf.Params) {
	co := s.charonOrganization()

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
	ok, errE := activity.IsForUser(ctx, s, currentIdentityID, currentAccountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	if !ok {
		s.NotFound(w, req)
		return
	}

	actorIsThisUser := false
	actor, _, errE := s.getIdentityFromOrganization(ctx, activity.Actor.Organization.ID, activity.Actor.Identity.ID)
	if errors.Is(errE, ErrIdentityNotFound) {
		// TODO: This should not really happen because we do not support deleting identities.
		activity.Actor = nil
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	} else if *actor.ID == currentIdentityID {
		actorIsThisUser = true
	} else if activity.Type == ActivityIdentityBlocked || activity.Type == ActivityIdentityUnblocked || activity.Type == ActivityAccountBlocked {
		// We do not want to expose the actor in these activities.
		activity.Actor = nil
	} else if activity.Actor.Organization.ID != co.ID {
		// We expose actor only for Charon organization.
		activity.Actor = nil
	}

	// We limit identities based on how is this activity for the user.
	if slices.Contains(activity.Accounts, AccountRef{ID: currentAccountID}) || actorIsThisUser { //nolint:revive
		// We do not limit identities because activity is for the user.
	} else {
		// We limit only to the current identity.
		// TODO: We should limit only to those the current identity has access to.
		identities, errE := s.limitIdentitiesForUser(ctx, activity.Identities, currentIdentityID)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		if len(identities) == 0 {
			identities = nil
		}
		activity.Identities = identities
	}

	// We write out only the public part of the activity so that accounts are never exposed.
	s.WriteJSON(w, req, activity.ActivityPublic, nil)
}

// OrganizationActivityGet is the frontend handler for listing organization's activities.
func (s *Service) OrganizationActivityGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

// OrganizationActivityGetAPI is the API handler for listing organization's activities, GET request.
func (s *Service) OrganizationActivityGetAPI(w http.ResponseWriter, req *http.Request, params waf.Params) {
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

	o := organization.Ref()

	result := []ActivityRef{}

	s.activities.RLock()
	defer s.activities.RUnlock()

	// Collect activities that include this organization.
	activities := []*Activity{}
	for id, data := range s.activities.All() {
		var activity Activity
		errE := x.UnmarshalWithoutUnknownFields(data, &activity)
		if errE != nil {
			errors.Details(errE)["id"] = id
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		if !activity.IsForOrganization(o) {
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
		result = append(result, activity.Ref())
	}

	s.WriteJSON(w, req, result, nil)
}

// OrganizationActivityGetGetAPI is the API handler for getting the organization's activity, GET request.
func (s *Service) OrganizationActivityGetGetAPI(w http.ResponseWriter, req *http.Request, params waf.Params) {
	co := s.charonOrganization()

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
	if !activity.IsForOrganization(organization.Ref()) {
		s.NotFound(w, req)
		return
	}

	if activity.Actor.Organization.ID != co.ID && activity.Actor.Organization.ID != *organization.ID {
		// We expose actor only for Charon organization or this organization.
		activity.Actor = nil
	}

	// Limit identities to those for requested organization.
	identities := []OrganizationIdentityRef{}
	for _, organizationIdentityRef := range activity.Identities {
		if organizationIdentityRef.Organization.ID == *organization.ID {
			identities = append(identities, organizationIdentityRef)
		}
	}
	if len(identities) == 0 {
		identities = nil
	}
	activity.Identities = identities

	// Limit organizations only to the requested organization.
	organizations := []OrganizationRef{}
	for _, organizationRef := range activity.Organizations {
		if organizationRef.ID == *organization.ID {
			organizations = append(organizations, organizationRef)
		}
	}
	if len(organizations) == 0 {
		organizations = nil
	}
	activity.Organizations = organizations

	// We write out only the public part of the activity so that accounts are never exposed.
	s.WriteJSON(w, req, activity.ActivityPublic, nil)
}
