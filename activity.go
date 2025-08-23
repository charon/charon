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

var ErrActivityNotFound = errors.Base("activity not found")

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

// Activity represents a user activity record.
type Activity struct {
	ID        *identifier.Identifier `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      ActivityType           `json:"type"`

	// The identity that performed this activity.
	Actor IdentityRef `json:"actor"`

	// Optional references to documents that were affected by the activity.
	Identity            *IdentityRef            `json:"identity,omitempty"`
	Organization        *OrganizationRef        `json:"organization,omitempty"`
	ApplicationTemplate *ApplicationTemplateRef `json:"applicationTemplate,omitempty"`

	// Optional application ID for sign-in activities.
	AppID *identifier.Identifier `json:"appId,omitempty"`
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

	if a.Timestamp.IsZero() {
		a.Timestamp = time.Now().UTC()
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
		return errE
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
//
// The optional ID parameters will be used to create the appropriate references based on activityType.
func (s *Service) logActivity(
	ctx context.Context, activityType ActivityType, identityID *identifier.Identifier, organizationID *identifier.Identifier,
	applicationTemplateID *identifier.Identifier, appID *identifier.Identifier,
) {
	// Get current identity from context, return silently if not present.
	actorID, hasActor := ctx.Value(identityIDContextKey).(identifier.Identifier)
	if !hasActor {
		return
	}

	activity := &Activity{ //nolint:exhaustruct
		Type:  activityType,
		Actor: IdentityRef{ID: actorID},
		AppID: appID,
	}

	// Set the appropriate document references based on activity type and provided IDs.
	switch activityType {
	case ActivityIdentityCreate, ActivityIdentityUpdate:
		if identityID != nil {
			activity.Identity = &IdentityRef{ID: *identityID}
		}
	case ActivityOrganizationCreate, ActivityOrganizationUpdate:
		if organizationID != nil {
			activity.Organization = &OrganizationRef{ID: *organizationID}
		}
	case ActivityApplicationTemplateCreate, ActivityApplicationTemplateUpdate:
		if applicationTemplateID != nil {
			activity.ApplicationTemplate = &ApplicationTemplateRef{ID: *applicationTemplateID}
		}
	case ActivitySignIn:
		// For sign-in, we can set organization reference if provided.
		if organizationID != nil {
			activity.Organization = &OrganizationRef{ID: *organizationID}
		}
	case ActivitySignOut:
		// Sign-out doesn't need additional references.
	}

	// We don't propagate errors from activity logging as it shouldn't break the main operation.
	_ = s.createActivity(ctx, activity)
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
		return b.Timestamp.Compare(a.Timestamp)
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
