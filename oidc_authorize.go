package charon

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ory/fosite"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

// roleScopePrefix is the namespace used to expose organization roles as OIDC scopes.
// A client that registers role.* (matched by fosite's WildcardScopeStrategy) may request:
//   - role.* to be granted one role.<key> scope for every role the user holds in the organization;
//   - role.<key> to be granted that specific role if (and only if) the user holds it.
const roleScopePrefix = "role."

// roleScopeWildcard is the literal scope value clients use to request all of a user's roles.
const roleScopeWildcard = "role.*"

// grantAllAudiences copies requested audiences to request (and thus to tokens).
// If no audience was requested, all allowed audiences are granted.
func grantAllAudiences(request fosite.Requester) {
	if len(request.GetRequestedAudience()) > 0 {
		// Set all requested audiences (they are already validated that they are a subset of allowed ones for the client).
		for _, audience := range request.GetRequestedAudience() {
			request.GrantAudience(audience)
		}
	} else {
		for _, audience := range request.GetClient().GetAudience() {
			request.GrantAudience(audience)
		}
	}
}

// grantRequestedScopes grants requested scopes to the request (and thus to tokens), with role-prefix handling:
//   - role.* expands to one role.<key> grant per role the user actually holds in the organization;
//   - role.<key> is granted only if the user holds <key> (unheld role scopes are silently dropped, per OAuth conventions);
//   - all other scopes are granted as-is (they have already been validated against the client's allowed scopes by fosite).
//
// Should be called after grantAllAudiences. userRoles is the slice of role keys the subject holds in the organization.
func grantRequestedScopes(request fosite.Requester, userRoles []string) {
	for _, scope := range request.GetRequestedScopes() {
		switch {
		case scope == roleScopeWildcard:
			for _, key := range userRoles {
				request.GrantScope(roleScopePrefix + key)
			}
		case strings.HasPrefix(scope, roleScopePrefix):
			key := strings.TrimPrefix(scope, roleScopePrefix)
			if slices.Contains(userRoles, key) {
				request.GrantScope(scope)
			}
		default:
			request.GrantScope(scope)
		}
	}
}

// TODO: Support "display" parameter.
// TODO: Support "prompt=none" parameter.
// TODO: Support also "none" for response type.
//       See: https://github.com/ory/fosite/issues/409
// TODO: Support also cases where frontend is never involved and redirect happens on the server side.
//       Currently the frontend redirects at the end, but with "prompt=none" or when prompt is not
//       required we could just finish the whole flow server side and never even load frontend.
// TODO: If session is already provided through Cookie, skip to organization step (unless prompt or something else requires us to re-authenticate).

// OIDCAuthorizeGet handler does not really do the whole handling of the authorization request,
// but stores the request into a flow, and then redirects to our authentication page
// (GET request), which is expected to conclude handling the authorization request eventually
// with call to completeOIDCAuthorize.
func (s *Service) OIDCAuthorizeGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	// OIDC GetClient requires ctx with serviceContextKey set.
	ctx := context.WithValue(req.Context(), serviceContextKey, s)
	oidc := s.oidc()

	authorizeRequest, err := oidc.NewAuthorizeRequest(ctx, req)
	if err != nil {
		errE := withFositeError(err)
		s.WithError(ctx, errE)
		oidc.WriteAuthorizeError(ctx, w, authorizeRequest, errE)
		return
	}

	if !strings.Contains(authorizeRequest.GetID(), "-") {
		// Use our identifiers but the default is UUID ID (which contains "-" in its string representation).
		// Here we check that the default ID generation has really been used and panic if not. This way we know
		// that we can safely set it to flow ID and we will not override some other ID which might have been set.
		// TODO: Find a better way to override ID generator in accessRequest.GetID.
		panic(errors.New("default ID generation has not been used"))
	}

	// We link authorization request with the flow by reusing ID.
	id := identifier.New()
	authorizeRequest.SetID(id.String())

	ar, ok := authorizeRequest.(*fosite.AuthorizeRequest)
	if !ok {
		errE := errors.New("invalid AuthorizeRequester type")
		errors.Details(errE)["type"] = fmt.Sprintf("%T", authorizeRequest)
		s.WithError(ctx, errE)
		oidc.WriteAuthorizeError(ctx, w, authorizeRequest, errE)
		return
	}

	client := ar.Client.(*OIDCClient) //nolint:errcheck,forcetypeassert

	organization, errE := s.getOrganization(ctx, client.OrganizationID)
	if errE != nil {
		s.WithError(ctx, errE)
		oidc.WriteAuthorizeError(ctx, w, authorizeRequest, errE)
		return
	}

	errE = s.setFlow(ctx, &flow{
		ID:        id,
		CreatedAt: time.Now().UTC(),
		Completed: []Completed{},
		AuthTime:  nil,

		OrganizationID: client.OrganizationID,
		AppID:          client.AppID,

		SessionID: nil,
		Identity:  nil,

		OIDCAuthorizeRequest: ar,

		AuthAttempts:     0,
		Providers:        nil,
		AllowedProviders: organization.AllowedProviders,
		EmailOrUsername:  "",
		OIDCProvider:     nil,
		SAMLProvider:     nil,
		Passkey:          nil,
		Password:         nil,
		Code:             nil,
	})
	if errE != nil {
		s.WithError(ctx, errE)
		oidc.WriteAuthorizeError(ctx, w, authorizeRequest, errE)
		return
	}

	location, errE := s.Reverse("AuthFlowGet", waf.Params{"id": id.String()}, nil)
	if errE != nil {
		s.WithError(ctx, errE)
		oidc.WriteAuthorizeError(ctx, w, authorizeRequest, errE)
		return
	}
	s.TemporaryRedirectGetMethod(w, req, location)
}

func (s *Service) completeOIDCAuthorize(w http.ResponseWriter, req *http.Request, flow *flow) bool {
	// OIDC GetClient requires ctx with serviceContextKey set.
	ctx := context.WithValue(req.Context(), serviceContextKey, s)
	oidc := s.oidc()

	errE := flow.AddCompleted(CompletedFinished)
	if errE != nil {
		// This should not happen. completeOIDCAuthorize should be called only
		// with CompletedFinishReady as the last completed step.
		s.InternalServerErrorWithError(w, req, errE)
		return true
	}

	authorizeRequest := flow.OIDCAuthorizeRequest
	// Clear authorize request.
	flow.OIDCAuthorizeRequest = nil

	if flow.HasFailed() {
		errE = s.setFlow(ctx, flow)
		if errE != nil {
			// Because this can fail, store's CreateAuthorizeCodeSession, CreateOpenIDConnectSession, and CreatePKCERequestSession should be idempotent.
			s.InternalServerErrorWithError(w, req, errE)
			return true
		}

		oidc.WriteAuthorizeError(ctx, w, authorizeRequest, errors.Wrap(fosite.ErrAccessDenied, "user authentication failed"))
		return true
	}

	// It should not be possible to get to CompletedFinishReady state with flow.Session being nil,
	// unless CompletedFailed, which we checked above.
	session, handled := s.validateSession(w, req, false, flow)
	if session == nil {
		return handled
	}

	errE = s.setFlow(ctx, flow)
	if errE != nil {
		// Because this can fail, store's CreateAuthorizeCodeSession, CreateOpenIDConnectSession, and CreatePKCERequestSession should be idempotent.
		s.InternalServerErrorWithError(w, req, errE)
		return true
	}

	if flow.HasDeclined() {
		oidc.WriteAuthorizeError(ctx, w, authorizeRequest, errors.Wrap(fosite.ErrAccessDenied, "user declined"))
		return true
	}

	grantAllAudiences(authorizeRequest)

	// Look up roles via the client's organization for consistency with the refresh_token path in OIDCTokenPostAPI,
	// which only has access to the client (no flow). client.OrganizationID equals flow.OrganizationID by construction.
	client := authorizeRequest.GetClient().(*OIDCClient) //nolint:errcheck,forcetypeassert
	organization, errE := s.getOrganization(ctx, client.OrganizationID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return true
	}

	subject := *flow.Identity.GetOrganization(&flow.OrganizationID).ID

	// We grant all non-role requested scopes (user picks an identity that satisfies them) and expand/validate
	// role scopes against the user's current roles in the organization.
	grantRequestedScopes(authorizeRequest, organization.Roles[subject])

	oidcSession := &OIDCSession{
		AccountID:              session.AccountID,
		Subject:                subject,
		SessionID:              session.ID,
		ExpiresAt:              nil,
		RequestedAt:            flow.CreatedAt,
		AuthTime:               *flow.AuthTime,
		ClientID:               client.ID,
		JWTClaims:              nil,
		JWTHeaders:             nil,
		IDTokenClaimsInternal:  nil,
		IDTokenHeadersInternal: nil,
	}

	idTokenClaims := oidcSession.IDTokenClaims()

	for _, scope := range authorizeRequest.GetGrantedScopes() {
		switch strings.ToLower(scope) {
		case "profile":
			if flow.Identity.Username != "" {
				idTokenClaims.Add("preferred_username", flow.Identity.Username)
			}
			if flow.Identity.GivenName != "" {
				idTokenClaims.Add("given_name", flow.Identity.GivenName)
			}
			if flow.Identity.FullName != "" {
				idTokenClaims.Add("name", flow.Identity.FullName)
			}
			if flow.Identity.PictureURL != "" {
				idTokenClaims.Add("picture", flow.Identity.PictureURL)
			}
		case "email":
			if flow.Identity.Email != "" {
				// If identity.Email is set, it is a confirmed mapped/canonical e-mail address.
				idTokenClaims.Add("email", flow.Identity.Email)
				idTokenClaims.Add("email_verified", true)
			}
		}
	}

	response, err := oidc.NewAuthorizeResponse(ctx, authorizeRequest, oidcSession)
	if err != nil {
		errE = withFositeError(err)
		s.WithError(ctx, errE)
		oidc.WriteAuthorizeError(ctx, w, authorizeRequest, errE)
		return true
	}

	o := OrganizationRef{ID: flow.OrganizationID}

	c := s.withAccountID(ctx, session.AccountID)
	c = s.withIdentityID(c, *flow.Identity.ID)
	c = s.withSessionID(c, session.ID)
	// TODO: Should this activity be logged with flow.AuthTime for its timestamp?
	errE = s.logActivity(c, ActivitySignIn, nil, []OrganizationRef{o}, nil, []OrganizationApplicationRef{{
		Organization: o,
		Application:  OrganizationApplicationApplicationRef{ID: flow.AppID},
	}}, nil, nil, flow.Providers, o)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return true
	}

	oidc.WriteAuthorizeResponse(ctx, w, authorizeRequest, response)
	return true
}
