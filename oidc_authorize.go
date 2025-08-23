package charon

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

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

// grantAllScopes copies requested scopes to request (and thus to tokens).
// This function should be called after grantAllAudiences has been called.
func grantAllScopes(request fosite.Requester) {
	// Grant all requested scopes (they are already validated that they are a subset of allowed ones for the client).
	for _, scope := range request.GetRequestedScopes() {
		request.GrantScope(scope)
	}
}

// TODO: Support "display" parameter.
// TODO: Support "prompt=none" parameter.
// TODO: Support also "none" for response type.
//       See: https://github.com/ory/fosite/issues/409
// TODO: Support also cases where frontend is never involved and redirect happens on the server side.
//       Currently the frontend redirects at the end, but with "prompt=none" or when prompt is not
//       required we could just finish the whole flow serer side and never even load frontend.
// TODO: If session is already provided through Cookie, skip to organization step (unless prompt or something else requires us to re-authenticate).

// OIDCAuthorize handler does not really do the whole handling of the authorization request,
// but stores the request into a flow, and then redirects to our authentication page
// (GET request), which is expected to conclude handling the authorization request eventually
// with call to completeOIDCAuthorize.
func (s *Service) OIDCAuthorize(w http.ResponseWriter, req *http.Request, _ waf.Params) {
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

	errE := s.setFlow(req.Context(), &Flow{
		ID:        id,
		CreatedAt: time.Now().UTC(),
		Completed: []Completed{},
		AuthTime:  nil,

		OrganizationID: client.OrganizationID,
		AppID:          client.AppID,

		SessionID: nil,
		Identity:  nil,

		OIDCAuthorizeRequest: ar,

		AuthAttempts:    0,
		Providers:       nil,
		EmailOrUsername: "",
		OIDCProvider:    nil,
		Passkey:         nil,
		Password:        nil,
		Code:            nil,
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

func (s *Service) completeOIDCAuthorize(w http.ResponseWriter, req *http.Request, flow *Flow) bool {
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

	// We always grant all requested scopes because user can choose an identity with values they want
	// for all requested scopes. This works because currently we support only ID token scopes and
	// additional scopes for the app itself. If we add scopes for calling into Charon API, we will
	// have to provide a way for the user to approve those and change call here.
	grantAllScopes(authorizeRequest)

	oidcSession := &OIDCSession{ //nolint:forcetypeassert
		AccountID:              session.AccountID,
		Subject:                *flow.Identity.GetOrganization(&flow.OrganizationID).ID,
		SessionID:              session.ID,
		ExpiresAt:              nil,
		RequestedAt:            flow.CreatedAt,
		AuthTime:               *flow.AuthTime,
		ClientID:               authorizeRequest.GetClient().(*OIDCClient).ID, //nolint:errcheck
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
				idTokenClaims.Add("email", flow.Identity.Email)
				// TODO: We are not yet making sure only validated addressed can be set in an identity.
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

	c := s.withIdentityID(ctx, *flow.Identity.ID)
	c = s.withSessionID(c, session.ID)
	// TODO: Should this activity be logged with flow.AuthTime for its timestamp?
	errE = s.logActivity(c, ActivitySignIn, nil, []OrganizationRef{{ID: flow.OrganizationID}}, nil, &flow.AppID, nil, flow.Providers)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return true
	}

	oidc.WriteAuthorizeResponse(ctx, w, authorizeRequest, response)
	return true
}
