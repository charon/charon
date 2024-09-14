package charon

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
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
	ctx := req.Context()
	oidc := s.oidc()

	authorizeRequest, err := oidc.NewAuthorizeRequest(ctx, req)
	if err != nil {
		errE := errors.WithStack(err)
		s.WithError(ctx, errE)
		oidc.WriteAuthorizeError(ctx, w, authorizeRequest, errE)
		return
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

	errE := SetFlow(req.Context(), &Flow{
		ID:                   id,
		CreatedAt:            time.Now().UTC(),
		Session:              nil,
		Completed:            "",
		AuthTime:             nil,
		Target:               TargetOIDC,
		TargetLocation:       client.AppHomepage,
		TargetName:           client.TargetName,
		TargetOrganizationID: &client.TargetOrganization,
		Provider:             "",
		EmailOrUsername:      "",
		Attempts:             0,
		OIDCAuthorizeRequest: ar,
		OIDCIdentity:         nil,
		OIDCRedirectReady:    false,
		OIDCProvider:         nil,
		Passkey:              nil,
		Password:             nil,
		Code:                 nil,
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
	ctx := req.Context()
	oidc := s.oidc()

	authorizeRequest := flow.OIDCAuthorizeRequest
	completed := flow.Completed

	if completed == CompletedFailed {
		flow.Completed = CompletedRedirect
		flow.OIDCRedirectReady = false

		// Clear authorize request.
		flow.OIDCAuthorizeRequest = nil

		errE := SetFlow(ctx, flow)
		if errE != nil {
			// Because this can fail, store's CreateAuthorizeCodeSession, CreateOpenIDConnectSession, and CreatePKCERequestSession should be idempotent.
			s.InternalServerErrorWithError(w, req, errE)
			return true
		}

		oidc.WriteAuthorizeError(ctx, w, authorizeRequest, errors.Wrap(fosite.ErrAccessDenied, "user authentication failed"))
		return true
	}

	// It should not be possible to get to OIDCRedirectReady state with flow.Session being nil,
	// unless flow.Completed == CompletedFailed, which we checked above.
	accountID, handled := s.validateSession(w, req, false, flow)
	if accountID == nil {
		return handled
	}

	flow.Completed = CompletedRedirect
	flow.OIDCRedirectReady = false

	// Clear authorize request.
	flow.OIDCAuthorizeRequest = nil

	errE := SetFlow(ctx, flow)
	if errE != nil {
		// Because this can fail, store's CreateAuthorizeCodeSession, CreateOpenIDConnectSession, and CreatePKCERequestSession should be idempotent.
		s.InternalServerErrorWithError(w, req, errE)
		return true
	}

	if completed == CompletedDeclined {
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
		Subject:                *flow.OIDCIdentity.ID,
		Session:                *accountID,
		ExpiresAt:              nil,
		RequestedAt:            flow.CreatedAt,
		AuthTime:               *flow.AuthTime,
		Client:                 authorizeRequest.GetClient().(*OIDCClient).ID,
		JWTClaims:              nil,
		JWTHeaders:             nil,
		IDTokenClaimsInternal:  new(jwt.IDTokenClaims),
		IDTokenHeadersInternal: nil,
	}

	for _, scope := range authorizeRequest.GetGrantedScopes() {
		switch strings.ToLower(scope) {
		case "profile":
			if flow.OIDCIdentity.Username != "" {
				oidcSession.IDTokenClaimsInternal.Add("preferred_username", flow.OIDCIdentity.Username)
			}
			if flow.OIDCIdentity.GivenName != "" {
				oidcSession.IDTokenClaimsInternal.Add("given_name", flow.OIDCIdentity.GivenName)
			}
			if flow.OIDCIdentity.FullName != "" {
				oidcSession.IDTokenClaimsInternal.Add("name", flow.OIDCIdentity.FullName)
			}
			if flow.OIDCIdentity.PictureURL != "" {
				oidcSession.IDTokenClaimsInternal.Add("picture", flow.OIDCIdentity.PictureURL)
			}
		case "email":
			if flow.OIDCIdentity.Email != "" {
				oidcSession.IDTokenClaimsInternal.Add("email", flow.OIDCIdentity.Username)
				// TODO: We are not yet making sure only validated addressed can be set in an identity.
				oidcSession.IDTokenClaimsInternal.Add("email", true)
			}
		}
	}

	response, err := oidc.NewAuthorizeResponse(ctx, authorizeRequest, oidcSession)
	if err != nil {
		errE = errors.WithStack(err)
		s.WithError(ctx, errE)
		oidc.WriteAuthorizeError(ctx, w, authorizeRequest, errE)
		return true
	}

	oidc.WriteAuthorizeResponse(ctx, w, authorizeRequest, response)
	return true
}
