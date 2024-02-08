package charon

import (
	"fmt"
	"net/http"

	"github.com/ory/fosite"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

// grantAllAudiences copies requested audiences to request (and thus to tokens).
func grantAllAudiences(request fosite.Requester) {
	// Set all requested audiences (they are already validated that they are a subset of allowed ones for the client).
	for _, audience := range request.GetRequestedAudience() {
		request.GrantAudience(audience)
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
// (GET request), which is expected to conclude handling the authorization request eventually.
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

	grantAllAudiences(authorizeRequest)

	ar, ok := authorizeRequest.(*fosite.AuthorizeRequest)
	if !ok {
		errE := errors.New("invalid AuthorizeRequester type")
		errors.Details(errE)["type"] = fmt.Sprintf("%T", authorizeRequest)
		s.WithError(ctx, errE)
		oidc.WriteAuthorizeError(ctx, w, authorizeRequest, errE)
		return
	}

	client := ar.Client.(*OIDCClient) //nolint:errcheck,forcetypeassert

	id := identifier.New()
	errE := SetFlow(req.Context(), &Flow{
		ID:                   id,
		Session:              nil,
		Completed:            "",
		Target:               TargetOIDC,
		TargetLocation:       "",
		TargetName:           client.TargetName,
		TargetOrganization:   &client.TargetOrganization,
		Provider:             "",
		EmailOrUsername:      "",
		Attempts:             0,
		OIDCAuthorizeRequest: ar,
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

	location, errE := s.Reverse("AuthFlow", waf.Params{"id": id.String()}, nil)
	if errE != nil {
		s.WithError(ctx, errE)
		oidc.WriteAuthorizeError(ctx, w, authorizeRequest, errE)
		return
	}
	s.TemporaryRedirectGetMethod(w, req, location)
}
