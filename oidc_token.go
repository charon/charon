package charon

import (
	"context"
	"io"
	"net/http"

	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

// OIDCTokenPost handler handles requests to issue access and other tokens.
func (s *Service) OIDCTokenPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	// OIDC GetClient requires ctx with serviceContextKey set.
	ctx := context.WithValue(req.Context(), serviceContextKey, s)
	oidc := s.oidc()

	// Create an empty session object which serves as a prototype of the reconstructed session object.
	// For client credentials grant type there is no reconstruction and then we set subject to client's
	// ID in those tokens, because client credentials based tokens do not have associated
	// user, but represent access for the client itself.
	sessionData := new(OIDCSession)

	accessRequest, err := oidc.NewAccessRequest(ctx, req, sessionData)
	if err != nil {
		errE := withFositeError(err)
		s.WithError(ctx, errE)
		oidc.WriteAccessError(ctx, w, accessRequest, errE)
		return
	}

	// Use our identifiers.
	id := identifier.New()
	accessRequest.SetID(id.String())

	if accessRequest.GetGrantTypes().ExactOne("client_credentials") {
		// This is used by the client credentials grant type. For implicit
		// and explicit flows this is done in the authorization handler.

		grantAllAudiences(accessRequest)
		grantAllScopes(accessRequest)

		session := accessRequest.GetSession().(*OIDCSession) //nolint:errcheck,forcetypeassert
		client := accessRequest.GetClient().(*OIDCClient)    //nolint:errcheck,forcetypeassert
		session.ClientID = identifier.String(client.GetID())
		session.Subject = client.AppID
	}

	response, err := oidc.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		errE := withFositeError(err)
		s.WithError(ctx, errE)
		oidc.WriteAccessError(ctx, w, accessRequest, errE)
		return
	}

	oidc.WriteAccessResponse(ctx, w, accessRequest, response)
}
