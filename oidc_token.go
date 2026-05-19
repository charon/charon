package charon

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/ory/fosite"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

// OIDCTokenPostAPI handler handles requests to issue access and other tokens.
func (s *Service) OIDCTokenPostAPI(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	// OIDC GetClient requires ctx with serviceContextKey set.
	ctx := context.WithValue(req.Context(), serviceContextKey, s)
	oidc := s.oidc()

	// Create an empty session object which serves as a prototype of the reconstructed session object.
	// For client credentials grant type there is no reconstruction, and then we set subject to client's
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

	if strings.Contains(accessRequest.GetID(), "-") {
		// Use our identifiers if ID is the default is UUID ID (which contains "-" in its string representation).
		// We do not set ID unconditionally because it might be populated from a previous request with our ID.
		// TODO: Find a better way to override ID generator in accessRequest.GetID.
		id := identifier.New()
		accessRequest.SetID(id.String())
	}

	if accessRequest.GetGrantTypes().ExactOne("client_credentials") {
		// This is used by the client credentials grant type. For implicit
		// and explicit flows this is done in the authorization handler.

		grantAllAudiences(accessRequest)
		// client_credentials tokens never carry roles (Subject is an AppID), so passing nil userRoles is fine,
		// any role.* / role.<key> in the request would simply not match anything and be dropped.
		grantRequestedScopes(accessRequest, nil)

		session := accessRequest.GetSession().(*OIDCSession) //nolint:errcheck,forcetypeassert
		client := accessRequest.GetClient().(*OIDCClient)    //nolint:errcheck,forcetypeassert
		session.ClientID = identifier.String(client.GetID())
		session.Subject = client.AppID
	}

	if accessRequest.GetGrantTypes().ExactOne("refresh_token") {
		// Re-evaluate role.<key> grants against the current organization state so refreshed tokens reflect
		// roles the user has gained or lost since the original authorize step.
		session := accessRequest.GetSession().(*OIDCSession) //nolint:errcheck,forcetypeassert
		client := accessRequest.GetClient().(*OIDCClient)    //nolint:errcheck,forcetypeassert
		organization, errE := s.getOrganization(ctx, client.OrganizationID)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		// Strip role.<key> scopes inherited from the original grant; grantRequestedScopes re-applies them
		// based on the current (requested-scopes ∩ user-currently-held-roles) set. Non-role scopes are
		// preserved because grantRequestedScopes is idempotent via fosite's GrantScope dedup.
		ar := accessRequest.(*fosite.AccessRequest) //nolint:errcheck,forcetypeassert
		filtered := ar.GrantedScope[:0]
		for _, scope := range ar.GrantedScope {
			if !strings.HasPrefix(scope, roleScopePrefix) {
				filtered = append(filtered, scope)
			}
		}
		ar.GrantedScope = filtered

		grantRequestedScopes(accessRequest, organization.Roles[session.Subject])
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
