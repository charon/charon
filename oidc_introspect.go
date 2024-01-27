package charon

import (
	"net/http"

	"github.com/ory/fosite"
	"gitlab.com/tozd/waf"
)

// TODO: Support introspecting ID tokens.
//       See: https://github.com/ory/fosite/issues/410

// OIDCIntrospectPost handler handles requests to introspect a token. This also validates the token for the caller.
func (s *Service) OIDCIntrospectPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := req.Context()
	oidc := s.oidc()

	// Create an empty session object which serves as a prototype of the reconstructed session object.
	session := new(fosite.DefaultSession)

	ir, err := oidc.NewIntrospectionRequest(ctx, req, session)
	if err != nil {
		oidc.WriteIntrospectionError(ctx, w, err)
		return
	}

	oidc.WriteIntrospectionResponse(ctx, w, ir)
}
