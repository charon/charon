package charon

import (
	"net/http"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/waf"
)

// TODO: Support introspecting ID tokens.
//       See: https://github.com/ory/fosite/issues/410

// OIDCIntrospectPost handler handles requests to introspect a token. This also validates the token for the caller.
func (s *Service) OIDCIntrospectPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := req.Context()
	oidc := s.oidc()

	// Create an empty session object which serves as a prototype of the reconstructed session object.
	session := new(OIDCSession)

	ir, err := oidc.NewIntrospectionRequest(ctx, req, session)
	if err != nil {
		errE := errors.WithStack(err)
		s.WithError(ctx, errE)
		oidc.WriteIntrospectionError(ctx, w, errE)
		return
	}

	oidc.WriteIntrospectionResponse(ctx, w, ir)
}
