package charon

import (
	"io"
	"net/http"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/waf"
)

// OIDCRevokePost handler handles requests to revoke a token.
func (s *Service) OIDCRevokePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()
	oidc := s.oidc()

	err := oidc.NewRevocationRequest(ctx, req)
	if err != nil {
		errE := errors.WithStack(err)
		s.WithError(ctx, errE)
		oidc.WriteRevocationResponse(ctx, w, errE)
		return
	}

	oidc.WriteRevocationResponse(ctx, w, nil)
}
