package charon

import (
	"context"
	"io"
	"net/http"

	"gitlab.com/tozd/waf"
)

// OIDCRevokePost handler handles requests to revoke a token.
func (s *Service) OIDCRevokePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck,gosec
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	// OIDC GetClient requires ctx with serviceContextKey set.
	ctx := context.WithValue(req.Context(), serviceContextKey, s)
	oidc := s.oidc()

	err := oidc.NewRevocationRequest(ctx, req)
	if err != nil {
		errE := withFositeError(err)
		s.WithError(ctx, errE)
		oidc.WriteRevocationResponse(ctx, w, errE)
		return
	}

	oidc.WriteRevocationResponse(ctx, w, nil)
}
