package charon

import (
	"net/http"

	"gitlab.com/tozd/waf"
)

// OIDCRevokePost handler handles requests to revoke a token.
func (s *Service) OIDCRevokePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := req.Context()
	oidc := s.oidc()

	err := oidc.NewRevocationRequest(ctx, req)
	oidc.WriteRevocationResponse(ctx, w, err)
}
