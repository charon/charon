package charon

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ory/fosite"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/waf"
)

// TODO: Add support for tokeninfo endpoint to introspect ID tokens.
//       See: https://github.com/ory/fosite/issues/410
//       See: https://developers.google.com/identity/sign-in/web/backend-auth#calling-the-tokeninfo-endpoint

// TODO: Add support for specifying expected audience to be available in introspected access tokens.
//       See: https://github.com/ory/fosite/issues/410#issuecomment-948393832

// OIDCIntrospectPost handler handles requests to introspect a token. This also validates the token for the caller.
func (s *Service) OIDCIntrospectPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

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

	// We have to fix RequestedAt timestamp to match the IssuedAt timestamp
	// because RequestedAt is used as IssuedAt in WriteIntrospectionResponse.
	// See: https://github.com/ory/fosite/issues/774
	ar := ir.GetAccessRequester().(*fosite.AccessRequest)
	ar.RequestedAt = ar.GetSession().(*OIDCSession).JWTClaims.IssuedAt

	if ir.GetTokenUse() == "refresh_token" {
		// We want to handle refresh tokens differently and output refresh token expiration time.
		// See: https://github.com/ory/fosite/issues/801

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		if !ir.IsActive() {
			_ = json.NewEncoder(w).Encode(&struct {
				Active bool `json:"active"`
			}{Active: false})
			return
		}

		response := map[string]interface{}{
			"active": true,
		}

		if !ir.GetAccessRequester().GetSession().GetExpiresAt(fosite.RefreshToken).IsZero() {
			response["exp"] = ir.GetAccessRequester().GetSession().GetExpiresAt(fosite.RefreshToken).Unix()
		}

		_ = json.NewEncoder(w).Encode(response)
		return
	}

	oidc.WriteIntrospectionResponse(ctx, w, ir)
}
