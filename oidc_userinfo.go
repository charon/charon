package charon

import (
	"fmt"
	"io"
	"net/http"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/waf"
)

// oidcCUserInfo provides ID token contents based on provided access token.
//
// Based on UserinfoHandler from Hydra.
// See: https://github.com/ory/hydra/blob/master/oauth2/handler.go
func (s *Service) oidcCUserInfo(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()
	oidc := s.oidc()

	// Create an empty session object which serves as a prototype of the reconstructed session object.
	session := new(OIDCSession)

	tokenType, ar, err := oidc.IntrospectToken(ctx, fosite.AccessTokenFromRequest(req), fosite.AccessToken, session)
	if err != nil {
		rfcerr := fosite.ErrorToRFC6749Error(err)
		if rfcerr.StatusCode() == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s",error_description="%s"`, rfcerr.ErrorField, rfcerr.GetDescription()))
		}
		s.WithError(ctx, errors.WithStack(rfcerr))
		waf.Error(w, req, rfcerr.StatusCode())
		return
	}

	if tokenType != fosite.AccessToken {
		errE := errors.New("only access tokens are allowed in the authorization header")
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="invalid_token",error_description="%s"`, err.Error()))
		s.WithError(ctx, errE)
		waf.Error(w, req, http.StatusUnauthorized)
		return
	}

	interim := ar.GetSession().(openid.Session).IDTokenClaims().ToMap() //nolint:forcetypeassert
	keysToDelete := []string{"aud", "auth_time", "exp", "gau", "iat", "iss", "jti", "nonce", "rat", "at_hash", "c_hash", "sid"}
	for _, key := range keysToDelete {
		delete(interim, key)
	}

	s.WriteJSON(w, req, interim, nil)
}

func (s *Service) OIDCUserInfoGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	s.oidcCUserInfo(w, req)
}

func (s *Service) OIDCUserInfoPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	s.oidcCUserInfo(w, req)
}
