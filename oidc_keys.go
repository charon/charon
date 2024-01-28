package charon

import (
	"net/http"

	"github.com/go-jose/go-jose/v3"
	"gitlab.com/tozd/waf"
)

// TODO: Implement using fosite.
//       See: https://github.com/ory/fosite/issues/407

// Provides public key used to sign tokens.
func (s *Service) OIDCKeys(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	response := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{s.oidcPublicKey},
	}

	s.WriteJSON(w, req, response, nil)
}
