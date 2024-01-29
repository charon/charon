package charon

import (
	"net/http"

	"github.com/go-jose/go-jose/v3"
	"gitlab.com/tozd/waf"
)

// TODO: Implement using fosite.
//       See: https://github.com/ory/fosite/issues/407

// OIDCKeys provides public key used to sign tokens.
func (s *Service) OIDCKeys(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	keys := []jose.JSONWebKey{}

	if s.oidcKeys.rsa != nil {
		keys = append(keys, s.oidcKeys.rsa.Public())
	}
	if s.oidcKeys.p256 != nil {
		keys = append(keys, s.oidcKeys.p256.Public())
	}
	if s.oidcKeys.p384 != nil {
		keys = append(keys, s.oidcKeys.p384.Public())
	}
	if s.oidcKeys.p521 != nil {
		keys = append(keys, s.oidcKeys.p521.Public())
	}

	response := jose.JSONWebKeySet{
		Keys: keys,
	}

	s.WriteJSON(w, req, response, nil)
}
