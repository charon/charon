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

	for _, key := range s.oidcKeys {
		keys = append(keys, key.Public())
	}

	response := jose.JSONWebKeySet{
		Keys: keys,
	}

	s.WriteJSON(w, req, response, nil)
}
