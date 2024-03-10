package charon

import (
	"net/http"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/waf"
)

func (s *Service) MeGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	_, errE := s.getSessionFromRequest(w, req)
	if errors.Is(errE, ErrSessionNotFound) {
		encoded := s.PrepareJSON(w, req, []byte(`{"error":"unauthorized"}`), nil)
		if encoded == nil {
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(encoded)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, []byte(`{"success":true}`), nil)
}
