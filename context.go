package charon

import (
	"net/http"

	"gitlab.com/tozd/waf"
)

type serviceContext struct {
	Site

	ClientID    string `json:"clientId"`
	RedirectURI string `json:"redirectUri"`
}

func (s *Service) Context(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := req.Context()

	site := waf.MustGetSite[*Site](ctx)

	co := s.charonOrganization()

	// TODO: Cache so that it is not re-computed on every request.
	s.WriteJSON(w, req, serviceContext{
		Site:        *site,
		ClientID:    co.ClientID.String(),
		RedirectURI: co.RedirectURI,
	}, nil)
}
