package charon

import (
	"net/http"

	"gitlab.com/tozd/waf"
)

type serviceContext struct {
	Site

	OrganizationID string `json:"organizationId"`
	ClientID       string `json:"clientId"`
	RedirectURI    string `json:"redirectUri"`
}

type ProviderInfo struct {
	Key  string                 `json:"key"`
	Name string                 `json:"name"`
	Type ThirdPartyProviderType `json:"type"`
}

func (s *Service) Context(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := req.Context()

	site := waf.MustGetSite[*Site](ctx)

	co := s.charonOrganization()

	// TODO: Cache so that it is not re-computed on every request.
	s.WriteJSON(w, req, serviceContext{
		Site:           *site,
		OrganizationID: co.ID.String(),
		ClientID:       co.ClientID.String(),
		RedirectURI:    co.RedirectURI,
	}, nil)
}
