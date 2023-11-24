package charon

import (
	"net/http"
	"net/url"
	"strings"

	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

func (s *Service) Home(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	// During development Vite creates WebSocket connection. We always proxy it.
	if s.Development != "" && strings.ToLower(req.Header.Get("Connection")) == "upgrade" {
		s.Proxy(w, req)
		return
	}

	// TODO: Check if user is authenticated.
	qs := url.Values{}
	qs.Set("flow", identifier.New().String())
	location, errE := s.Reverse("Auth", nil, qs)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	s.TemporaryRedirectGetMethod(w, req, location)
}

func (s *Service) HomeGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	s.ServeStaticFile(w, req, "/index.json")
}
