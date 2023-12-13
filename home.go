package charon

import (
	"net/http"

	"gitlab.com/tozd/waf"
)

func (s *Service) Home(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	// During development Vite creates WebSocket connection. We always proxy it.
	if s.Development != "" && hasConnectionUpgrade(req) {
		s.Proxy(w, req)
		return
	}

	if !s.RequireAuthenticated(w, req, false, "Charon Home") {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) HomeGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	s.ServeStaticFile(w, req, "/index.json")
}
