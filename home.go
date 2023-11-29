package charon

import (
	"net/http"
	"strings"

	"gitlab.com/tozd/waf"
)

func (s *Service) Home(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	// During development Vite creates WebSocket connection. We always proxy it.
	if s.Development != "" && strings.ToLower(req.Header.Get("Connection")) == "upgrade" {
		s.Proxy(w, req)
		return
	}

	if !s.RequireAuthenticated(w, req, false) {
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
