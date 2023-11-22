package charon

import (
	"net/http"

	"gitlab.com/tozd/waf"
)

func (s *Service) Home(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) HomeGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	s.ServeStaticFile(w, req, "/index.json")
}
