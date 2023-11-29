package charon

import (
	"net/http"

	"gitlab.com/tozd/waf"
)

func (s *Service) Auth(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if !s.RequireActiveFlow(w, req, false) {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}
