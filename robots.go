package charon

import (
	"net/http"

	"gitlab.com/tozd/waf"
)

func (s *Service) Robots(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/robots.txt")
	}
}
