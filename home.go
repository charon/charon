package charon

import (
	"net/http"

	"gitlab.com/tozd/waf"
)

func (s *Service) Home(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	// During development Vite creates WebSocket connection. We always proxy it.
	if s.ProxyStaticTo != "" && hasConnectionUpgrade(req) {
		s.Proxy(w, req)
		return
	}

	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}
