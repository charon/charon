package charon

import (
	"net/http"

	"github.com/rs/zerolog"
	"gitlab.com/tozd/waf"
)

type Service struct {
	waf.Service[*Site]
}

func (s *Service) Home(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	zerolog.Ctx(req.Context()).Info().Msg("hello from Home handler")

	s.ServeStaticFile(w, req, "/index.html")
}

func (s *Service) HomeGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	s.ServeStaticFile(w, req, "/index.json")
}
