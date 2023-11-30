package charon

import (
	"net/http"
	"time"

	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

func (s *Service) completeAuthStep(w http.ResponseWriter, req *http.Request, flow *Flow, provider, userID string) {
	sessionID := identifier.New()
	errE := SetSession(req.Context(), &Session{
		ID: sessionID,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	flow.Session = &sessionID
	flow.OIDC = nil

	errE = SetFlow(req.Context(), flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	cookie := http.Cookie{ //nolint:exhaustruct
		Name:     SessionCookieName,
		Value:    sessionID.String(),
		Path:     "/",
		Domain:   "",
		Expires:  time.Now().Add(7 * 24 * time.Hour),
		MaxAge:   0,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	s.TemporaryRedirectGetMethod(w, req, flow.Target)
}

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
