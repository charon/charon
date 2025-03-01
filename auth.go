package charon

import (
	"io"
	"net/http"
	"strings"
	"time"

	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/waf"
)

type AuthSignoutRequest struct {
	Location string `json:"location"`
}

type AuthSignoutResponse struct {
	Location string `json:"url"`
}

// TODO: Allow specifying that a) provider who signed the user in should be signed out as well b) all providers user is known with is signed out as well.

func (s *Service) AuthSignoutPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	var authSignoutRequest AuthSignoutRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &authSignoutRequest)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	location, errE := validRedirectLocation(s, authSignoutRequest.Location)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	// We clear all session cookies for all flows.
	for _, cookie := range req.Cookies() {
		if strings.HasPrefix(cookie.Name, SessionCookiePrefix) {
			cookie.Value = ""
			cookie.Expires = time.Time{}
			cookie.MaxAge = -1
			http.SetCookie(w, cookie)
		}
	}

	s.WriteJSON(w, req, AuthSignoutResponse{
		Location: location,
	}, nil)
}
