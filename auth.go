package charon

import (
	"io"
	"net/http"

	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

type AccountRef struct {
	ID identifier.Identifier `json:"id"`
}

type AuthSignoutRequest struct {
	Location string `json:"location"`
}

type AuthSignoutResponse struct {
	URL     string `json:"url"`
	Replace bool   `json:"replace"`
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

	cookie := http.Cookie{ //nolint:exhaustruct
		Name:     SessionCookieName,
		Path:     "/",
		Domain:   "",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	s.WriteJSON(w, req, AuthSignoutResponse{
		URL:     location,
		Replace: false,
	}, nil)
}
