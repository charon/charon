package charon

import (
	"net/http"

	"gitlab.com/tozd/waf"
)

// TODO: Allow specifying target to redirect to?
//       How to do that in a way that we do not enable open redirect?

// TODO: Allow specifying that a) provider who signed the user in should be signed out as well b) all providers user is known with is signed out as well.

func (s *Service) AuthDelete(w http.ResponseWriter, req *http.Request, _ waf.Params) {
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

	s.WriteJSON(w, req, AuthFlowResponse{
		Error: "",
		Location: &AuthFlowResponseLocation{
			URL:     "/",
			Replace: false,
		},
		Passkey:  nil,
		Password: nil,
		Code:     nil,
	}, nil)
}
