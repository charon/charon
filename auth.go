package charon

import (
	"io"
	"net/http"
	"net/url"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

type AccountRef struct {
	ID identifier.Identifier `json:"id"`
}

type AuthSignoutResponse struct {
	URL     string `json:"url"`
	Replace bool   `json:"replace"`
}

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

	s.WriteJSON(w, req, AuthSignoutResponse{
		URL:     "/",
		Replace: false,
	}, nil)
}

type AuthCreateRequest struct {
	Location string `json:"location"`
}

type AuthCreateResponse struct {
	ID identifier.Identifier `json:"id"`
}

func (s *Service) AuthCreatePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	var authCreatePostRequest AuthCreateRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &authCreatePostRequest)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if authCreatePostRequest.Location == "" {
		s.BadRequestWithError(w, req, errors.New("invalid location"))
		return
	}

	u, err := url.Parse(authCreatePostRequest.Location)
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithMessage(err, "invalid location"))
		return
	}

	if u.Scheme != "" || u.Host != "" || u.Opaque != "" || u.User != nil {
		s.BadRequestWithError(w, req, errors.New("invalid location"))
		return
	}

	_, errE = s.GetRoute(u.Path, http.MethodGet)
	if errE != nil {
		s.BadRequestWithError(w, req, errors.WithMessage(errE, "invalid location"))
		return
	}

	_, errE = getSessionFromRequest(req)
	if errE == nil {
		encoded := s.PrepareJSON(w, req, []byte(`{"error":"alreadyAuthenticated"}`), nil)
		if encoded == nil {
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write(encoded)
		return
	} else if !errors.Is(errE, ErrSessionNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	id := identifier.New()
	errE = SetFlow(req.Context(), &Flow{
		ID:                   id,
		Session:              nil,
		Completed:            "",
		Target:               TargetSession,
		TargetLocation:       u.String(),
		TargetName:           "Charon Dashboard",
		TargetOrganization:   nil,
		Provider:             "",
		EmailOrUsername:      "",
		Attempts:             0,
		OIDCAuthorizeRequest: nil,
		OIDCRedirectReady:    false,
		OIDCProvider:         nil,
		Passkey:              nil,
		Password:             nil,
		Code:                 nil,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthCreateResponse{ID: id}, nil)
}
