package charon

import (
	"net/http"
	"net/url"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

const (
	SessionCookieName = "session"
	FlowParameterName = "flow"
)

func getSessionFromRequest(req *http.Request) (*Session, errors.E) {
	cookie, err := req.Cookie(SessionCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, errors.WithStack(ErrSessionNotFound)
	} else if err != nil {
		return nil, errors.WithStack(err)
	}

	id, errE := identifier.FromString(cookie.Value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrSessionNotFound)
	}

	return GetSession(req.Context(), id)
}

func getFlowFromRequest(req *http.Request, param string) (*Flow, errors.E) {
	value := req.Form.Get(param)
	if value == "" {
		return nil, errors.WithStack(ErrFlowNotFound)
	}

	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrFlowNotFound)
	}

	return GetFlow(req.Context(), id)
}

func (s *Service) RequireAuthenticated(w http.ResponseWriter, req *http.Request, api bool) bool {
	_, errE := getSessionFromRequest(req)
	if errE == nil {
		return true
	} else if !errors.Is(errE, ErrSessionNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return false
	}

	if api {
		waf.Error(w, req, http.StatusUnauthorized)
		return false
	}

	id := identifier.New()
	errE = SetFlow(req.Context(), &Flow{
		ID:      id,
		Session: nil,
		Target:  req.URL.String(),
		OIDC:    nil,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return false
	}

	qs := url.Values{}
	qs.Set(FlowParameterName, id.String())
	location, errE := s.Reverse("Auth", nil, qs)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return false
	}
	s.TemporaryRedirectGetMethod(w, req, location)
	return false
}

func (s *Service) RequireActiveFlow(w http.ResponseWriter, req *http.Request, api bool) bool {
	flow := s.GetActiveFlow(w, req, api, FlowParameterName)
	return flow != nil
}

func (s *Service) GetActiveFlow(w http.ResponseWriter, req *http.Request, api bool, param string) *Flow {
	flow, errE := getFlowFromRequest(req, param)
	if errors.Is(errE, ErrFlowNotFound) {
		s.BadRequestWithError(w, req, errE)
		return nil
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}

	if flow.Session != nil {
		if api {
			s.BadRequest(w, req)
			return nil
		} else {
			// TODO: Redirect to target only if same user is still authenticated.
			//       When flow completes, we should remember the user who authenticated. Then, here, we should check if the same user is still
			//       authenticated. If yes, then we redirect to target. If not and some user is authenticated, then we redirect to /. If not and
			//       no user is authenticated, then we start a new flow with additional field which requires the completing user to be the same.
			//       If after flow completes the user is the same, we redirect to target, otherwise to /.
			s.TemporaryRedirectGetMethod(w, req, flow.Target)
			return nil
		}
	}

	return flow
}
