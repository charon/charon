package charon

import (
	"context"
	"net"
	"net/http"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

const (
	SessionCookieName = "__Host-session"
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

// getFlowFromID obtains Flow from its string ID.
func getFlowFromID(ctx context.Context, value string) (*Flow, errors.E) {
	if value == "" {
		return nil, errors.WithStack(ErrFlowNotFound)
	}

	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrFlowNotFound)
	}

	return GetFlow(ctx, id)
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
		Passkey: nil,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return false
	}

	location, errE := s.Reverse("AuthFlow", waf.Params{"id": id.String()}, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return false
	}
	s.TemporaryRedirectGetMethod(w, req, location)
	return false
}

func (s *Service) GetActiveFlow(w http.ResponseWriter, req *http.Request, api bool, value string) *Flow {
	flow, errE := getFlowFromID(req.Context(), value)
	if errors.Is(errE, ErrFlowNotFound) {
		s.BadRequestWithError(w, req, errE)
		return nil
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}

	// Has flow already completed?
	if flow.Session != nil {
		// TODO: Redirect to target only if same user is still authenticated.
		//       When flow completes, we should remember the user who authenticated. Then, here, we should check if the same user is still
		//       authenticated. If yes, then we redirect to target. If not and some user is authenticated, then we redirect to /. If not and
		//       no user is authenticated, then we start a new flow with additional field which requires the completing user to be the same.
		//       If after flow completes the user is the same, we redirect to target, otherwise to /.

		if api {
			s.WriteJSON(w, req, AuthFlowResponse{
				Location: &AuthFlowResponseLocation{
					URL:     flow.Target,
					Replace: true,
				},
				Passkey: nil,
			}, nil)
			return nil
		}

		s.TemporaryRedirectGetMethod(w, req, flow.Target)
		return nil
	}

	return flow
}

func getHost(app *App, domain string) (string, errors.E) {
	// ListenAddr blocks until the server runs.
	listenAddr := app.Server.ListenAddr()
	if listenAddr == "" {
		// Server failed to start. We just return in this case.
		return "", nil
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", errors.WithStack(err)
	}
	host := domain
	if port != "443" {
		host = net.JoinHostPort(host, port)
	}
	return host, nil
}
