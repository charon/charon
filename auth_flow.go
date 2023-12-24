package charon

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

const (
	StepStart    = "start"
	StepComplete = "complete"
)

type AuthFlowRequest struct {
	Step     string                   `json:"step"`
	Provider Provider                 `json:"provider"`
	Passkey  *AuthFlowRequestPasskey  `json:"passkey,omitempty"`
	Password *AuthFlowRequestPassword `json:"password,omitempty"`
	Code     *AuthFlowRequestCode     `json:"code,omitempty"`
}

type AuthFlowResponseLocation struct {
	URL     string `json:"url"`
	Replace bool   `json:"replace"`
}

type AuthFlowResponse struct {
	Name            string                    `json:"name,omitempty"`
	Provider        Provider                  `json:"provider,omitempty"`
	EmailOrUsername string                    `json:"emailOrUsername,omitempty"`
	Error           string                    `json:"error,omitempty"`
	Completed       bool                      `json:"completed,omitempty"`
	Location        *AuthFlowResponseLocation `json:"location,omitempty"`
	Passkey         *AuthFlowResponsePasskey  `json:"passkey,omitempty"`
	Password        *AuthFlowResponsePassword `json:"password,omitempty"`
}

func (s *Service) flowError(w http.ResponseWriter, req *http.Request, code string, err errors.E) {
	ctx := req.Context()

	if err == nil {
		err = errors.New("flow error")
	}
	errors.Details(err)["code"] = code
	s.WithError(ctx, err)

	response := AuthFlowResponse{
		Name:            "",
		Provider:        "",
		EmailOrUsername: "",
		Error:           code,
		Completed:       false,
		Location:        nil,
		Passkey:         nil,
		Password:        nil,
	}

	encoded := s.PrepareJSON(w, req, response, nil)
	if encoded == nil {
		return
	}

	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(encoded)
}

func (s *Service) AuthFlow(w http.ResponseWriter, req *http.Request, params waf.Params) {
	flow := s.GetActiveFlow(w, req, params["id"])
	if flow == nil {
		return
	}

	l, errE := s.ReverseAPI("AuthFlow", waf.Params{"id": flow.ID.String()}, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// We have it hard-coded here because we have it hard-coded on the frontend as well.
	w.Header().Add("Link", "</context.json>; rel=preload; as=fetch; crossorigin=anonymous")
	w.Header().Add("Link", fmt.Sprintf("<%s>; rel=preload; as=fetch; crossorigin=anonymous", l))
	w.WriteHeader(http.StatusEarlyHints)

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) AuthFlowGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	flow := s.GetActiveFlow(w, req, params["id"])
	if flow == nil {
		return
	}

	response := AuthFlowResponse{
		Name:            flow.TargetName,
		Provider:        flow.Provider,
		EmailOrUsername: flow.EmailOrUsername,
		Error:           "",
		Completed:       false,
		Location:        nil,
		Passkey:         nil,
		Password:        nil,
	}

	// Has flow already completed?
	if flow.Session != nil || flow.Failed {
		// TODO: Redirect to target only if same user is still authenticated.
		//       When flow completes, we should remember the user who authenticated. Then, here, we should check if the same user is still
		//       authenticated. If yes, then we redirect to target. If not and some user is authenticated, then we redirect to /. If not and
		//       no user is authenticated, then we start a new flow with additional field which requires the completing user to be the same.
		//       If after flow completes the user is the same, we redirect to target, otherwise to /.

		response.Completed = true
		response.Location = &AuthFlowResponseLocation{
			URL:     flow.TargetLocation,
			Replace: true,
		}

		if flow.Failed {
			response.Error = "failed"
		}
	}

	s.WriteJSON(w, req, response, nil)
}

func (s *Service) AuthFlowPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	flow := s.GetActiveFlow(w, req, params["id"])
	if flow == nil {
		return
	}

	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	// Has flow already completed?
	if flow.Session != nil || flow.Failed {
		s.BadRequestWithError(w, req, errors.New("flow already completed"))
		return
	}

	var authFlowRequest AuthFlowRequest
	errE := x.DecodeJSON(req.Body, &authFlowRequest)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if _, ok := s.oidcProviders()[authFlowRequest.Provider]; ok {
		if authFlowRequest.Step == StepStart {
			if authFlowRequest.Provider != "" {
				s.startOIDCProvider(w, req, flow, authFlowRequest.Provider)
				return
			}
		}
	}

	if authFlowRequest.Provider == PasskeyProvider {
		switch authFlowRequest.Step {
		case "getStart":
			s.startPasskeyGet(w, req, flow)
			return
		case "getComplete":
			if authFlowRequest.Passkey != nil && authFlowRequest.Passkey.GetResponse != nil {
				s.completePasskeyGet(w, req, flow, authFlowRequest.Passkey.GetResponse)
				return
			}
		case "createStart":
			s.startPasskeyCreate(w, req, flow)
			return
		case "createComplete":
			if authFlowRequest.Passkey != nil && authFlowRequest.Passkey.CreateResponse != nil {
				s.completePasskeyCreate(w, req, flow, authFlowRequest.Passkey.CreateResponse)
				return
			}
		}
	}

	if authFlowRequest.Provider == PasswordProvider {
		switch authFlowRequest.Step {
		case StepStart:
			if authFlowRequest.Password != nil && authFlowRequest.Password.Start != nil {
				s.startPassword(w, req, flow, authFlowRequest.Password.Start)
				return
			}
		case StepComplete:
			if authFlowRequest.Password != nil && authFlowRequest.Password.Complete != nil {
				s.completePassword(w, req, flow, authFlowRequest.Password.Complete)
				return
			}
		}
	}

	if authFlowRequest.Provider == CodeProvider {
		switch authFlowRequest.Step {
		case StepStart:
			if authFlowRequest.Code != nil && authFlowRequest.Code.Start != nil {
				s.startCode(w, req, flow, authFlowRequest.Code.Start)
				return
			}
		case StepComplete:
			if authFlowRequest.Code != nil && authFlowRequest.Code.Complete != nil {
				s.completeCode(w, req, flow, authFlowRequest.Code.Complete)
				return
			}
		}
	}

	errE = errors.New("invalid auth request")
	errors.Details(errE)["request"] = authFlowRequest
	s.BadRequestWithError(w, req, errE)
}

func (s *Service) completeAuthStep(w http.ResponseWriter, req *http.Request, api bool, flow *Flow, account *Account, credentials []Credential) {
	ctx := req.Context()

	if account == nil {
		// Sign-up. Create new account.
		account = &Account{
			ID:          identifier.New(),
			Credentials: map[Provider][]Credential{},
		}
		for _, credential := range credentials {
			account.Credentials[credential.Provider] = append(account.Credentials[credential.Provider], credential)
		}
		errE := SetAccount(ctx, account)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
	} else {
		// Sign-in. Update credentials for an existing account.
		// TODO: Updating only if credentials (meaningfully) changed.
		// TODO: Update in a way which does not preserve history.
		account.UpdateCredentials(credentials)
		errE := SetAccount(ctx, account)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
	}

	sessionID := identifier.New()
	errE := SetSession(ctx, &Session{
		ID:      sessionID,
		Account: account.ID,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	flow.Session = &sessionID

	// Should already be set to nil at this point, but just to make sure.
	flow.Reset()

	errE = SetFlow(ctx, flow)
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

	if api {
		s.WriteJSON(w, req, AuthFlowResponse{
			Name:            flow.TargetName,
			Provider:        flow.Provider,
			EmailOrUsername: flow.EmailOrUsername,
			Error:           "",
			Completed:       true,
			Location: &AuthFlowResponseLocation{
				URL:     flow.TargetLocation,
				Replace: true,
			},
			Passkey:  nil,
			Password: nil,
		}, nil)
		return
	}

	// We redirect back to the flow which then redirects to the target location on the frontend,
	// after showing the message about successful sign-in or sign-up.
	l, errE := s.Reverse("AuthFlow", waf.Params{"id": flow.ID.String()}, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	s.TemporaryRedirectGetMethod(w, req, l)
}

func (s *Service) failAuthStep(w http.ResponseWriter, req *http.Request, api bool, flow *Flow, err errors.E) {
	ctx := req.Context()

	flow.Failed = true

	// Should already be set to nil at this point, but just to make sure.
	flow.Reset()

	errE := SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WithError(ctx, err)

	if api {
		encoded := s.PrepareJSON(w, req, AuthFlowResponse{
			Name:            flow.TargetName,
			Provider:        flow.Provider,
			EmailOrUsername: flow.EmailOrUsername,
			Error:           "failed",
			Completed:       true,
			Location: &AuthFlowResponseLocation{
				URL:     flow.TargetLocation,
				Replace: true,
			},
			Passkey:  nil,
			Password: nil,
		}, nil)
		if encoded == nil {
			return
		}

		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(encoded)
		return
	}

	// We redirect back to the flow which then shows the failure message.
	l, errE := s.Reverse("AuthFlow", waf.Params{"id": flow.ID.String()}, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	s.TemporaryRedirectGetMethod(w, req, l)
}
