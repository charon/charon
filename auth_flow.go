package charon

import (
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

// TODO: Make error message translatable.

type AuthFlowResponse struct {
	Error    string                    `json:"error,omitempty"`
	Location *AuthFlowResponseLocation `json:"location,omitempty"`
	Passkey  *AuthFlowResponsePasskey  `json:"passkey,omitempty"`
	Password *AuthFlowResponsePassword `json:"password,omitempty"`
	Code     *AuthFlowResponseCode     `json:"code,omitempty"`
}

func (s *Service) flowError(w http.ResponseWriter, req *http.Request, msg string, err errors.E) {
	ctx := req.Context()

	if err != nil {
		s.WithError(ctx, err)
	}

	response := AuthFlowResponse{
		Error:    msg,
		Location: nil,
		Passkey:  nil,
		Password: nil,
		Code:     nil,
	}

	encoded := s.PrepareJSON(w, req, response, nil)
	if encoded == nil {
		return
	}

	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(encoded)
}

func (s *Service) AuthFlow(w http.ResponseWriter, req *http.Request, params waf.Params) {
	flow := s.GetActiveFlow(w, req, false, params["id"])
	if flow == nil {
		return
	}

	w.Header().Add("Link", "</api>; rel=preload; as=fetch; crossorigin=anonymous")
	w.WriteHeader(http.StatusEarlyHints)

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) AuthFlowGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	// This already returns AuthFlowResponse with Location set.
	flow := s.GetActiveFlow(w, req, true, params["id"])
	if flow == nil {
		return
	}

	response := AuthFlowResponse{
		Error:    "",
		Location: nil,
		Passkey:  nil,
		Password: nil,
		Code:     nil,
	}

	// Only code can be resumed.
	if flow.Code != nil {
		response.Code = &AuthFlowResponseCode{
			EmailOrUsername: flow.Code.EmailOrUsername,
		}
	}

	s.WriteJSON(w, req, response, nil)
}

func (s *Service) AuthFlowPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	flow := s.GetActiveFlow(w, req, true, params["id"])
	if flow == nil {
		return
	}

	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

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
			if authFlowRequest.Passkey != nil {
				s.completePasskeyGet(w, req, flow, authFlowRequest.Passkey)
				return
			}
		case "createStart":
			s.startPasskeyCreate(w, req, flow)
			return
		case "createComplete":
			if authFlowRequest.Passkey != nil {
				s.completePasskeyCreate(w, req, flow, authFlowRequest.Passkey)
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
			Error: "",
			Location: &AuthFlowResponseLocation{
				URL:     flow.Target,
				Replace: true,
			},
			Passkey:  nil,
			Password: nil,
			Code:     nil,
		}, nil)
	} else {
		s.TemporaryRedirectGetMethod(w, req, flow.Target)
	}
}
