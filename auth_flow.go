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

	MaxAuthAttempts = 10
)

type AuthFlowRequest struct {
	Step     string                   `json:"step"`
	Provider Provider                 `json:"provider,omitempty"`
	Passkey  *AuthFlowRequestPasskey  `json:"passkey,omitempty"`
	Password *AuthFlowRequestPassword `json:"password,omitempty"`
	Code     *AuthFlowRequestCode     `json:"code,omitempty"`
}

type AuthFlowResponseLocation struct {
	URL     string `json:"url"`
	Replace bool   `json:"replace"`
}

type AuthFlowResponse struct {
	Target          Target                    `json:"target"`
	Name            string                    `json:"name,omitempty"`
	Homepage        string                    `json:"homepage,omitempty"`
	OrganizationID  string                    `json:"organizationId,omitempty"`
	Provider        Provider                  `json:"provider,omitempty"`
	EmailOrUsername string                    `json:"emailOrUsername,omitempty"`
	Error           string                    `json:"error,omitempty"`
	Completed       Completed                 `json:"completed,omitempty"`
	Location        *AuthFlowResponseLocation `json:"location,omitempty"`
	Passkey         *AuthFlowResponsePasskey  `json:"passkey,omitempty"`
	Password        *AuthFlowResponsePassword `json:"password,omitempty"`
}

func (s *Service) flowError(w http.ResponseWriter, req *http.Request, flow *Flow, code string, failureErr errors.E) {
	ctx := req.Context()

	if failureErr == nil {
		failureErr = errors.New("flow error")
	}
	errors.Details(failureErr)["code"] = code
	s.WithError(ctx, failureErr)

	response := AuthFlowResponse{
		Target:          flow.Target,
		Name:            flow.TargetName,
		Homepage:        flow.GetTargetHomepage(),
		OrganizationID:  flow.GetTargetOrganization(),
		Provider:        flow.Provider,
		EmailOrUsername: "",
		Error:           code,
		Completed:       "",
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

	// Is the flow ready for a redirect to the OIDC client?
	if flow.Target == TargetOIDC && flow.OIDCRedirectReady && s.completeOIDCAuthorize(w, req, flow) {
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
	// This is similar to API case in completeAuthStep and failAuthStep,
	// but fetches also the flow and checks the session.

	flow := s.GetActiveFlow(w, req, params["id"])
	if flow == nil {
		return
	}

	response := AuthFlowResponse{
		Target:          flow.Target,
		Name:            flow.TargetName,
		Homepage:        flow.GetTargetHomepage(),
		OrganizationID:  flow.GetTargetOrganization(),
		Provider:        flow.Provider,
		EmailOrUsername: flow.EmailOrUsername,
		Error:           "",
		Completed:       flow.Completed,
		Location:        nil,
		Passkey:         nil,
		Password:        nil,
	}

	// Has flow already completed auth step?
	if flow.Completed != "" {
		// If auth step was successful (session is not nil), then we require that the session matches the one made by the flow.
		if flow.Session != nil && !s.validateSession(w, req, flow) {
			return
		}

		if flow.Target == TargetSession {
			// For session target we provide the target location.
			response.Location = &AuthFlowResponseLocation{
				URL:     flow.TargetLocation,
				Replace: true,
			}
		}
	}

	s.WriteJSON(w, req, response, nil)
}

func (s *Service) AuthFlowPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	flow := s.GetActiveFlow(w, req, params["id"])
	if flow == nil {
		return
	}

	// Has flow already completed?
	if flow.IsCompleted() {
		waf.Error(w, req, http.StatusGone)
		return
	}

	var authFlowRequest AuthFlowRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &authFlowRequest)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	// Auth step has not yet been completed.
	if flow.Completed == "" { //nolint:nestif
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
	} else if flow.Target == TargetOIDC && flow.Session != nil && authFlowRequest.Provider == "" {
		// Flow already successfully (session is not nil) completed auth step (but not the others
		// for the OIDC target), provider should not be provided.

		// We checked that flow.Completed != CompletedRedirect in flow.IsCompleted() check above.

		// Current session should match the session in the flow.
		if !s.validateSession(w, req, flow) {
			return
		}

		switch authFlowRequest.Step {
		case "restartAuth":
			s.restartAuth(w, req, flow)
			return
		case "decline":
			s.oidcDecline(w, req, flow)
			return
		case "chooseIdentity":
			s.chooseIdentity(w, req, flow)
			return
		case "redirect":
			if flow.Completed == CompletedDeclined || flow.Completed == CompletedIdentity {
				s.oidcRedirect(w, req, flow)
				return
			}
		}
	} else if flow.Target == TargetOIDC && flow.Completed == CompletedFailed && authFlowRequest.Provider == "" {
		// OIDC target flow did not successfully completed auth step, provider should not be provided.

		if authFlowRequest.Step == "redirect" {
			s.oidcRedirect(w, req, flow)
			return
		}
	}

	errE = errors.New("invalid auth request")
	errors.Details(errE)["request"] = authFlowRequest
	s.BadRequestWithError(w, req, errE)
}

func (s *Service) validateSession(w http.ResponseWriter, req *http.Request, flow *Flow) bool {
	session, errE := getSessionFromRequest(req)
	if errors.Is(errE, ErrSessionNotFound) {
		waf.Error(w, req, http.StatusGone)
		return false
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return false
	}

	// Caller should call validateSession only when flow.Session is set.
	if *flow.Session != session.ID {
		waf.Error(w, req, http.StatusGone)
		return false
	}

	return true
}

func (s *Service) completeAuthStep(w http.ResponseWriter, req *http.Request, api bool, flow *Flow, account *Account, credentials []Credential) {
	ctx := req.Context()

	var completed Completed
	if account == nil {
		// Sign-up. Create new account.
		completed = CompletedSignup
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
		completed = CompletedSignin
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
	flow.Completed = completed
	flow.OIDCRedirectReady = false

	// Everything should already be set to nil at this point, but just to make sure.
	flow.ClearAuthStepAll()

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
		// This is similar to AuthFlowGet, only without fetching the flow and checking the session.
		// It is similar to failAuthStep as well.

		response := AuthFlowResponse{
			Target:          flow.Target,
			Name:            flow.TargetName,
			Homepage:        flow.GetTargetHomepage(),
			OrganizationID:  flow.GetTargetOrganization(),
			Provider:        flow.Provider,
			EmailOrUsername: "",
			Error:           "",
			Completed:       flow.Completed,
			Location:        nil,
			Passkey:         nil,
			Password:        nil,
		}

		if flow.Target == TargetSession {
			// For session target we provide the target location.
			response.Location = &AuthFlowResponseLocation{
				URL:     flow.TargetLocation,
				Replace: true,
			}
		}

		s.WriteJSON(w, req, response, nil)
		return
	}

	// We redirect back to the flow which then for session target redirects to the target location on
	// the frontend, after showing the message about successful sign-in or sign-up. For OIDC target
	// the frontend continues with choosing the identity.
	l, errE := s.Reverse("AuthFlow", waf.Params{"id": flow.ID.String()}, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	s.TemporaryRedirectGetMethod(w, req, l)
}

func (s *Service) increaseAttempts(w http.ResponseWriter, req *http.Request, flow *Flow) bool {
	ctx := req.Context()

	flow.Attempts++
	errE := SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return false
	}

	if flow.Attempts >= MaxAuthAttempts {
		s.failAuthStep(w, req, true, flow, errors.New("reached max auth attempts"))
		return false
	}

	return true
}

func (s *Service) failAuthStep(w http.ResponseWriter, req *http.Request, api bool, flow *Flow, failureErr errors.E) {
	ctx := req.Context()

	flow.Completed = CompletedFailed
	flow.OIDCRedirectReady = false

	// Everything should already be set to nil at this point, but just to make sure.
	flow.ClearAuthStepAll()

	errE := SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WithError(ctx, failureErr)

	if api {
		// This is similar to AuthFlowGet, only without fetching the flow and checking the session.
		// It is similar to completeAuthStep as well.

		response := AuthFlowResponse{
			Target:          flow.Target,
			Name:            flow.TargetName,
			Homepage:        flow.GetTargetHomepage(),
			OrganizationID:  flow.GetTargetOrganization(),
			Provider:        flow.Provider,
			EmailOrUsername: "",
			Error:           "",
			Completed:       flow.Completed,
			Location:        nil,
			Passkey:         nil,
			Password:        nil,
		}

		if flow.Target == TargetSession {
			// For session target we provide the target location.
			response.Location = &AuthFlowResponseLocation{
				URL:     flow.TargetLocation,
				Replace: true,
			}
		}

		encoded := s.PrepareJSON(w, req, response, nil)
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

// restartAuth is not possible in session target because you could then open the flow later on,
// after you already completed the flow and was redirected to target location, and reauthenticate.
// In other words, session target flow is completed (flow.IsCompleted() returns true) after auth
// step is completed and it makes no sense to allow restarting of completed flows.
//
// For OIDC target it is similar, after redirect, we do not allow restarting anymore.
// In other words, after redirect, OIDC target flow is also completed.
func (s *Service) restartAuth(w http.ResponseWriter, req *http.Request, flow *Flow) {
	if flow.IsCompleted() {
		// Sanity check. This should never happen and we check it already in AuthFlowPost but
		// we want to check it again here because restarting authentication for completed
		// flows should really not be possible.
		s.InternalServerErrorWithError(w, req, errors.New("restarting auth for completed flow"))
		return
	}

	ctx := req.Context()

	flow.Session = nil
	flow.Completed = ""
	flow.Provider = ""
	flow.OIDCRedirectReady = false

	// Everything should already be set to nil at this point, but just to make sure.
	flow.ClearAuthStepAll()

	// We do not clear flow.Attempts because otherwise somebody with an account on the
	// system could try up to MaxAuthAttempts - 1, then sign in, then restart, and repeat
	// attempts. We want them to fail the whole flow and to have to restart it (it is easier
	// to count failed flows and detect attacks this way).

	errE := SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// We clear the session cookie. It might otherwise be a surprise to the user that they
	// restarted auth but still stay signed in if they do not complete new authentication.
	// It is better that they have to sign in again.
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
		Target:          flow.Target,
		Name:            flow.TargetName,
		Homepage:        flow.GetTargetHomepage(),
		OrganizationID:  flow.GetTargetOrganization(),
		Provider:        "",
		EmailOrUsername: "",
		Error:           "",
		Completed:       "",
		Location:        nil,
		Passkey:         nil,
		Password:        nil,
	}, nil)
}

func (s *Service) oidcDecline(w http.ResponseWriter, req *http.Request, flow *Flow) {
	ctx := req.Context()

	// TODO: Store decline.

	flow.Completed = CompletedDeclined
	flow.OIDCRedirectReady = false

	errE := SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Target:          flow.Target,
		Name:            flow.TargetName,
		Homepage:        flow.GetTargetHomepage(),
		OrganizationID:  flow.GetTargetOrganization(),
		Provider:        "",
		EmailOrUsername: "",
		Error:           "",
		Completed:       flow.Completed,
		Location:        nil,
		Passkey:         nil,
		Password:        nil,
	}, nil)
}

func (s *Service) chooseIdentity(w http.ResponseWriter, req *http.Request, flow *Flow) {
	ctx := req.Context()

	// TODO: Store chosen identity.

	flow.Completed = CompletedIdentity
	flow.OIDCRedirectReady = false

	errE := SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Target:          flow.Target,
		Name:            flow.TargetName,
		Homepage:        flow.GetTargetHomepage(),
		OrganizationID:  flow.GetTargetOrganization(),
		Provider:        "",
		EmailOrUsername: "",
		Error:           "",
		Completed:       flow.Completed,
		Location:        nil,
		Passkey:         nil,
		Password:        nil,
	}, nil)
}

func (s *Service) oidcRedirect(w http.ResponseWriter, req *http.Request, flow *Flow) {
	ctx := req.Context()

	// It is already checked that flow.Completed is one of CompletedDeclined, CompletedIdentity, or CompletedFailed.
	flow.OIDCRedirectReady = true

	errE := SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Target:          flow.Target,
		Name:            flow.TargetName,
		Homepage:        flow.GetTargetHomepage(),
		OrganizationID:  flow.GetTargetOrganization(),
		Provider:        "",
		EmailOrUsername: "",
		Error:           "",
		Completed:       flow.Completed,
		Location:        nil,
		Passkey:         nil,
		Password:        nil,
	}, nil)
}
