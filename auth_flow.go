package charon

import (
	"io"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

type AuthFlowResponsePasskey struct {
	CreateOptions *protocol.CredentialCreation  `json:"createOptions,omitempty"`
	GetOptions    *protocol.CredentialAssertion `json:"getOptions,omitempty"`
}

type AuthFlowResponseLocation struct {
	URL     string `json:"url"`
	Replace bool   `json:"replace"`
}

type AuthFlowResponse struct {
	Location *AuthFlowResponseLocation `json:"location,omitempty"`
	Passkey  *AuthFlowResponsePasskey  `json:"passkey,omitempty"`
}

type AuthFlowRequestPasskey struct {
	CreateResponse *protocol.CredentialCreationResponse  `json:"createResponse,omitempty"`
	GetResponse    *protocol.CredentialAssertionResponse `json:"getResponse,omitempty"`
}

type AuthFlowRequest struct {
	Step     string                  `json:"step"`
	Provider string                  `json:"provider"`
	Passkey  *AuthFlowRequestPasskey `json:"passkey,omitempty"`
}

func (s *Service) AuthFlow(w http.ResponseWriter, req *http.Request, params waf.Params) {
	flow := s.GetActiveFlow(w, req, false, params["id"])
	if flow == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
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
		if authFlowRequest.Step != "start" {
			errE = errors.New("invalid auth request")
			errors.Details(errE)["request"] = authFlowRequest
			s.BadRequestWithError(w, req, errE)
			return
		}
		s.startOIDCProvider(w, req, flow, authFlowRequest.Provider)
		return
	}

	if authFlowRequest.Provider == "passkey" {
		switch authFlowRequest.Step {
		case "getStart":
			s.startPasskeyGet(w, req, flow)
			return
		case "getComplete":
			s.completePasskeyGet(w, req, flow, authFlowRequest.Passkey)
			return
		case "createStart":
			s.startPasskeyCreate(w, req, flow)
			return
		case "createComplete":
			s.completePasskeyCreate(w, req, flow, authFlowRequest.Passkey)
			return
		default:
			errE = errors.New("invalid auth request")
			errors.Details(errE)["request"] = authFlowRequest
			s.BadRequestWithError(w, req, errE)
			return
		}
	}

	errE = errors.New("invalid auth request")
	errors.Details(errE)["request"] = authFlowRequest
	s.BadRequestWithError(w, req, errE)
}

func (s *Service) completeAuthStep(w http.ResponseWriter, req *http.Request, api bool, flow *Flow, provider, credentialID string, jsonData []byte) {
	ctx := req.Context()

	account, errE := GetAccountByCredential(ctx, provider, credentialID)
	if errors.Is(errE, ErrAccountNotFound) {
		// Sign-up. Create new account.
		account = &Account{
			ID: identifier.New(),
			Credentials: map[string][]Credential{
				provider: {{
					ID:       credentialID,
					Provider: provider,
					Data:     jsonData,
				}},
			},
		}
		errE = SetAccount(ctx, account)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	} else {
		// Sign-in. Update credential for an existing account.
		account.UpdateCredential(provider, credentialID, jsonData)
		errE = SetAccount(ctx, account)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
	}

	sessionID := identifier.New()
	errE = SetSession(ctx, &Session{
		ID:      sessionID,
		Account: account.ID,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	flow.Session = &sessionID

	// These should already be set to nil at this point, but just to make sure.
	flow.OIDC = nil
	flow.Passkey = nil

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
			Location: &AuthFlowResponseLocation{
				URL:     flow.Target,
				Replace: true,
			},
			Passkey: nil,
		}, nil)
	} else {
		s.TemporaryRedirectGetMethod(w, req, flow.Target)
	}
}
