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

type AuthFlowResponsePasswordDeriveOptions struct {
	Name       string `json:"name"`
	NamedCurve string `json:"namedCurve"`
}

type AuthFlowResponsePasswordEncryptOptions struct {
	Name      string `json:"name"`
	Length    int    `json:"length"`
	NonceSize int    `json:"nonceSize"`
	TagLength int    `json:"tagLength"`
}

type AuthFlowResponsePassword struct {
	PublicKey      []byte                                 `json:"publicKey"`
	DeriveOptions  AuthFlowResponsePasswordDeriveOptions  `json:"deriveOptions"`
	EncryptOptions AuthFlowResponsePasswordEncryptOptions `json:"encryptOptions"`
}

type AuthFlowResponse struct {
	Location *AuthFlowResponseLocation `json:"location,omitempty"`
	Passkey  *AuthFlowResponsePasskey  `json:"passkey,omitempty"`
	Password *AuthFlowResponsePassword `json:"password,omitempty"`
	Code     bool                      `json:"code,omitempty"`
}

type AuthFlowRequestPasskey struct {
	CreateResponse *protocol.CredentialCreationResponse  `json:"createResponse,omitempty"`
	GetResponse    *protocol.CredentialAssertionResponse `json:"getResponse,omitempty"`
}

type AuthFlowRequestPassword struct {
	PublicKey       []byte `json:"publicKey"`
	Nonce           []byte `json:"nonce"`
	EmailOrUsername string `json:"emailOrUsername"`
	Password        []byte `json:"password"`
}

type AuthFlowRequestCodeStart struct {
	EmailOrUsername string `json:"emailOrUsername"`
}

type AuthFlowRequestCodeComplete struct {
	Code string `json:"code"`
}

type AuthFlowRequest struct {
	Step         string                       `json:"step"`
	Provider     Provider                     `json:"provider"`
	Passkey      *AuthFlowRequestPasskey      `json:"passkey,omitempty"`
	Password     *AuthFlowRequestPassword     `json:"password,omitempty"`
	CodeStart    *AuthFlowRequestCodeStart    `json:"codeStart,omitempty"`
	CodeComplete *AuthFlowRequestCodeComplete `json:"codeComplete,omitempty"`
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
		if authFlowRequest.Step == "start" {
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
		case "start":
			s.startPassword(w, req, flow)
			return
		case "complete":
			if authFlowRequest.Password != nil {
				s.completePassword(w, req, flow, authFlowRequest.Password)
				return
			}
		}
	}

	if authFlowRequest.Provider == CodeProvider {
		switch authFlowRequest.Step {
		case "start":
			if authFlowRequest.CodeStart != nil {
				s.startCode(w, req, flow, authFlowRequest.CodeStart)
				return
			}
		case "complete":
			if authFlowRequest.CodeComplete != nil {
				s.completeCode(w, req, flow, authFlowRequest.CodeComplete)
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
			Passkey:  nil,
			Password: nil,
			Code:     false,
		}, nil)
	} else {
		s.TemporaryRedirectGetMethod(w, req, flow.Target)
	}
}
