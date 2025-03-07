package charon

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/automattic/go-gravatar"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

const (
	MaxAuthAttempts = 10
)

type AuthFlowResponse struct {
	Completed []Completed `json:"completed"`

	OrganizationID identifier.Identifier `json:"organizationId"`
	AppID          identifier.Identifier `json:"appId"`

	Providers       []Provider                    `json:"providers,omitempty"`
	EmailOrUsername string                        `json:"emailOrUsername,omitempty"`
	OIDCProvider    *AuthFlowResponseOIDCProvider `json:"oidcProvider,omitempty"`
	Passkey         *AuthFlowResponsePasskey      `json:"passkey,omitempty"`
	Password        *AuthFlowResponsePassword     `json:"password,omitempty"`

	Error ErrorCode `json:"error,omitempty"`
}

type ErrorCode string

const (
	ErrorCodeWrongPassword          ErrorCode = "wrongPassword"
	ErrorCodeNoEmails               ErrorCode = "noEmails"
	ErrorCodeNoAccount              ErrorCode = "noAccount"
	ErrorCodeInvalidCode            ErrorCode = "invalidCode"
	ErrorCodeInvalidEmailOrUsername ErrorCode = "invalidEmailOrUsername"
	ErrorCodeShortEmailOrUsername   ErrorCode = "shortEmailOrUsername"
	ErrorCodeInvalidPassword        ErrorCode = "invalidPassword"
	ErrorCodeShortPassword          ErrorCode = "shortPassword"
)

func (s *Service) flowError(w http.ResponseWriter, req *http.Request, flow *Flow, errorCode ErrorCode, failureErr errors.E) {
	ctx := req.Context()

	if failureErr == nil {
		failureErr = errors.New("flow error")
	}
	errors.Details(failureErr)["code"] = errorCode
	s.WithError(ctx, failureErr)

	response := AuthFlowResponse{
		Completed:       flow.Completed,
		OrganizationID:  flow.OrganizationID,
		AppID:           flow.AppID,
		Providers:       flow.Providers,
		EmailOrUsername: "",
		OIDCProvider:    nil,
		Passkey:         nil,
		Password:        nil,
		Error:           errorCode,
	}

	encoded := s.PrepareJSON(w, req, response, nil)
	if encoded == nil {
		return
	}

	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(encoded)
}

func (s *Service) AuthFlowGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	flow := s.GetFlowHandler(w, req, params["id"])
	if flow == nil {
		return
	}

	// Is the flow ready for a redirect to the OIDC client?
	if flow.IsFinishReady() && s.completeOIDCAuthorize(w, req, flow) {
		return
	}

	l, errE := s.ReverseAPI("AuthFlowGet", waf.Params{"id": flow.ID.String()}, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// We have it hard-coded here because we have it hard-coded on the frontend as well.
	w.Header().Add("Link", "</context.json>; rel=preload; as=fetch; crossorigin=anonymous")
	w.Header().Add("Link", fmt.Sprintf("<%s>; rel=preload; as=fetch; crossorigin=anonymous", l))
	w.WriteHeader(http.StatusEarlyHints)

	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) AuthFlowGetGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	// This is similar to API case in failAuthStep, but fetches also the flow and checks the session.

	flow := s.GetFlowHandler(w, req, params["id"])
	if flow == nil {
		return
	}

	response := AuthFlowResponse{
		Completed:       flow.Completed,
		OrganizationID:  flow.OrganizationID,
		AppID:           flow.AppID,
		Providers:       flow.Providers,
		EmailOrUsername: flow.EmailOrUsername,
		OIDCProvider:    nil,
		Passkey:         nil,
		Password:        nil,
		Error:           "",
	}

	// If auth step was successful (session is not nil), then we require that the session matches the one made by the flow.
	if flow.SessionID != nil {
		if _, handled := s.validateSession(w, req, true, flow); handled {
			return
		}
	}

	s.WriteJSON(w, req, response, nil)
}

func (s *Service) makeIdentityFromCredentials(credentials []Credential) (*Identity, errors.E) {
	var identity *Identity
	for _, credential := range credentials {
		switch credential.Provider {
		case CodeProvider:
			return nil, errors.New("code provider among credentials")
		case PasskeyProvider:
			// Nothing available.
		case PasswordProvider:
			// Nothing available.
		case EmailProvider:
			var c emailCredential
			errE := x.UnmarshalWithoutUnknownFields(credential.Data, &c)
			if errE != nil {
				return nil, errE
			}
			if identity == nil {
				identity = new(Identity)
			}
			identity.Email = c.Email
		case UsernameProvider:
			var c usernameCredential
			errE := x.UnmarshalWithoutUnknownFields(credential.Data, &c)
			if errE != nil {
				return nil, errE
			}
			if identity == nil {
				identity = new(Identity)
			}
			identity.Username = c.Username
		default:
			var token map[string]interface{}
			errE := x.UnmarshalWithoutUnknownFields(credential.Data, &token)
			if errE != nil {
				return nil, errE
			}
			if identity == nil {
				identity = new(Identity)
			}
			givenName, _ := token["given_name"].(string)
			if givenName != "" {
				identity.GivenName = givenName
			}
			name, _ := token["name"].(string)
			if name != "" {
				identity.FullName = name
			} else {
				familyName, _ := token["family_name"].(string)
				if givenName != "" && familyName != "" {
					identity.FullName = fmt.Sprintf("%s %s", givenName, familyName)
				}
			}
			picture, _ := token["picture"].(string)
			if picture != "" {
				identity.PictureURL = picture
			}
			email, _ := token["email"].(string)
			if email != "" {
				// TODO: We should verify the e-mail.
				identity.Email = email
			}
			username, _ := token["preferred_username"].(string)
			if username != "" {
				identity.Username = username
			}
			identity.Description = fmt.Sprintf("Identity automatically imported from %s.", s.oidcProviders()[credential.Provider].Name)
		}
	}
	if identity != nil {
		if identity.Username == "" && identity.Email != "" {
			identity.Username, _, _ = strings.Cut(identity.Email, "@")
		}
		if identity.PictureURL == "" && identity.Email != "" {
			// TODO: Generate some local picture and do not use remote Gravatar.
			g := gravatar.NewGravatarFromEmail(identity.Email)
			g.Default = "identicon"
			identity.PictureURL = g.GetURL()
		}
		if identity.PictureURL == "" && identity.Username != "" {
			// TODO: Generate some local picture and do not misuse username for Gravatar.
			g := gravatar.NewGravatarFromEmail(identity.Username)
			g.Default = "identicon"
			identity.PictureURL = g.GetURL()
		}
	}
	return identity, nil
}

func (s *Service) completeAuthStep(w http.ResponseWriter, req *http.Request, api bool, flow *Flow, account *Account, credentials []Credential) {
	ctx := req.Context()

	if account == nil {
		// Sign-up. Create new account.
		errE := flow.AddCompleted(CompletedSignup)
		if errE != nil {
			s.BadRequestWithError(w, req, errE)
			return
		}

		account = &Account{
			ID:          identifier.New(),
			Credentials: map[Provider][]Credential{},
		}
		for _, credential := range credentials {
			account.Credentials[credential.Provider] = append(account.Credentials[credential.Provider], credential)
		}
		errE = s.setAccount(ctx, account)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		identity, errE := s.makeIdentityFromCredentials(credentials)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		// From some credentials it is not possible to make an identity.
		if identity != nil {
			// We do not set identityIDContextKey because we are creating a new identity for the current
			// account while using a session cookie. The identity itself will be used instead.
			errE = s.createIdentity(context.WithValue(ctx, accountIDContextKey, account.ID), identity)
			if errE != nil && !errors.Is(errE, errEmptyIdentity) {
				s.InternalServerErrorWithError(w, req, errE)
				return
			}
		}
	} else {
		// Sign-in. Update credentials for an existing account.
		errE := flow.AddCompleted(CompletedSignin)
		if errE != nil {
			s.BadRequestWithError(w, req, errE)
			return
		}

		// TODO: Updating only if credentials (meaningfully) changed.
		// TODO: Update in a way which does not preserve history.
		account.UpdateCredentials(credentials)
		errE = s.setAccount(ctx, account)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
	}

	token, signature, err := s.hmac.Generate(ctx)
	if err != nil {
		s.InternalServerErrorWithError(w, req, withFositeError(err))
		return
	}

	secretID, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		// Internal error: this should never happen.
		panic(errors.WithStack(err))
	}

	sessionID := identifier.New()
	now := time.Now().UTC()
	errE := s.setSession(ctx, &Session{
		ID:        sessionID,
		CreatedAt: now,
		SecretID:  [32]byte(secretID),
		AccountID: account.ID,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	flow.SessionID = &sessionID
	flow.AuthTime = &now

	// Everything should already be set to nil at this point, but just to make sure.
	flow.ClearAuthStepAll()

	errE = s.SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	cookie := http.Cookie{ //nolint:exhaustruct
		Name:     SessionCookiePrefix + flow.ID.String(),
		Value:    SecretPrefixSession + token,
		Path:     "/", // Host cookies have to have path set to "/".
		Domain:   "",
		Expires:  time.Now().Add(sessionExpiration),
		MaxAge:   0,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	if api {
		response := AuthFlowResponse{
			Completed:       flow.Completed,
			OrganizationID:  flow.OrganizationID,
			AppID:           flow.AppID,
			Providers:       flow.Providers,
			EmailOrUsername: flow.EmailOrUsername,
			OIDCProvider:    nil,
			Passkey:         nil,
			Password:        nil,
			Error:           "",
		}

		s.WriteJSON(w, req, response, nil)
		return
	}

	// We redirect back to the flow where the frontend continues with choosing the identity.
	l, errE := s.Reverse("AuthFlowGet", waf.Params{"id": flow.ID.String()}, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	s.TemporaryRedirectGetMethod(w, req, l)
}

func (s *Service) increaseAuthAttempts(w http.ResponseWriter, req *http.Request, flow *Flow) bool {
	ctx := req.Context()

	flow.AuthAttempts++
	errE := s.SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return false
	}

	if flow.AuthAttempts >= MaxAuthAttempts {
		s.failAuthStep(w, req, true, flow, errors.New("reached max auth attempts"))
		return false
	}

	return true
}

func (s *Service) failAuthStep(w http.ResponseWriter, req *http.Request, api bool, flow *Flow, failureErr errors.E) {
	ctx := req.Context()

	errE := flow.AddCompleted(CompletedFailed)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	// Everything should already be set to nil at this point, but just to make sure.
	flow.ClearAuthStepAll()

	errE = s.SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WithError(ctx, failureErr)

	if api {
		// This is similar to AuthFlowGet, only without fetching the flow and checking the session.

		response := AuthFlowResponse{
			Completed:       flow.Completed,
			OrganizationID:  flow.OrganizationID,
			AppID:           flow.AppID,
			Providers:       flow.Providers,
			EmailOrUsername: flow.EmailOrUsername,
			OIDCProvider:    nil,
			Passkey:         nil,
			Password:        nil,
			Error:           "",
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
	l, errE := s.Reverse("AuthFlowGet", waf.Params{"id": flow.ID.String()}, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	s.TemporaryRedirectGetMethod(w, req, l)
}

func (s *Service) AuthFlowRestartAuthPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	// Restarting is possible after successful auth step but it is not possible anymore after redirect
	// (after the flow has finished) which is checked in GetActiveFlowWithSession.
	_, flow := s.GetActiveFlowWithSession(w, req, params["id"])
	if flow == nil {
		return
	}

	var ea emptyRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &ea)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	flow.Completed = []Completed{}
	flow.SessionID = nil
	flow.Identity = nil
	flow.Providers = nil

	// We clear everything else as well.
	flow.ClearAuthStepAll()

	// We do not clear flow.AuthAttempts because otherwise somebody with an account on the
	// system could try up to MaxAuthAttempts - 1, then sign in, then restart, and repeat
	// attempts. We want them to fail the whole flow and to have to restart it (it is easier
	// to count failed flows and detect attacks this way).

	errE = s.SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// We clear the session cookie. It might otherwise be a surprise to the user that they
	// restarted auth but still stay signed in if they do not complete new authentication.
	// It is better that they have to sign in again.
	cookie := http.Cookie{ //nolint:exhaustruct
		Name:     SessionCookiePrefix + flow.ID.String(),
		Value:    "",
		Path:     "/",
		Domain:   "",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	s.WriteJSON(w, req, AuthFlowResponse{
		Completed:       flow.Completed,
		OrganizationID:  flow.OrganizationID,
		AppID:           flow.AppID,
		Providers:       flow.Providers,
		EmailOrUsername: flow.EmailOrUsername,
		OIDCProvider:    nil,
		Passkey:         nil,
		Password:        nil,
		Error:           "",
	}, nil)
}

func (s *Service) AuthFlowDeclinePost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	_, flow := s.GetActiveFlowWithSession(w, req, params["id"])
	if flow == nil {
		return
	}

	var ea emptyRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &ea)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = flow.AddCompleted(CompletedDeclined)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	// TODO: Store decline in a way that it is persisted in a similar way that choosing an identity is.

	errE = s.SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Completed:       flow.Completed,
		OrganizationID:  flow.OrganizationID,
		AppID:           flow.AppID,
		Providers:       flow.Providers,
		EmailOrUsername: flow.EmailOrUsername,
		OIDCProvider:    nil,
		Passkey:         nil,
		Password:        nil,
		Error:           "",
	}, nil)
}

type AuthFlowChooseIdentityRequest struct {
	Identity IdentityRef `json:"identity"`
}

func (s *Service) AuthFlowChooseIdentityPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	accountID, flow := s.GetActiveFlowWithSession(w, req, params["id"])
	if flow == nil {
		return
	}

	var chooseIdentity AuthFlowChooseIdentityRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &chooseIdentity)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = flow.AddCompleted(CompletedIdentity)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	c := context.WithValue(ctx, accountIDContextKey, accountID)
	c = context.WithValue(c, identityIDContextKey, chooseIdentity.Identity.ID)

	identity, errE := s.selectAndActivateIdentity(c, chooseIdentity.Identity.ID, flow.OrganizationID)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	flow.Identity = identity

	errE = s.SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Completed:       flow.Completed,
		OrganizationID:  flow.OrganizationID,
		AppID:           flow.AppID,
		Providers:       flow.Providers,
		EmailOrUsername: flow.EmailOrUsername,
		OIDCProvider:    nil,
		Passkey:         nil,
		Password:        nil,
		Error:           "",
	}, nil)
}

func (s *Service) AuthFlowRedirectPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	flow := s.GetActiveFlow(w, req, params["id"])
	if flow == nil {
		return
	}

	// If auth step was successful (session is not nil), then we require that the session matches the one made by the flow.
	if flow.SessionID != nil {
		if _, handled := s.validateSession(w, req, true, flow); handled {
			return
		}
	}

	errE := flow.AddCompleted(CompletedFinishReady)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	var ea emptyRequest
	errE = x.DecodeJSONWithoutUnknownFields(req.Body, &ea)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = s.SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Completed:       flow.Completed,
		OrganizationID:  flow.OrganizationID,
		AppID:           flow.AppID,
		Providers:       flow.Providers,
		EmailOrUsername: flow.EmailOrUsername,
		OIDCProvider:    nil,
		Passkey:         nil,
		Password:        nil,
		Error:           "",
	}, nil)
}
