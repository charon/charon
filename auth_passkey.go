package charon

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog/hlog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
)

const defaultPasskeyTimeout = 60 * time.Second

type charonUser struct {
	Credentials []webauthn.Credential
}

func (*charonUser) WebAuthnID() []byte {
	return []byte{0}
}

func (*charonUser) WebAuthnName() string {
	return "charon-passkey"
}

func (*charonUser) WebAuthnDisplayName() string {
	return "Charon passkey"
}

func (*charonUser) WebAuthnIcon() string {
	return ""
}

func (u *charonUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func withWebauthnError(err error) errors.E {
	errE := errors.WithStack(err)
	var e *protocol.Error
	if errors.As(err, &e) {
		if e.Type != "" {
			errors.Details(errE)["type"] = e.Type
		}
		if e.DevInfo != "" {
			errors.Details(errE)["debug"] = e.DevInfo
		}
	}
	return errE
}

func WithPreferredCredentialAlgorithms(preferredAlgorithms []webauthncose.COSEAlgorithmIdentifier) webauthn.RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		credentialParameters := []protocol.CredentialParameter{}
		// We first add preferred algorithms.
		for _, alg := range preferredAlgorithms {
			credentialParameters = append(credentialParameters, protocol.CredentialParameter{
				Type:      protocol.PublicKeyCredentialType,
				Algorithm: alg,
			})
		}
		// Then we copy others.
		for _, parameter := range cco.Parameters {
			// We skip preferred algorithms.
			if slices.Contains(preferredAlgorithms, parameter.Algorithm) {
				continue
			}
			credentialParameters = append(credentialParameters, parameter)
		}
		cco.Parameters = credentialParameters
	}
}

func initPasskeyProvider(app *App, domain string) func() *webauthn.WebAuthn {
	return func() *webauthn.WebAuthn {
		host, errE := getHost(app, domain)
		if errE != nil {
			panic(errE)
		}
		if host == "" {
			// Server failed to start. We just return in this case.
			return nil
		}
		origin := fmt.Sprintf("https://%s", host)
		wconfig := &webauthn.Config{ //nolint:exhaustruct
			RPDisplayName:         "Charon",
			RPID:                  domain,
			RPOrigins:             []string{origin},
			AttestationPreference: protocol.PreferNoAttestation,
			Timeouts: webauthn.TimeoutsConfig{
				Login: webauthn.TimeoutConfig{
					Enforce:    false,
					Timeout:    defaultPasskeyTimeout,
					TimeoutUVD: defaultPasskeyTimeout,
				},
				Registration: webauthn.TimeoutConfig{
					Enforce:    false,
					Timeout:    defaultPasskeyTimeout,
					TimeoutUVD: defaultPasskeyTimeout,
				},
			},
		}

		webAuthn, err := webauthn.New(wconfig)
		if err != nil {
			panic(withWebauthnError(err))
		}
		return webAuthn
	}
}

func (s *Service) startPasskeyGet(w http.ResponseWriter, req *http.Request, flow *Flow) {
	options, session, err := s.passkeyProvider().BeginDiscoverableLogin()
	if err != nil {
		s.InternalServerErrorWithError(w, req, withWebauthnError(err))
		return
	}

	// TODO: What if flow.Passkey is already set?
	flow.Passkey = session
	errE := SetFlow(req.Context(), flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Location: nil,
		Passkey: &AuthFlowResponsePasskey{
			CreateOptions: nil,
			GetOptions:    options,
		},
	}, nil)
}

func (s *Service) getFlowPasskey(w http.ResponseWriter, req *http.Request, flow *Flow) *webauthn.SessionData {
	if flow.Passkey == nil {
		s.BadRequestWithError(w, req, errors.New("passkey not started"))
		return nil
	}

	flowPasskey := flow.Passkey

	// We reset flow.Passkey to nil always after this point, even if there is a failure,
	// so that challenge cannot be reused.
	flow.Passkey = nil
	errE := SetFlow(req.Context(), flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}

	return flowPasskey
}

func (s *Service) completePasskeyGet(w http.ResponseWriter, req *http.Request, flow *Flow, requestPasskey *AuthFlowRequestPasskey) {
	if requestPasskey.GetResponse == nil {
		s.BadRequestWithError(w, req, errors.New("get response missing"))
		return
	}

	parsedResponse, err := requestPasskey.GetResponse.Parse()
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
	}

	flowPasskey := s.getFlowPasskey(w, req, flow)
	if flowPasskey == nil {
		return
	}

	credential, err := s.passkeyProvider().ValidateDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		id := base64.RawURLEncoding.EncodeToString(rawID)
		account, errE := GetAccountByCredential(req.Context(), "passkey", id)
		if errE != nil {
			return nil, errE
		}
		var c webauthn.Credential
		errE = x.Unmarshal(account.GetCredential("passkey", id).Data, &c)
		if errE != nil {
			return nil, errE
		}
		return &charonUser{
			Credentials: []webauthn.Credential{c},
		}, nil
	}, *flowPasskey, parsedResponse)
	if err != nil {
		s.BadRequestWithError(w, req, withWebauthnError(err))
		return
	}

	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)

	if credential.Authenticator.CloneWarning {
		hlog.FromRequest(req).Warn().Str("credential", credentialID).Msg("authenticator may be cloned")
	}

	// TODO: Have camelCase json field names.
	//       See: https://github.com/go-webauthn/webauthn/issues/193
	jsonData, errE := x.MarshalWithoutEscapeHTML(credential)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.completeAuthStep(w, req, true, flow, "passkey", credentialID, jsonData)
}

func (s *Service) startPasskeyCreate(w http.ResponseWriter, req *http.Request, flow *Flow) {
	options, session, err := s.passkeyProvider().BeginRegistration(
		&charonUser{nil},
		webauthn.WithExtensions(protocol.AuthenticationExtensions{
			"credentialProtectionPolicy": "userVerificationOptional",
		}),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: "",
			RequireResidentKey:      protocol.ResidentKeyRequired(),
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			UserVerification:        protocol.VerificationDiscouraged,
		}),
		WithPreferredCredentialAlgorithms([]webauthncose.COSEAlgorithmIdentifier{
			webauthncose.AlgEdDSA,
			webauthncose.AlgES256,
			webauthncose.AlgRS256,
		}),
	)
	if err != nil {
		s.InternalServerErrorWithError(w, req, withWebauthnError(err))
		return
	}

	// TODO: What if flow.Passkey is already set?
	flow.Passkey = session
	errE := SetFlow(req.Context(), flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Location: nil,
		Passkey: &AuthFlowResponsePasskey{
			CreateOptions: options,
			GetOptions:    nil,
		},
	}, nil)
}

func (s *Service) completePasskeyCreate(w http.ResponseWriter, req *http.Request, flow *Flow, requestPasskey *AuthFlowRequestPasskey) {
	if requestPasskey.CreateResponse == nil {
		s.BadRequestWithError(w, req, errors.New("create response missing"))
		return
	}

	parsedResponse, err := requestPasskey.CreateResponse.Parse()
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
	}

	flowPasskey := s.getFlowPasskey(w, req, flow)
	if flowPasskey == nil {
		return
	}

	credential, err := s.passkeyProvider().CreateCredential(&charonUser{nil}, *flowPasskey, parsedResponse)
	if err != nil {
		s.BadRequestWithError(w, req, withWebauthnError(err))
		return
	}

	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)

	// TODO: Have camelCase json field names.
	//       See: https://github.com/go-webauthn/webauthn/issues/193
	jsonData, errE := x.MarshalWithoutEscapeHTML(credential)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.completeAuthStep(w, req, true, flow, "passkey", credentialID, jsonData)
}
