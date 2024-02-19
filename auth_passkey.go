package charon

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog/hlog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/waf"
)

const PasskeyProvider Provider = "passkey"

type AuthFlowResponsePasskey struct {
	CreateOptions *protocol.CredentialCreation  `json:"createOptions,omitempty"`
	GetOptions    *protocol.CredentialAssertion `json:"getOptions,omitempty"`
}

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

func initPasskeyProvider(config *Config, domain string) func() *webauthn.WebAuthn {
	return func() *webauthn.WebAuthn {
		host, errE := getHost(config, domain)
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

func (s *Service) AuthFlowPasskeyGetStartPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	flow := s.GetFlow(w, req, params["id"])
	if flow == nil {
		return
	}

	// Has flow already completed?
	if flow.IsCompleted() {
		waf.Error(w, req, http.StatusGone)
		return
	}

	// Has auth step already been completed?
	if flow.Completed != "" {
		s.BadRequestWithError(w, req, errors.New("auth step already completed"))
		return
	}

	var ea emptyRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &ea)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	options, session, err := s.passkeyProvider().BeginDiscoverableLogin()
	if err != nil {
		s.InternalServerErrorWithError(w, req, withWebauthnError(err))
		return
	}

	flow.ClearAuthStep("")
	flow.Provider = PasskeyProvider
	flow.Passkey = session
	errE = SetFlow(req.Context(), flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Target:          flow.Target,
		Name:            flow.TargetName,
		Homepage:        flow.GetTargetHomepage(),
		OrganizationID:  flow.GetTargetOrganization(),
		Provider:        flow.Provider,
		EmailOrUsername: flow.EmailOrUsername,
		Error:           "",
		Completed:       "",
		Location:        nil,
		Passkey: &AuthFlowResponsePasskey{
			CreateOptions: nil,
			GetOptions:    options,
		},
		Password: nil,
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

type AuthFlowPasskeyGetCompleteRequest struct {
	GetResponse protocol.CredentialAssertionResponse `json:"getResponse"`
}

func (s *Service) AuthFlowPasskeyGetCompletePost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	flow := s.GetFlow(w, req, params["id"])
	if flow == nil {
		return
	}

	// Has flow already completed?
	if flow.IsCompleted() {
		waf.Error(w, req, http.StatusGone)
		return
	}

	// Has auth step already been completed?
	if flow.Completed != "" {
		s.BadRequestWithError(w, req, errors.New("auth step already completed"))
		return
	}

	// We do not use DecodeJSONWithoutUnknownFields here because browsers
	// (might and do) send extra fields.
	// See: https://github.com/go-webauthn/webauthn/issues/221
	var passkeyGetComplete AuthFlowPasskeyGetCompleteRequest
	errE := x.DecodeJSON(req.Body, &passkeyGetComplete)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	assertionResponse := passkeyGetComplete.GetResponse

	ctx := req.Context()

	flowPasskey := s.getFlowPasskey(w, req, flow)
	if flowPasskey == nil {
		return
	}

	parsedResponse, err := assertionResponse.Parse()
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
	}

	credential, err := s.passkeyProvider().ValidateDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		id := base64.RawURLEncoding.EncodeToString(rawID)
		account, errE := GetAccountByCredential(ctx, PasskeyProvider, id) //nolint:govet
		if errE != nil {
			return nil, errE
		}
		var c webauthn.Credential
		errE = x.Unmarshal(account.GetCredential(PasskeyProvider, id).Data, &c)
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

	jsonData, errE := x.MarshalWithoutEscapeHTML(credential)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	account, errE := GetAccountByCredential(ctx, PasskeyProvider, credentialID)
	if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.completeAuthStep(w, req, true, flow, account, []Credential{{ID: credentialID, Provider: PasskeyProvider, Data: jsonData}})
}

func (s *Service) AuthFlowPasskeyCreateStartPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	flow := s.GetFlow(w, req, params["id"])
	if flow == nil {
		return
	}

	// Has flow already completed?
	if flow.IsCompleted() {
		waf.Error(w, req, http.StatusGone)
		return
	}

	// Has auth step already been completed?
	if flow.Completed != "" {
		s.BadRequestWithError(w, req, errors.New("auth step already completed"))
		return
	}

	var ea emptyRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &ea)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

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

	flow.ClearAuthStep("")
	flow.Provider = PasskeyProvider
	flow.Passkey = session
	errE = SetFlow(req.Context(), flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Target:          flow.Target,
		Name:            flow.TargetName,
		Homepage:        flow.GetTargetHomepage(),
		OrganizationID:  flow.GetTargetOrganization(),
		Provider:        flow.Provider,
		EmailOrUsername: flow.EmailOrUsername,
		Error:           "",
		Completed:       "",
		Location:        nil,
		Passkey: &AuthFlowResponsePasskey{
			CreateOptions: options,
			GetOptions:    nil,
		},
		Password: nil,
	}, nil)
}

type AuthFlowPasskeyCreateCompleteRequest struct {
	CreateResponse protocol.CredentialCreationResponse `json:"createResponse"`
}

func (s *Service) AuthFlowPasskeyCreateCompletePost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	flow := s.GetFlow(w, req, params["id"])
	if flow == nil {
		return
	}

	// Has flow already completed?
	if flow.IsCompleted() {
		waf.Error(w, req, http.StatusGone)
		return
	}

	// Has auth step already been completed?
	if flow.Completed != "" {
		s.BadRequestWithError(w, req, errors.New("auth step already completed"))
		return
	}

	// We do not use DecodeJSONWithoutUnknownFields here because browsers
	// (might and do) send extra fields.
	// See: https://github.com/go-webauthn/webauthn/issues/221
	var passkeyCreateComplete AuthFlowPasskeyCreateCompleteRequest
	errE := x.DecodeJSON(req.Body, &passkeyCreateComplete)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	createResponse := passkeyCreateComplete.CreateResponse

	parsedResponse, err := createResponse.Parse()
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

	jsonData, errE := x.MarshalWithoutEscapeHTML(credential)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	account, errE := GetAccountByCredential(req.Context(), PasskeyProvider, credentialID)
	if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.completeAuthStep(w, req, true, flow, account, []Credential{{ID: credentialID, Provider: PasskeyProvider, Data: jsonData}})
}
