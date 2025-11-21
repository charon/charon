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
	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

//nolint:revive
const ProviderPasskey Provider = "passkey"

// AuthFlowResponsePasskey represents response data of the passkey provider step, sign-in (get) or sign-up (create).
type AuthFlowResponsePasskey struct {
	CreateOptions *protocol.CredentialCreation  `json:"createOptions,omitempty"`
	GetOptions    *protocol.CredentialAssertion `json:"getOptions,omitempty"`
}

const defaultPasskeyTimeout = 60 * time.Second

type passkeyCredential struct {
	ID         identifier.Identifier `json:"id"`
	Label      string                `json:"label"`
	Credential *webauthn.Credential  `json:"credential"`
}

func (c passkeyCredential) WebAuthnID() []byte {
	return c.ID[:]
}

func (c passkeyCredential) WebAuthnName() string {
	return c.WebAuthnDisplayName()
}

func (c passkeyCredential) WebAuthnDisplayName() string {
	return fmt.Sprintf("Charon (%s)", c.Label)
}

func (passkeyCredential) WebAuthnIcon() string {
	return ""
}

func (c passkeyCredential) WebAuthnCredentials() []webauthn.Credential {
	if c.Credential != nil {
		return []webauthn.Credential{*c.Credential}
	}
	return nil
}

func withPreferredCredentialAlgorithms(preferredAlgorithms []webauthncose.COSEAlgorithmIdentifier) webauthn.RegistrationOption {
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

func initPasskeyProvider(config *Config, domain string) (func() *webauthn.WebAuthn, errors.E) {
	return initWithHost(config, domain, func(host string) *webauthn.WebAuthn {
		origin := "https://" + host
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
			// Internal error: this should never happen.
			panic(withWebauthnError(err))
		}
		return webAuthn
	})
}

// AuthFlowPasskeyGetStartPost is the API handler to start the passkey provider step (sign-in), POST request.
func (s *Service) AuthFlowPasskeyGetStartPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	flow := s.getActiveFlowNoAuthStep(w, req, params["id"])
	if flow == nil {
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
	// Currently we support only one factor.
	flow.Providers = []Provider{ProviderPasskey}
	flow.Passkey = session
	errE = s.setFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Completed:          flow.Completed,
		OrganizationID:     flow.OrganizationID,
		AppID:              flow.AppID,
		Providers:          flow.Providers,
		EmailOrUsername:    flow.EmailOrUsername,
		ThirdPartyProvider: nil,
		Passkey: &AuthFlowResponsePasskey{
			CreateOptions: nil,
			GetOptions:    options,
		},
		Password: nil,
		Error:    "",
	}, nil)
}

func (s *Service) getFlowPasskey(w http.ResponseWriter, req *http.Request, flow *flow) *webauthn.SessionData {
	if flow.Passkey == nil {
		s.BadRequestWithError(w, req, errors.New("passkey not started"))
		return nil
	}

	flowPasskey := flow.Passkey

	// We reset flow.Passkey to nil always after this point, even if there is a failure,
	// so that challenge cannot be reused.
	flow.Passkey = nil
	errE := s.setFlow(req.Context(), flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}

	return flowPasskey
}

// AuthFlowPasskeyGetCompleteRequest represents the request body for the AuthFlowPasskeyGetCompletePost handler.
type AuthFlowPasskeyGetCompleteRequest struct {
	GetResponse protocol.CredentialAssertionResponse `json:"getResponse"`
}

// AuthFlowPasskeyGetCompletePost is the API handler to complete the passkey provider step (sign-in), POST request.
func (s *Service) AuthFlowPasskeyGetCompletePost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	flow := s.getActiveFlowNoAuthStep(w, req, params["id"])
	if flow == nil {
		return
	}

	flowPasskey := s.getFlowPasskey(w, req, flow)
	if flowPasskey == nil {
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

	parsedResponse, err := assertionResponse.Parse()
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	user, newCredential, err := s.passkeyProvider().ValidatePasskeyLogin(func(rawID, _ []byte) (webauthn.User, error) {
		id := base64.RawURLEncoding.EncodeToString(rawID)
		account, errE := s.getAccountByCredential(ctx, ProviderPasskey, id)
		if errE != nil {
			return nil, errE
		}
		var credential passkeyCredential
		errE = x.Unmarshal(account.GetCredential(ProviderPasskey, id).Data, &credential)
		if errE != nil {
			return nil, errE
		}
		return credential, nil
	}, *flowPasskey, parsedResponse)
	if err != nil {
		s.BadRequestWithError(w, req, withWebauthnError(err))
		return
	}

	// We know the user is passkeyCredential because we just created it above.
	credential := user.(passkeyCredential) //nolint:errcheck,forcetypeassert
	// Credential is changed by ValidatePasskeyLogin (e.g., its Authenticator.UpdateCounter
	// is called to update its sign count) so we set it back here.
	credential.Credential = newCredential

	credentialID := base64.RawURLEncoding.EncodeToString(credential.Credential.ID)

	if credential.Credential.Authenticator.CloneWarning {
		zerolog.Ctx(ctx).Warn().Str("credential", credentialID).Msg("authenticator may be cloned")
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(credential)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	account, errE := s.getAccountByCredential(ctx, ProviderPasskey, credentialID)
	if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.completeAuthStep(w, req, true, flow, account, []Credential{{ID: credentialID, Provider: ProviderPasskey, Data: jsonData}})
}

// AuthFlowPasskeyCreateStartPost is the API handler to start the passkey provider step (sign-up), POST request.
func (s *Service) AuthFlowPasskeyCreateStartPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	flow := s.getActiveFlowNoAuthStep(w, req, params["id"])
	if flow == nil {
		return
	}

	var ea emptyRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &ea)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	userID := identifier.New()

	options, session, err := s.passkeyProvider().BeginRegistration(
		passkeyCredential{
			ID:         userID,
			Label:      userID.String(),
			Credential: nil,
		},
		webauthn.WithExtensions(protocol.AuthenticationExtensions{
			"credentialProtectionPolicy":        "userVerificationRequired",
			"enforceCredentialProtectionPolicy": false,
		}),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: "",
			RequireResidentKey:      protocol.ResidentKeyRequired(),
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			UserVerification:        protocol.VerificationRequired,
		}),
		withPreferredCredentialAlgorithms([]webauthncose.COSEAlgorithmIdentifier{
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
	// Currently we support only one factor.
	flow.Providers = []Provider{ProviderPasskey}
	flow.Passkey = session
	errE = s.setFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Completed:          flow.Completed,
		OrganizationID:     flow.OrganizationID,
		AppID:              flow.AppID,
		Providers:          flow.Providers,
		EmailOrUsername:    flow.EmailOrUsername,
		ThirdPartyProvider: nil,
		Passkey: &AuthFlowResponsePasskey{
			CreateOptions: options,
			GetOptions:    nil,
		},
		Password: nil,
		Error:    "",
	}, nil)
}

// AuthFlowPasskeyCreateCompleteRequest represents the request body for the AuthFlowPasskeyCreateCompletePost handler.
type AuthFlowPasskeyCreateCompleteRequest struct {
	CreateResponse protocol.CredentialCreationResponse `json:"createResponse"`
}

// AuthFlowPasskeyCreateCompletePost is the API handler to complete the passkey provider step (sign-up), POST request.
func (s *Service) AuthFlowPasskeyCreateCompletePost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	flow := s.getActiveFlowNoAuthStep(w, req, params["id"])
	if flow == nil {
		return
	}

	flowPasskey := s.getFlowPasskey(w, req, flow)
	if flowPasskey == nil {
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
		return
	}

	userID := identifier.Data([16]byte(flowPasskey.UserID))

	credential := passkeyCredential{
		ID:         userID,
		Label:      userID.String(),
		Credential: nil,
	}

	credential.Credential, err = s.passkeyProvider().CreateCredential(credential, *flowPasskey, parsedResponse)
	if err != nil {
		s.BadRequestWithError(w, req, withWebauthnError(err))
		return
	}

	credentialID := base64.RawURLEncoding.EncodeToString(credential.Credential.ID)

	jsonData, errE := x.MarshalWithoutEscapeHTML(credential)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	account, errE := s.getAccountByCredential(ctx, ProviderPasskey, credentialID)
	if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.completeAuthStep(w, req, true, flow, account, []Credential{{ID: credentialID, Provider: ProviderPasskey, Data: jsonData}})
}
