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
	// userID is the same as the public credential ID so we do not need to store it.
	userID identifier.Identifier

	// displayName is the same as the display name of the credential so we do not need to store it.
	displayName string

	Credential *webauthn.Credential `json:"credential"`
}

func (c passkeyCredential) WebAuthnID() []byte {
	return c.userID[:]
}

func (c passkeyCredential) WebAuthnName() string {
	return c.WebAuthnDisplayName()
}

func (c passkeyCredential) WebAuthnDisplayName() string {
	return fmt.Sprintf("Charon (%s)", c.displayName)
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
	flow.Passkey = &flowPasskey{
		SessionData: session,
		// We mark the request as sign-in.
		DisplayName: "",
	}
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
		Password:      nil,
		Error:         "",
		SignalUnknown: nil,
	}, nil)
}

func (s *Service) getFlowPasskey(w http.ResponseWriter, req *http.Request, flow *flow) *flowPasskey {
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

	if flowPasskey.DisplayName != "" {
		s.BadRequestWithError(w, req, errors.New("not a sign-in request"))
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

	var storedCredential *Credential
	var account *Account
	user, newWebAuthnCredential, err := s.passkeyProvider().ValidatePasskeyLogin(func(rawCredentialID, _ []byte) (webauthn.User, error) {
		// We use credential ID as provider ID.
		providerID := base64.RawURLEncoding.EncodeToString(rawCredentialID)
		account, errE = s.getAccountByCredential(ctx, ProviderPasskey, providerID)
		if errE != nil {
			return nil, errE
		}
		var pkCredential passkeyCredential
		// This cannot return nil because we just got the account by matching the provider ID.
		storedCredential = account.GetCredential(ProviderPasskey, providerID)
		errE = x.Unmarshal(storedCredential.Data, &pkCredential)
		if errE != nil {
			return nil, errE
		}
		pkCredential.userID = storedCredential.ID
		pkCredential.displayName = storedCredential.DisplayName
		return pkCredential, nil
	}, *flowPasskey.SessionData, parsedResponse)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			signalUnknown := s.getPasskeySignalUnknownData(parsedResponse.RawID)
			s.flowError(w, req, flow, ErrorCodeNoAccount, nil, signalUnknown)
			return
		}
		s.BadRequestWithError(w, req, withWebauthnError(err))
		return
	}

	// We know the user is passkeyCredential because we just created it above.
	pkCredential := user.(passkeyCredential) //nolint:errcheck,forcetypeassert
	// Credential is changed by ValidatePasskeyLogin (e.g., its Authenticator.UpdateCounter
	// is called to update its sign count) so we set it back here.
	pkCredential.Credential = newWebAuthnCredential

	newProviderID := base64.RawURLEncoding.EncodeToString(pkCredential.Credential.ID)
	if storedCredential.ProviderID != newProviderID {
		errE := errors.New("provider ID changed")
		errors.Details(errE)["existing"] = storedCredential.ProviderID
		errors.Details(errE)["new"] = newProviderID
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if pkCredential.Credential.Authenticator.CloneWarning {
		zerolog.Ctx(ctx).Warn().Str("providerID", storedCredential.ProviderID).Msg("authenticator may be cloned")
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(pkCredential)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.completeAuthStep(w, req, true, flow, account,
		[]Credential{{
			CredentialPublic: CredentialPublic{
				ID:          storedCredential.ID,
				Provider:    ProviderPasskey,
				DisplayName: storedCredential.DisplayName,
				Verified:    false,
			},
			ProviderID: storedCredential.ProviderID,
			Data:       jsonData,
		}},
	)
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

	// User ID also serves as public credential ID once stored in the database.
	userID := identifier.New()
	displayName := userID.String()
	options, session, errE := beginPasskeyRegistration(s.passkeyProvider(), userID, displayName)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	flow.ClearAuthStep("")
	// Currently we support only one factor.
	flow.Providers = []Provider{ProviderPasskey}
	flow.Passkey = &flowPasskey{
		SessionData: session,
		// We mark the request as sign-up.
		DisplayName: displayName,
	}
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
		Password:      nil,
		Error:         "",
		SignalUnknown: nil,
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

	if flowPasskey.DisplayName == "" {
		s.BadRequestWithError(w, req, errors.New("not a sign-up request"))
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

	credential, providerID, errE := s.completePasskeyRegistration(createResponse, flowPasskey.DisplayName, flowPasskey.SessionData)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(credential)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	account, errE := s.getAccountByCredential(ctx, ProviderPasskey, providerID)
	if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.completeAuthStep(w, req, true, flow, account,
		[]Credential{{
			CredentialPublic: CredentialPublic{
				// User ID also serves as public credential ID.
				ID:          credential.userID,
				Provider:    ProviderPasskey,
				DisplayName: flowPasskey.DisplayName,
				Verified:    false,
			},
			ProviderID: providerID,
			Data:       jsonData,
		}})
}

func (s *Service) getPasskeySignalData(credential Credential, updatedDisplayName string) (*SignalCurrentUserDetails, errors.E) {
	var pk passkeyCredential
	errE := x.UnmarshalWithoutUnknownFields(credential.Data, &pk)
	if errE != nil {
		errors.Details(errE)["id"] = credential.ID
		return nil, errE
	}

	pk.userID = credential.ID
	pk.displayName = updatedDisplayName

	return &SignalCurrentUserDetails{
		RPID:        s.passkeyProvider().Config.RPID,
		UserID:      pk.WebAuthnID(),
		Name:        pk.WebAuthnName(),
		DisplayName: pk.WebAuthnDisplayName(),
	}, nil
}

func (s *Service) getPasskeySignalUnknownData(credentialID []byte) *SignalUnknownCredential {
	return &SignalUnknownCredential{
		RPID:         s.passkeyProvider().Config.RPID,
		CredentialID: credentialID,
	}
}
