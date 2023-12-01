package charon

import (
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/waf"
)

const defaultPasskeyTimeout = 60 * time.Second

type charonUser struct{}

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

func (*charonUser) WebAuthnCredentials() []webauthn.Credential {
	return []webauthn.Credential{}
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

func initPasskey(app *App, domain string) func() *webauthn.WebAuthn {
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
		wconfig := &webauthn.Config{
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

func (s *Service) AuthPasskeySignin(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if !s.RequireActiveFlow(w, req, false) {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

type AuthPasskeySigninResponse struct {
	Options *protocol.CredentialAssertion `json:"options"`
}

func (s *Service) AuthPasskeySigninPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	flow := s.GetActiveFlow(w, req, true, FlowParameterName)
	if flow == nil {
		return
	}

	options, session, err := s.passkey().BeginDiscoverableLogin()
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

	s.WriteJSON(w, req, AuthPasskeySigninResponse{
		Options: options,
	}, nil)
}

func (s *Service) AuthPasskeySigninCompletePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	flow := s.GetActiveFlow(w, req, true, FlowParameterName)
	if flow == nil {
		return
	}

	if flow.Passkey == nil {
		s.BadRequestWithError(w, req, errors.New("passkey not started"))
		return
	}

	// TODO: Pass first argument.
	credential, err := s.passkey().FinishDiscoverableLogin(nil, *flow.Passkey, req)
	// We make sure the body is fully read and closed.
	// See: https://github.com/go-webauthn/webauthn/issues/189
	io.Copy(io.Discard, req.Body)
	req.Body.Close()
	if err != nil {
		s.BadRequestWithError(w, req, withWebauthnError(err))
		return
	}

	// TODO: Convert ID to a more reasonable string.
	s.completeAuthStep(w, req, flow, "passkey", string(credential.ID))
}

func (s *Service) AuthPasskeySignup(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if !s.RequireActiveFlow(w, req, false) {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

type AuthPasskeySignupResponse struct {
	Options *protocol.CredentialCreation `json:"options"`
}

func (s *Service) AuthPasskeySignupPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	flow := s.GetActiveFlow(w, req, true, FlowParameterName)
	if flow == nil {
		return
	}

	options, session, err := s.passkey().BeginRegistration(
		&charonUser{},
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

	s.WriteJSON(w, req, AuthPasskeySignupResponse{
		Options: options,
	}, nil)
}

func (s *Service) AuthPasskeySignupCompletePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	flow := s.GetActiveFlow(w, req, true, FlowParameterName)
	if flow == nil {
		return
	}

	if flow.Passkey == nil {
		s.BadRequestWithError(w, req, errors.New("passkey not started"))
		return
	}

	credential, err := s.passkey().FinishRegistration(&charonUser{}, *flow.Passkey, req)
	// We make sure the body is fully read and closed.
	// See: https://github.com/go-webauthn/webauthn/issues/189
	io.Copy(io.Discard, req.Body)
	req.Body.Close()
	if err != nil {
		s.BadRequestWithError(w, req, withWebauthnError(err))
		return
	}

	// TODO: Store whole credential?
	// TODO: Convert ID to a more reasonable string.
	s.completeAuthStep(w, req, flow, "passkey", string(credential.ID))
}
