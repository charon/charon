package charon

import (
	"context"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/ory/fosite"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

var ErrFlowNotFound = errors.Base("flow not found")

var (
	flows   = make(map[identifier.Identifier][]byte) //nolint:gochecknoglobals
	flowsMu = sync.RWMutex{}                         //nolint:gochecknoglobals
)

type Completed string

const (
	// Auth step completed with sign in.
	CompletedSignin Completed = "signin"
	// Auth step completed with sign up.
	CompletedSignup Completed = "signup"
	// Auth step failed (3rd party authentication failed, too many attempts, etc.).
	CompletedFailed Completed = "failed"

	// OIDC organization joined.
	CompletedOrganization Completed = "organization"
	// OIDC identity picked.
	CompletedIdentity Completed = "identity"
	// OIDC redirect was made back to the OIDC client.
	CompletedRedirect Completed = "redirect"
)

type Target string

const (
	TargetSession Target = "session"
	TargetOIDC    Target = "oidc"
)

type FlowOIDCProvider struct {
	Verifier string
	Nonce    string
}

type FlowPassword struct {
	PrivateKey []byte
	Nonce      []byte
}

type FlowCode struct {
	Codes       []string
	Account     *identifier.Identifier
	Credentials []Credential
}

type Flow struct {
	ID                 identifier.Identifier
	Session            *identifier.Identifier
	Completed          Completed
	Target             Target
	TargetLocation     string
	TargetName         string
	TargetOrganization string
	Provider           Provider
	EmailOrUsername    string
	Attempts           int

	OIDCAuthorizeRequest *fosite.AuthorizeRequest

	OIDCProvider *FlowOIDCProvider
	Passkey      *webauthn.SessionData
	Password     *FlowPassword
	Code         *FlowCode
}

func (f *Flow) ClearAuthStep(emailOrUsername string) {
	f.OIDCProvider = nil
	f.Passkey = nil
	f.Password = nil

	// If emailOrUsername is provided, we require that it is the same as what was previously
	// provided to not clear the code provider's state as well.
	if emailOrUsername != "" && emailOrUsername != f.EmailOrUsername {
		f.Code = nil
		f.EmailOrUsername = emailOrUsername
	}
}

func (f *Flow) ClearAuthStepAll() {
	f.ClearAuthStep("")
	f.Code = nil
	f.EmailOrUsername = ""
}

func (f *Flow) IsCompleted() bool {
	switch f.Target {
	case TargetSession:
		switch f.Completed {
		case CompletedSignin, CompletedSignup, CompletedFailed:
			return true
		case CompletedOrganization, CompletedIdentity, CompletedRedirect:
			fallthrough
		default:
			errE := errors.New("invalid flow completed state for target")
			errors.Details(errE)["target"] = f.Target
			errors.Details(errE)["completed"] = f.Completed
			panic(errE)
		}
	case TargetOIDC:
		switch f.Completed {
		case CompletedRedirect:
			return true
		case CompletedSignin, CompletedSignup, CompletedFailed, CompletedOrganization, CompletedIdentity:
			return false
		default:
			errE := errors.New("invalid flow completed state for target")
			errors.Details(errE)["target"] = f.Target
			errors.Details(errE)["completed"] = f.Completed
			panic(errE)
		}
	default:
		errE := errors.New("invalid flow target")
		errors.Details(errE)["target"] = f.Target
		panic(errE)
	}
}

func GetFlow(ctx context.Context, id identifier.Identifier) (*Flow, errors.E) { //nolint:revive
	flowsMu.RLock()
	defer flowsMu.RUnlock()

	data, ok := flows[id]
	if !ok {
		return nil, errors.WithDetails(ErrFlowNotFound, "id", id)
	}
	var flow Flow
	// We set interface fields so that unmarshal has structs to use.
	flow.OIDCAuthorizeRequest = new(fosite.AuthorizeRequest)
	flow.OIDCAuthorizeRequest.Client = new(OIDCClient)
	flow.OIDCAuthorizeRequest.Session = new(OIDCSession)
	errE := x.UnmarshalWithoutUnknownFields(data, &flow)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, errE
	}
	// If ResponseTypes is still nil, then OIDCAuthorizeRequest was not really set
	// in the flow, so we set it to nil explicitly to clear interface fields we set.
	// This can happen when OIDCAuthorizeRequest is used with omitempty, then
	// Unmarshal does not set it to nil if it is not present in JSON.
	if flow.OIDCAuthorizeRequest != nil && flow.OIDCAuthorizeRequest.ResponseTypes == nil {
		flow.OIDCAuthorizeRequest = nil
	}
	return &flow, nil
}

func SetFlow(ctx context.Context, flow *Flow) errors.E { //nolint:revive
	sanitizedFlow := flow
	if flow.OIDCAuthorizeRequest != nil {
		// We make a copy of the flow.
		sanitizedFlow = new(Flow)
		*sanitizedFlow = *flow
		// And sanitize OIDCAuthorizeRequest.
		sanitizedFlow.OIDCAuthorizeRequest = sanitizeAuthorizeRequest(sanitizedFlow.OIDCAuthorizeRequest)
	}

	data, errE := x.MarshalWithoutEscapeHTML(sanitizedFlow)
	if errE != nil {
		errors.Details(errE)["id"] = flow.ID
		return errE
	}

	flowsMu.Lock()
	defer flowsMu.Unlock()

	flows[flow.ID] = data
	return nil
}
