package charon

import (
	"context"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/ory/fosite"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

var (
	ErrFlowNotFound     = errors.Base("flow not found")
	ErrInvalidCompleted = errors.Base("invalid completed value for flow state")
)

type Completed string

const (
	// Auth step completed with sign in.
	CompletedSignin Completed = "signin"
	// Auth step completed with sign up.
	CompletedSignup Completed = "signup"
	// Auth step failed (3rd party authentication failed, too many attempts, etc.).
	CompletedFailed Completed = "failed"

	// Identity selected.
	CompletedIdentity Completed = "identity"
	// Identity selection has been declined.
	CompletedDeclined Completed = "declined"

	// Flow is ready to be finished.
	CompletedFinishReady Completed = "finishReady"

	// Flow has finished.
	CompletedFinished Completed = "finished"
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
	AccountID   *identifier.Identifier
	Credentials []Credential
}

type FlowSAMLProvider struct{}

type Flow struct {
	ID        identifier.Identifier
	CreatedAt time.Time
	Completed []Completed
	AuthTime  *time.Time

	OrganizationID identifier.Identifier
	AppID          identifier.Identifier

	SessionID *identifier.Identifier
	Identity  *Identity

	// State of the OIDC authorization request which started this flow.
	OIDCAuthorizeRequest *fosite.AuthorizeRequest

	// State while the user is authenticating themselves.
	AuthAttempts    int
	Providers       []Provider
	EmailOrUsername string
	OIDCProvider    *FlowOIDCProvider
	SAMLProvider    *FlowSAMLProvider
	Passkey         *webauthn.SessionData
	Password        *FlowPassword
	Code            *FlowCode
}

func (f *Flow) AddCompleted(completed Completed) errors.E {
	for {
		previous := f.lastCompletedStep()

		switch completed {
		case CompletedSignin, CompletedSignup, CompletedFailed:
			// It has to be the first.
			if previous != "" {
				return errors.WithStack(ErrInvalidCompleted)
			}
		case CompletedIdentity:
			if previous == CompletedIdentity || previous == CompletedDeclined {
				// We allow to select identity again or to select it after it was previously declined.
				// We remove the last completed step first.
				f.Completed = f.Completed[:len(f.Completed)-1]
				continue
			} else if previous != CompletedSignin && previous != CompletedSignup {
				// Only CompletedSignin and CompletedSignup are allowed as the previous step to select identity.
				return errors.WithStack(ErrInvalidCompleted)
			}
		case CompletedDeclined:
			if previous == "" { //nolint:revive
				// In UI we provide CompletedDeclined option only after the auth step, as an alternative to
				// CompletedIdentity, but in API we allow to decline the flow also as the first step.
			} else if previous == CompletedDeclined || previous == CompletedIdentity {
				// We allow to decline again or to decline after an identity was previously selected.
				// We remove the last completed step first.
				f.Completed = f.Completed[:len(f.Completed)-1]
				continue
			} else if previous != CompletedSignin && previous != CompletedSignup {
				return errors.WithStack(ErrInvalidCompleted)
			}
		case CompletedFinishReady:
			if previous == CompletedFinishReady {
				// We allow to mark the flow as ready to be finished again.
				// We remove the last completed step first.
				f.Completed = f.Completed[:len(f.Completed)-1]
				continue
			} else if previous != CompletedFailed && previous != CompletedIdentity && previous != CompletedDeclined {
				return errors.WithStack(ErrInvalidCompleted)
			}
		case CompletedFinished:
			if previous != CompletedFinishReady {
				return errors.WithStack(ErrInvalidCompleted)
			}
		default:
			errE := errors.New("invalid flow completed step")
			errors.Details(errE)["completed"] = completed
			errors.Details(errE)["existing"] = f.Completed
			// Internal error: this should never happen.
			panic(errE)
		}

		break
	}

	f.Completed = append(f.Completed, completed)
	return nil
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

func (f *Flow) lastCompletedStep() Completed {
	if len(f.Completed) == 0 {
		return ""
	}

	return f.Completed[len(f.Completed)-1]
}

func (f *Flow) ClearAuthStepAll() {
	f.ClearAuthStep("")
	f.Code = nil
	f.EmailOrUsername = ""
}

func (f *Flow) IsFinishReady() bool {
	return f.lastCompletedStep() == CompletedFinishReady
}

func (f *Flow) IsFinished() bool {
	return f.lastCompletedStep() == CompletedFinished
}

func (f *Flow) HasFailed() bool {
	return slices.Contains(f.Completed, CompletedFailed)
}

func (f *Flow) HasDeclined() bool {
	return slices.Contains(f.Completed, CompletedDeclined)
}

func (s *Service) getFlow(_ context.Context, id identifier.Identifier) (*Flow, errors.E) {
	s.flowsMu.RLock()
	defer s.flowsMu.RUnlock()

	data, ok := s.flows[id]
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
	// This can happen if OIDCAuthorizeRequest is ever used with omitempty, then
	// Unmarshal does not set it to nil if it is not present in JSON.
	if flow.OIDCAuthorizeRequest != nil && flow.OIDCAuthorizeRequest.ResponseTypes == nil {
		flow.OIDCAuthorizeRequest = nil
	}
	return &flow, nil
}

func (s *Service) setFlow(_ context.Context, flow *Flow) errors.E {
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

	s.flowsMu.Lock()
	defer s.flowsMu.Unlock()

	s.flows[flow.ID] = data
	return nil
}
