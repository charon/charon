package charon

import (
	"context"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
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
	CompletedSignin Completed = "signin"
	CompletedSignup Completed = "signup"
	CompletedFailed Completed = "failed"
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
	ID              identifier.Identifier
	Session         *identifier.Identifier
	Completed       Completed
	TargetLocation  string
	TargetName      string
	Provider        Provider
	EmailOrUsername string
	Attempts        int

	OIDCProvider *FlowOIDCProvider
	Passkey      *webauthn.SessionData
	Password     *FlowPassword
	Code         *FlowCode
}

func (f *Flow) Clear(emailOrUsername string) {
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

func (f *Flow) ClearAll() {
	f.Clear("")
	f.Code = nil
	f.EmailOrUsername = ""
}

func GetFlow(ctx context.Context, id identifier.Identifier) (*Flow, errors.E) { //nolint:revive
	flowsMu.RLock()
	defer flowsMu.RUnlock()

	data, ok := flows[id]
	if !ok {
		return nil, errors.WithDetails(ErrFlowNotFound, "id", id)
	}
	var flow Flow
	errE := x.UnmarshalWithoutUnknownFields(data, &flow)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, errE
	}
	return &flow, nil
}

func SetFlow(ctx context.Context, flow *Flow) errors.E { //nolint:revive
	data, errE := x.MarshalWithoutEscapeHTML(flow)
	if errE != nil {
		errors.Details(errE)["id"] = flow.ID
		return errE
	}

	flowsMu.Lock()
	defer flowsMu.Unlock()

	flows[flow.ID] = data
	return nil
}
