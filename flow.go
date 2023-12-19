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

type FlowOIDC struct {
	Verifier string
	Nonce    string
}

type FlowPassword struct {
	PrivateKey []byte
	Nonce      []byte
}

type FlowCode struct {
	Code        string
	Account     *identifier.Identifier
	Credentials []Credential
}

type Flow struct {
	ID              identifier.Identifier
	Session         *identifier.Identifier
	TargetLocation  string
	TargetName      string
	Provider        Provider
	EmailOrUsername string

	OIDC     *FlowOIDC
	Passkey  *webauthn.SessionData
	Password *FlowPassword
	Code     *FlowCode
}

func (f *Flow) Reset() {
	f.OIDC = nil
	f.Passkey = nil
	f.Password = nil
	f.Code = nil
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
