package charon

import (
	"context"
	"sync"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

var ErrSessionNotFound = errors.Base("session not found")

var (
	sessions   = make(map[identifier.Identifier][]byte) //nolint:gochecknoglobals
	sessionsMu = sync.RWMutex{}                         //nolint:gochecknoglobals
)

type Session struct {
	ID       identifier.Identifier
	SecretID [32]byte

	Account identifier.Identifier
}

func GetSession(ctx context.Context, id identifier.Identifier) (*Session, errors.E) { //nolint:revive
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()

	data, ok := sessions[id]
	if !ok {
		return nil, errors.WithDetails(ErrSessionNotFound, "id", id)
	}
	var session Session
	errE := x.UnmarshalWithoutUnknownFields(data, &session)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, errE
	}
	return &session, nil
}

func GetSessionBySecretID(ctx context.Context, secretID [32]byte) (*Session, errors.E) { //nolint:revive
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()

	for id, data := range sessions {
		var session Session
		errE := x.UnmarshalWithoutUnknownFields(data, &session)
		if errE != nil {
			errors.Details(errE)["id"] = id
			return nil, errE
		}
		if session.SecretID == secretID {
			return &session, nil
		}
	}

	return nil, errors.WithStack(ErrSessionNotFound)
}

func SetSession(ctx context.Context, session *Session) errors.E { //nolint:revive
	data, errE := x.MarshalWithoutEscapeHTML(session)
	if errE != nil {
		errors.Details(errE)["id"] = session.ID
		return errE
	}

	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	sessions[session.ID] = data
	return nil
}
