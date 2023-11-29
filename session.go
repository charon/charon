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
	sessions   = make(map[identifier.Identifier][]byte)
	sessionsMu = sync.RWMutex{}
)

type Session struct {
	ID identifier.Identifier
}

func GetSession(ctx context.Context, id identifier.Identifier) (*Session, errors.E) {
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

func SetSession(ctx context.Context, session *Session) errors.E {
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
