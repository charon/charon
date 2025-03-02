package charon

import (
	"context"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

var ErrSessionNotFound = errors.Base("session not found")

type Session struct {
	ID       identifier.Identifier
	SecretID [32]byte

	AccountID identifier.Identifier
}

func (s *Service) getSession(ctx context.Context, id identifier.Identifier) (*Session, errors.E) { //nolint:revive
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	data, ok := s.sessions[id]
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

func (s *Service) getSessionBySecretID(ctx context.Context, secretID [32]byte) (*Session, errors.E) { //nolint:revive
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	for id, data := range s.sessions {
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

func (s *Service) setSession(ctx context.Context, session *Session) errors.E { //nolint:revive
	data, errE := x.MarshalWithoutEscapeHTML(session)
	if errE != nil {
		errors.Details(errE)["id"] = session.ID
		return errE
	}

	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	s.sessions[session.ID] = data
	return nil
}
