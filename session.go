package charon

import (
	"context"
	"time"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

var ErrSessionNotFound = errors.Base("session not found")

// One week.
const sessionExpiration = time.Hour * 24 * 7

type Session struct {
	ID        identifier.Identifier
	SecretID  [32]byte
	CreatedAt time.Time

	AccountID identifier.Identifier
}

func (s Session) Expired() bool {
	return time.Now().After(s.CreatedAt.Add(sessionExpiration))
}

func (s *Service) getSession(_ context.Context, id identifier.Identifier) (*Session, errors.E) {
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
	if session.Expired() {
		return nil, errors.WithDetails(ErrSessionNotFound, "id", id)
	}
	return &session, nil
}

// GetSessionBySecretID is exported for testing.
func (s *Service) GetSessionBySecretID(ctx context.Context, secretID [32]byte) (*Session, errors.E) { //nolint:revive
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
			if session.Expired() {
				return nil, errors.WithDetails(ErrSessionNotFound)
			}
			return &session, nil
		}
	}

	return nil, errors.WithStack(ErrSessionNotFound)
}

func (s *Service) setSession(_ context.Context, session *Session) errors.E {
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
