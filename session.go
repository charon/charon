package charon

import (
	"context"
	"time"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

var errSessionNotFound = errors.Base("session not found")

// One week.
const sessionExpiration = time.Hour * 24 * 7

type session struct {
	ID        identifier.Identifier
	SecretID  [32]byte
	CreatedAt time.Time
	Active    bool

	AccountID identifier.Identifier
}

func (s session) Expired() bool {
	if !s.Active {
		return true
	}
	return time.Now().After(s.CreatedAt.Add(sessionExpiration))
}

func (s *Service) disableSession(ctx context.Context, id identifier.Identifier) errors.E {
	s.sessions.Lock()
	defer s.sessions.Unlock()

	session, errE := s.getSessionNoLock(ctx, id)
	if errE != nil {
		return errE
	}

	session.Active = false
	errE = s.setSessionNoLock(ctx, session)
	if errE != nil {
		return errE
	}

	return nil
}

func (s *Service) getSession(ctx context.Context, id identifier.Identifier) (*session, errors.E) {
	s.sessions.RLock()
	defer s.sessions.RUnlock()

	return s.getSessionNoLock(ctx, id)
}

func (s *Service) getSessionNoLock(_ context.Context, id identifier.Identifier) (*session, errors.E) {
	data, ok := s.sessions.Get(id)
	if !ok {
		return nil, errors.WithDetails(errSessionNotFound, "id", id)
	}
	var ses session
	errE := x.UnmarshalWithoutUnknownFields(data, &ses)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, errE
	}
	if ses.Expired() {
		return nil, errors.WithDetails(errSessionNotFound, "id", id)
	}
	return &ses, nil
}

func (s *Service) getSessionBySecretID(_ context.Context, secretID [32]byte) (*session, errors.E) {
	s.sessions.RLock()
	defer s.sessions.RUnlock()

	for id, data := range s.sessions.All() {
		var ses session
		errE := x.UnmarshalWithoutUnknownFields(data, &ses)
		if errE != nil {
			errors.Details(errE)["id"] = id
			return nil, errE
		}
		if ses.SecretID != secretID {
			continue
		}
		if ses.Expired() {
			return nil, errors.WithStack(errSessionNotFound)
		}
		return &ses, nil
	}

	return nil, errors.WithStack(errSessionNotFound)
}

func (s *Service) setSession(ctx context.Context, session *session) errors.E {
	s.sessions.Lock()
	defer s.sessions.Unlock()

	return s.setSessionNoLock(ctx, session)
}

func (s *Service) setSessionNoLock(_ context.Context, session *session) errors.E {
	data, errE := x.MarshalWithoutEscapeHTML(session)
	if errE != nil {
		errors.Details(errE)["id"] = session.ID
		return errE
	}

	return s.sessions.Set(session.ID, data)
}
