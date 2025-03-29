package charon //nolint:testpackage

import (
	"context"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
)

func (s *Service) TestingGetFlow(ctx context.Context, id identifier.Identifier) (*Flow, errors.E) {
	return s.getFlow(ctx, id)
}

func (s *Service) TestingSetFlow(ctx context.Context, flow *Flow) errors.E {
	return s.setFlow(ctx, flow)
}

func (s *Service) TestingGetSessionBySecretID(ctx context.Context, secretID [32]byte) (*Session, errors.E) {
	return s.getSessionBySecretID(ctx, secretID)
}

func TestingNormalizeUsernameCaseMapped(username string) (string, errors.E) {
	return normalizeUsernameCaseMapped(username)
}

func TestingNormalizeUsernameCasePreserved(username string) (string, errors.E) {
	return normalizeUsernameCasePreserved(username)
}

func TestingGetRandomCode() (string, errors.E) {
	return getRandomCode()
}

func TestingNormalizePassword(password []byte) ([]byte, errors.E) {
	return normalizePassword(password)
}
