package charon

import (
	"context"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
)

func (s *Service) TestingGetFlow(ctx context.Context, id identifier.Identifier) (*Flow, errors.E) { //nolint:revive
	return s.getFlow(ctx, id)
}

func (s *Service) TestingSetFlow(ctx context.Context, flow *Flow) errors.E {
	return s.setFlow(ctx, flow)
}

func (s *Service) TestingGetSessionBySecretID(ctx context.Context, secretID [32]byte) (*Session, errors.E) { //nolint:revive
	return s.getSessionBySecretID(ctx, secretID)
}
