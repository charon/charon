package charon //nolint:testpackage

import (
	"context"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
)

// We export these for testing purposes only.

func (s *Service) TestingGetFlow(ctx context.Context, id identifier.Identifier) (*Flow, errors.E) {
	return s.getFlow(ctx, id)
}

func (s *Service) TestingSetFlow(ctx context.Context, flow *Flow) errors.E {
	return s.setFlow(ctx, flow)
}

func (s *Service) TestingGetSessionBySecretID(ctx context.Context, secretID [32]byte) (*Session, errors.E) {
	return s.getSessionBySecretID(ctx, secretID)
}

func (s *Service) TestingCreateIdentity(ctx context.Context, identity *Identity) errors.E {
	return s.createIdentity(ctx, identity)
}

func (s *Service) TestingUpdateIdentity(ctx context.Context, identity *Identity) errors.E {
	return s.updateIdentity(ctx, identity)
}

func (s *Service) TestingGetIdentity(ctx context.Context, id identifier.Identifier) (*Identity, bool, errors.E) {
	return s.getIdentity(ctx, id)
}

func (s *Service) TestListIdentity(ctx context.Context) ([]IdentityRef, errors.E) {
	a := false
	return s.identityList(ctx, nil, nil, &a)
}

func (s *Service) TestingWithIdentityID(ctx context.Context, identityID identifier.Identifier) context.Context {
	return s.withIdentityID(ctx, identityID)
}

func (s *Service) TestingWithAccountID(ctx context.Context, accountID identifier.Identifier) context.Context {
	return s.withAccountID(ctx, accountID)
}

func (s *Service) TestingGetIdentitiesAccess(accountID identifier.Identifier) map[IdentityRef][][]IdentityRef {
	s.identitiesAccessMu.RLock()
	defer s.identitiesAccessMu.RUnlock()

	return s.identitiesAccess[accountID]
}

func (s *Service) TestingGetCreatedIdentities(identity IdentityRef) (identifier.Identifier, bool) {
	s.identitiesAccessMu.RLock()
	defer s.identitiesAccessMu.RUnlock()

	a, ok := s.identityCreators[identity]
	return a, ok
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
