package charon

import (
	"context"
	"crypto/sha512"
	"hash"

	"github.com/ory/fosite/token/hmac"
)

type hmacStrategyConfigurator struct {
	Secret []byte
}

// GetGlobalSecret implements hmac.HMACStrategyConfigurator.
func (h *hmacStrategyConfigurator) GetGlobalSecret(_ context.Context) ([]byte, error) {
	return h.Secret, nil
}

// GetHMACHasher implements hmac.HMACStrategyConfigurator.
func (h *hmacStrategyConfigurator) GetHMACHasher(_ context.Context) func() hash.Hash {
	return sha512.New512_256
}

// GetRotatedGlobalSecrets implements hmac.HMACStrategyConfigurator.
func (h *hmacStrategyConfigurator) GetRotatedGlobalSecrets(_ context.Context) ([][]byte, error) {
	// TODO: Support RotatedGlobalSecrets.
	return nil, nil
}

// GetTokenEntropy implements hmac.HMACStrategyConfigurator.
func (h *hmacStrategyConfigurator) GetTokenEntropy(_ context.Context) int {
	return 32 //nolint:gomnd
}

var _ hmac.HMACStrategyConfigurator = (*hmacStrategyConfigurator)(nil)
