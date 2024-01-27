package charon

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"net/url"

	"github.com/alexedwards/argon2id"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/waf"
)

type argon2idHasher struct{}

func (argon2idHasher) Compare(_ context.Context, hash, data []byte) error {
	// TODO: Use byte as input and not string.
	//       See: https://github.com/alexedwards/argon2id/issues/26
	match, err := argon2id.ComparePasswordAndHash(string(hash), string(data))
	if err != nil {
		return errors.WithStack(err)
	}

	if !match {
		return errors.New("hash mismatch")
	}

	return nil
}

func (argon2idHasher) Hash(_ context.Context, data []byte) ([]byte, error) {
	// TODO: Use byte as input and not string.
	//       See: https://github.com/alexedwards/argon2id/issues/26
	hashedPassword, err := argon2id.CreateHash(string(data), &argon2idParams)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return []byte(hashedPassword), nil
}

// TODO: Remove once it is merged upstream.
//       See: https://github.com/ory/fosite/pull/785

func isRedirectURISecureStrict(_ context.Context, redirectURI *url.URL) bool {
	return fosite.IsRedirectURISecureStrict(redirectURI)
}

func initOIDC(config *Config, service *Service, domain string, secret []byte, privateKey *ecdsa.PrivateKey) func() fosite.OAuth2Provider {
	return func() fosite.OAuth2Provider {
		host, errE := getHost(config, domain)
		if errE != nil {
			panic(errE)
		}
		if host == "" {
			// Server failed to start. We just return in this case.
			return nil
		}

		tokenPath, errE := service.Reverse("OIDCToken", nil, nil)
		if errE != nil {
			panic(errE)
		}

		issuer := fmt.Sprintf("https://%s", host)

		store := storage.NewMemoryStore()

		config := &fosite.Config{ //nolint:exhaustruct
			IDTokenIssuer: issuer,
			// Send some debug messages to clients?
			SendDebugMessagesToClients: config.OIDC.Development,
			ScopeStrategy:              fosite.ExactScopeStrategy,
			AudienceMatchingStrategy:   fosite.ExactAudienceMatchingStrategy,
			EnforcePKCE:                true,
			// TODO: Support also "login", "consent", and "select_account".
			AllowedPromptValues: []string{"none"},
			TokenURL:            issuer + tokenPath,
			// We do not want to allow potentially insecure custom schemes but require only https (and localhost http).
			// This means that for mobile native apps one has to use app-claimed https redirects instead of custom schemes.
			// Custom schemes are not secure because they can be registered by multiple apps.
			RedirectSecureChecker: isRedirectURISecureStrict,
			// We provide a refresh token if client asks for "offline_access" scope.
			// We further control which clients can  use refresh tokens by allowing
			// or not "refresh_token" grant type.
			RefreshTokenScopes:  []string{"offline_access"},
			JWTScopeClaimKey:    jwt.JWTScopeFieldString,
			AccessTokenIssuer:   issuer,
			ClientSecretsHasher: argon2idHasher{},
			GlobalSecret:        secret,
			// TODO: Support and set also RotatedGlobalSecrets.
		}

		// TODO: Support rotating private keys.
		//       See: https://github.com/ory/fosite/issues/786
		getPrivateKey := func(context.Context) (interface{}, error) {
			return privateKey, nil
		}

		return compose.Compose(
			config,
			store,
			&compose.CommonStrategy{
				CoreStrategy:               compose.NewOAuth2JWTStrategy(getPrivateKey, compose.NewOAuth2HMACStrategy(config), config),
				OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(getPrivateKey, config),
				Signer: &jwt.DefaultSigner{
					GetPrivateKey: getPrivateKey,
				},
			},

			compose.OAuth2AuthorizeExplicitFactory,
			compose.OAuth2AuthorizeImplicitFactory,
			compose.OAuth2ClientCredentialsGrantFactory,
			compose.OAuth2RefreshTokenGrantFactory,
			compose.OAuth2TokenIntrospectionFactory,
			compose.OAuth2TokenRevocationFactory,
			compose.RFC7523AssertionGrantFactory,

			compose.OpenIDConnectExplicitFactory,
			compose.OpenIDConnectImplicitFactory,
			compose.OpenIDConnectHybridFactory,
			compose.OpenIDConnectRefreshFactory,

			compose.OAuth2PKCEFactory,
			compose.PushedAuthorizeHandlerFactory,
		)
	}
}
