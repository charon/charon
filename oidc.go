package charon

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/go-jose/go-jose/v3"
	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/rfc7523"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
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

func initOIDC(config *Config, service *Service, domain string, secret []byte) func() *fosite.Fosite {
	return func() *fosite.Fosite {
		host, errE := getHost(config, domain)
		if errE != nil {
			panic(errE)
		}
		if host == "" {
			// Server failed to start. We just return in this case.
			return nil
		}

		tokenPath, errE := service.ReverseAPI("OIDCToken", nil, nil)
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
		// TODO: Implement support and add all from signingAlgValuesSupported.
		//       See: https://github.com/ory/fosite/issues/788
		getPrivateKey := func(context.Context) (interface{}, error) {
			return service.oidcKeys.rsa, nil
		}

		return compose.Compose( //nolint:forcetypeassert
			config,
			store,
			&compose.CommonStrategy{
				// TODO: Make HMACSHAStrategy use "charon" prefix instead of "ory" prefix.
				//       See: https://github.com/ory/fosite/issues/789
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
		).(*fosite.Fosite)
	}
}

var (
	_ fosite.Session             = (*OIDCSession)(nil)
	_ openid.Session             = (*OIDCSession)(nil)
	_ rfc7523.Session            = (*OIDCSession)(nil)
	_ oauth2.JWTSessionContainer = (*OIDCSession)(nil)
	_ fosite.ExtraClaimsSession  = (*OIDCSession)(nil)
)

// OIDCSession is a struct to store OIDC session (token) information (claims).
// All fields are public so that JSON marshaling can preserve the object.
// We use JSON marshaling when persisting sessions in the store.
type OIDCSession struct {
	Subject     identifier.Identifier          `json:"subject"`
	ExpiresAt   map[fosite.TokenType]time.Time `json:"expiresAt"`
	RequestedAt time.Time                      `json:"requestedAt"`
	AuthTime    time.Time                      `json:"authTime"`
	Client      identifier.Identifier          `json:"client"`
	// Fosite modifies these structs in-place and we have to keep a pointer
	// to them so that we return always the same struct between calls.
	JWTClaims  *jwt.JWTClaims `json:"jwtClaims"`
	JWTHeaders *jwt.Headers   `json:"jwtHeaders"`
	// Fosite modifies these structs in-place and we have to keep a pointer
	// to them so that we return always the same struct between calls.
	// We use "Internal" suffix because names would otherwise overlap with getters.
	IDTokenClaimsInternal  *jwt.IDTokenClaims `json:"idTokenClaims"`
	IDTokenHeadersInternal *jwt.Headers       `json:"idTokenHeaders"`
	Extra                  map[string]interface{}
}

// GetJWTClaims returns the claims of the JWT access token.
func (s *OIDCSession) GetJWTClaims() jwt.JWTClaimsContainer { //nolint:ireturn
	if s.JWTClaims == nil {
		s.JWTClaims = new(jwt.JWTClaims)
	}

	s.JWTClaims.Subject = s.Subject.String()
	s.JWTClaims.Add("client_id", s.Client.String())

	return s.JWTClaims
}

// GetJWTHeader returns the header of the JWT access token.
func (s *OIDCSession) GetJWTHeader() *jwt.Headers {
	if s.JWTHeaders == nil {
		s.JWTHeaders = new(jwt.Headers)
	}

	return s.JWTHeaders
}

// IDTokenClaims returns the claims of the JWT ID token.
func (s *OIDCSession) IDTokenClaims() *jwt.IDTokenClaims {
	if s.IDTokenClaimsInternal == nil {
		s.IDTokenClaimsInternal = new(jwt.IDTokenClaims)
	}

	s.IDTokenClaimsInternal.Subject = s.Subject.String()
	s.IDTokenClaimsInternal.RequestedAt = s.RequestedAt
	s.IDTokenClaimsInternal.AuthTime = s.AuthTime
	s.IDTokenClaimsInternal.Add("client_id", s.Client.String())

	return s.IDTokenClaimsInternal
}

// IDTokenHeaders returns the header of ID token.
func (s *OIDCSession) IDTokenHeaders() *jwt.Headers {
	if s.IDTokenHeadersInternal == nil {
		s.IDTokenHeadersInternal = new(jwt.Headers)
	}

	return s.IDTokenHeadersInternal
}

// SetExpiresAt sets the expiration time of a token.
func (s *OIDCSession) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}

	s.ExpiresAt[key] = exp
}

// GetExpiresAt returns the expiration time of a token if set, or time.IsZero() if not.
func (s *OIDCSession) GetExpiresAt(key fosite.TokenType) time.Time {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}

	_, ok := s.ExpiresAt[key]
	if !ok {
		return time.Time{}
	}

	return s.ExpiresAt[key]
}

// GetUsername returns the username, if set. This is optional and only used during token introspection.
func (s *OIDCSession) GetUsername() string {
	return ""
}

// GetSubject returns the subject, if set. This is optional and only used during token introspection.
func (s *OIDCSession) GetSubject() string {
	if s == nil {
		return ""
	}

	return s.Subject.String()
}

// Clone clones the session.
func (s *OIDCSession) Clone() fosite.Session { //nolint:ireturn
	if s == nil {
		return nil
	}

	return deepcopy.Copy(s).(fosite.Session) //nolint:forcetypeassert
}

// GetExtraClaims implements fosite.ExtraClaimsSession.
func (s *OIDCSession) GetExtraClaims() map[string]interface{} {
	if s == nil {
		return nil
	}

	if s.Extra == nil {
		s.Extra = make(map[string]interface{})
	}

	return s.Extra
}

// SetSubject implements rfc7523.Session.
func (s *OIDCSession) SetSubject(subject string) {
	// Subject is validated earlier (in GetPublicKeyScopes).
	s.Subject = identifier.MustFromString(subject)
}

var (
	_ fosite.Client                   = (*OIDCClient)(nil)
	_ fosite.OpenIDConnectClient      = (*OIDCClient)(nil)
	_ fosite.ResponseModeClient       = (*OIDCClient)(nil)
	_ fosite.ClientWithSecretRotation = (*OIDCClient)(nil)
)

type ClientType string

const (
	ClientPublic  ClientType = "public"
	ClientBackend ClientType = "backend"
	ClientService ClientType = "service"
)

// OIDCClient represents a configuration of the OIDC client for an app
// enabled in an organization.
type OIDCClient struct {
	ID                      identifier.Identifier
	Application             *Application
	OrganizationApplication *OrganizationApplication
	TokenEndpointAuthMethod string
	Type                    ClientType
}

func (c *OIDCClient) GetAppID() identifier.Identifier {
	return *c.OrganizationApplication.ID
}

// GetResponseModes implements fosite.ResponseModeClient.
func (*OIDCClient) GetResponseModes() []fosite.ResponseModeType {
	return responseModesSupported
}

// GetJSONWebKeys implements fosite.OpenIDConnectClient.
func (*OIDCClient) GetJSONWebKeys() *jose.JSONWebKeySet {
	// TODO: Support JWKs for authentication.
	return nil
}

// GetJSONWebKeysURI implements fosite.OpenIDConnectClient.
func (*OIDCClient) GetJSONWebKeysURI() string {
	// We are not planing to support JWK URIs so that apps do not have to store secrets (we prefer to store them).
	// If you need this feature please open an issue explaining the use cae and the app which needs it.
	return ""
}

// GetRequestObjectSigningAlgorithm implements fosite.OpenIDConnectClient.
func (*OIDCClient) GetRequestObjectSigningAlgorithm() string {
	// We do not really care how the request object is signed, so we support anything fosite does.
	return ""
}

// GetRequestURIs implements fosite.OpenIDConnectClient.
func (*OIDCClient) GetRequestURIs() []string {
	// We currently do not support allowlisting URIs for clients.
	return nil
}

// GetTokenEndpointAuthMethod implements fosite.OpenIDConnectClient.
func (c *OIDCClient) GetTokenEndpointAuthMethod() string {
	if c.IsPublic() {
		return "none"
	}
	return c.TokenEndpointAuthMethod
}

// GetTokenEndpointAuthSigningAlgorithm implements fosite.OpenIDConnectClient.
func (*OIDCClient) GetTokenEndpointAuthSigningAlgorithm() string {
	// TODO: Support JWKs for authentication.
	return ""
}

// GetAudience implements fosite.Client.
func (c *OIDCClient) GetAudience() fosite.Arguments {
	return fosite.Arguments{c.ID.String()}
}

// GetGrantTypes implements fosite.Client.
func (c *OIDCClient) GetGrantTypes() fosite.Arguments {
	switch c.Type {
	case ClientPublic:
		fallthrough
	case ClientBackend:
		return fosite.Arguments{"authorization_code", "refresh_token"}
	case ClientService:
		return fosite.Arguments{"client_credentials"}
	default:
		panic(errors.Errorf("unknown client type: %s", c.Type))
	}
}

// GetHashedSecret implements fosite.Client.
func (c *OIDCClient) GetHashedSecret() []byte {
	return []byte(c.OrganizationApplication.Secret)
}

// GetID implements fosite.Client.
func (c *OIDCClient) GetID() string {
	return c.ID.String()
}

// GetRedirectURIs implements fosite.Client.
func (c *OIDCClient) GetRedirectURIs() []string {
	redirects := []string{}
	for _, redirect := range c.Application.RedirectPaths {
		// TODO: Support arbitrary variables to be interpolated into app config.
		redirects = append(redirects, c.OrganizationApplication.URLBase+redirect)
	}
	return redirects
}

// GetResponseTypes implements fosite.Client.
func (*OIDCClient) GetResponseTypes() fosite.Arguments {
	return fosite.Arguments{"id_token", "code", "code id_token"}
}

// GetScopes implements fosite.Client.
func (*OIDCClient) GetScopes() fosite.Arguments {
	// TODO: Support configurable scopes.
	return fosite.Arguments{"openid", "offline_access"}
}

// IsPublic implements fosite.Client.
func (c *OIDCClient) IsPublic() bool {
	return c.Type == ClientPublic
}

// GetRotatedHashes implements fosite.ClientWithSecretRotation.
func (*OIDCClient) GetRotatedHashes() [][]byte {
	// We currently do not support secret rotation.
	return nil
}
