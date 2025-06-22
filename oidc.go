package charon

import (
	"context"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/go-jose/go-jose/v3"
	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/rfc7523"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/fosite/token/jwt"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
)

const (
	SecretPrefixAccessToken   = "cat-"
	SecretPrefixRefreshToken  = "crt-"
	SecretPrefixAuthorizeCode = "cac-"
)

var oidcStore = NewOIDCStore() //nolint:gochecknoglobals

type argon2idHasher struct{}

func (argon2idHasher) Compare(_ context.Context, hash, data []byte) error {
	strData := string(data)
	if !strings.HasPrefix(strData, SecretPrefixClientSecret) {
		return errors.Errorf(`secret does not have "%s" prefix`, SecretPrefixClientSecret)
	}
	strData = strings.TrimPrefix(strData, SecretPrefixClientSecret)
	// TODO: Use byte as input and not string.
	//       See: https://github.com/alexedwards/argon2id/issues/26
	match, err := argon2id.ComparePasswordAndHash(strData, string(hash))
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
	hashedPassword, err := argon2id.CreateHash(string(data), &Argon2idParams)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return []byte(hashedPassword), nil
}

var _ oauth2.CoreStrategy = (*hmacSHAStrategy)(nil)

type hmacSHAStrategy struct {
	*oauth2.HMACSHAStrategyUnPrefixed
}

func newHMACSHAStrategy(
	hmacStrategy *hmac.HMACStrategy,
	config oauth2.LifespanConfigProvider,
) *hmacSHAStrategy {
	return &hmacSHAStrategy{
		HMACSHAStrategyUnPrefixed: oauth2.NewHMACSHAStrategyUnPrefixed(hmacStrategy, config),
	}
}

func (h *hmacSHAStrategy) trimPrefix(token, prefix string) string {
	return strings.TrimPrefix(token, prefix)
}

func (h *hmacSHAStrategy) setPrefix(token, prefix string) string {
	if token == "" {
		return ""
	}
	return prefix + token
}

func (h *hmacSHAStrategy) GenerateAccessToken(ctx context.Context, r fosite.Requester) (string, string, error) {
	token, sig, err := h.HMACSHAStrategyUnPrefixed.GenerateAccessToken(ctx, r)
	return h.setPrefix(token, SecretPrefixAccessToken), sig, err
}

func (h *hmacSHAStrategy) ValidateAccessToken(ctx context.Context, r fosite.Requester, token string) error {
	return h.HMACSHAStrategyUnPrefixed.ValidateAccessToken(ctx, r, h.trimPrefix(token, SecretPrefixAccessToken)) //nolint:wrapcheck
}

func (h *hmacSHAStrategy) GenerateRefreshToken(ctx context.Context, r fosite.Requester) (string, string, error) {
	token, sig, err := h.HMACSHAStrategyUnPrefixed.GenerateRefreshToken(ctx, r)
	return h.setPrefix(token, SecretPrefixRefreshToken), sig, err
}

func (h *hmacSHAStrategy) ValidateRefreshToken(ctx context.Context, r fosite.Requester, token string) error {
	return h.HMACSHAStrategyUnPrefixed.ValidateRefreshToken(ctx, r, h.trimPrefix(token, SecretPrefixRefreshToken)) //nolint:wrapcheck
}

func (h *hmacSHAStrategy) GenerateAuthorizeCode(ctx context.Context, r fosite.Requester) (string, string, error) {
	token, sig, err := h.HMACSHAStrategyUnPrefixed.GenerateAuthorizeCode(ctx, r)
	return h.setPrefix(token, SecretPrefixAuthorizeCode), sig, err
}

func (h *hmacSHAStrategy) ValidateAuthorizeCode(ctx context.Context, r fosite.Requester, token string) error {
	return h.HMACSHAStrategyUnPrefixed.ValidateAuthorizeCode(ctx, r, h.trimPrefix(token, SecretPrefixAuthorizeCode)) //nolint:wrapcheck
}

func initOIDC(config *Config, service *Service, domain string, hmacStrategy *hmac.HMACStrategy) (func() *fosite.Fosite, errors.E) {
	return initWithHost(config, domain, func(host string) *fosite.Fosite {
		tokenPath, errE := service.ReverseAPI("OIDCToken", nil, nil)
		if errE != nil {
			// Internal error: this should never happen.
			panic(errE)
		}

		issuer := "https://" + host

		config := &fosite.Config{ //nolint:exhaustruct
			IDTokenIssuer: issuer,
			// Send some debug messages to clients?
			SendDebugMessagesToClients: config.Server.Development,
			ScopeStrategy:              fosite.ExactScopeStrategy,
			AudienceMatchingStrategy:   fosite.ExactAudienceMatchingStrategy,
			EnforcePKCE:                true,
			// TODO: Support also "login", "consent", and "select_account".
			AllowedPromptValues: []string{"none"},
			TokenURL:            issuer + tokenPath,
			// We do not want to allow potentially insecure custom schemes but require only https (and localhost http).
			// This means that for mobile native apps one has to use app-claimed https redirects instead of custom schemes.
			// Custom schemes are not secure because they can be registered by multiple apps.
			RedirectSecureChecker: fosite.IsRedirectURISecureStrict,
			// We provide a refresh token if client asks for "offline_access" scope.
			// We further control which clients can use refresh tokens by allowing
			// or not "refresh_token" grant type.
			RefreshTokenScopes:  []string{"offline_access"},
			JWTScopeClaimKey:    jwt.JWTScopeFieldString,
			AccessTokenIssuer:   issuer,
			ClientSecretsHasher: argon2idHasher{},
		}

		// TODO: Support rotating private keys.
		//       See: https://github.com/ory/fosite/issues/786
		// TODO: Implement support and add all from signingAlgValuesSupported.
		//       See: https://github.com/ory/fosite/issues/788
		getPrivateKey := func(context.Context) (interface{}, error) {
			return service.oidcKeys.rsa, nil
		}

		oAuth2HMACStrategy := newHMACSHAStrategy(hmacStrategy, config)

		return compose.Compose( //nolint:forcetypeassert,errcheck
			config,
			oidcStore,
			&compose.CommonStrategy{
				CoreStrategy:               compose.NewOAuth2JWTStrategy(getPrivateKey, oAuth2HMACStrategy, config),
				OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(getPrivateKey, config),
				Signer: &jwt.DefaultSigner{
					GetPrivateKey: getPrivateKey,
				},
			},

			compose.OAuth2AuthorizeExplicitFactory,
			compose.OAuth2ClientCredentialsGrantFactory,
			compose.OAuth2RefreshTokenGrantFactory,
			compose.OAuth2TokenIntrospectionFactory,
			compose.OAuth2TokenRevocationFactory,

			compose.OpenIDConnectExplicitFactory,
			compose.OpenIDConnectRefreshFactory,

			compose.OAuth2PKCEFactory,
		).(*fosite.Fosite)
	})
}

// sanitizeAuthorizeRequest sanitizes the authorization request so that it does not contain any sensitive
// data before it is stored into the database. It must still contain enough information to be able to
// complete the OIDC flow. We do that by removing fields from submitted form data.
func sanitizeAuthorizeRequest(request *fosite.AuthorizeRequest) *fosite.AuthorizeRequest {
	sanitized := new(fosite.AuthorizeRequest)
	*sanitized = *request
	sanitized.Request = *request.Request.Sanitize( //nolint:forcetypeassert,errcheck
		[]string{
			// OIDC parameters (same as fosite.handler.openid.oidcParameters).
			"max_age", "prompt", "acr_values", "id_token_hint", "nonce",
			// PCRE.
			"code_challenge", "code_challenge_method",
			// Required so that it is possible to validate if it is passed to the token
			// endpoint as well, if it was first passed to the authorization endpoint.
			"redirect_uri",
			// Other fields.
			"display", "ui_locales", "login_hint",
		},
	).(*fosite.Request)
	return sanitized
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
	AccountID   identifier.Identifier          `json:"accountId"`
	Subject     identifier.Identifier          `json:"subject"`
	SessionID   identifier.Identifier          `json:"sessionId"`
	ExpiresAt   map[fosite.TokenType]time.Time `json:"expiresAt"`
	RequestedAt time.Time                      `json:"requestedAt"`
	AuthTime    time.Time                      `json:"authTime"`
	ClientID    identifier.Identifier          `json:"clientId"`
	// Fosite modifies these structs in-place and we have to keep a pointer
	// to them so that we return always the same struct between calls.
	JWTClaims  *jwt.JWTClaims `json:"jwtClaims"`
	JWTHeaders *jwt.Headers   `json:"jwtHeaders"`
	// Fosite modifies these structs in-place and we have to keep a pointer
	// to them so that we return always the same struct between calls.
	// We use "Internal" suffix because names would otherwise overlap with getters.
	IDTokenClaimsInternal  *jwt.IDTokenClaims `json:"idTokenClaims"`
	IDTokenHeadersInternal *jwt.Headers       `json:"idTokenHeaders"`
}

// GetJWTClaims returns the claims of the JWT access token.
func (s *OIDCSession) GetJWTClaims() jwt.JWTClaimsContainer { //nolint:ireturn
	if s.JWTClaims == nil {
		s.JWTClaims = new(jwt.JWTClaims)

		s.JWTClaims.Subject = s.Subject.String()
		s.JWTClaims.Add("client_id", s.ClientID.String())
		s.JWTClaims.Add("sid", s.SessionID.String())
	}

	// We reset JTI every time.
	s.JWTClaims.JTI = identifier.New().String()

	// We reset IssuedAt every time.
	// See: https://github.com/ory/fosite/issues/774
	s.JWTClaims.IssuedAt = time.Now().UTC()

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

		s.IDTokenClaimsInternal.Subject = s.Subject.String()
		s.IDTokenClaimsInternal.Add("client_id", s.ClientID.String())
		s.IDTokenClaimsInternal.Add("sid", s.SessionID.String())

		// For ID tokens, these two timestamps are not reset
		// but are kept to their initial values.
		s.IDTokenClaimsInternal.RequestedAt = s.RequestedAt
		s.IDTokenClaimsInternal.AuthTime = s.AuthTime
	}

	// We reset JTI every time.
	s.IDTokenClaimsInternal.JTI = identifier.New().String()

	// We do not reset IssuedAt every time here because it is already done by fosite.
	// See: https://github.com/ory/fosite/issues/774

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

	return deepcopy.Copy(s).(fosite.Session) //nolint:forcetypeassert,errcheck
}

// GetExtraClaims implements fosite.ExtraClaimsSession and claims
// are used to populate the response of the introspection endpoint.
// The returned value is a copy of JWTClaims.
func (s *OIDCSession) GetExtraClaims() map[string]interface{} {
	if s == nil {
		return nil
	}

	// We make a clone so that WithScopeField does not change the original value.
	return s.Clone().(*OIDCSession).JWTClaims.WithScopeField(jwt.JWTScopeFieldString).ToMapClaims() //nolint:forcetypeassert,errcheck
}

// SetSubject implements rfc7523.Session.
func (s *OIDCSession) SetSubject(subject string) {
	// Subject is validated earlier (in GetPublicKeyScopes).
	s.Subject = identifier.String(subject)
}

var (
	_ fosite.Client                         = (*OIDCClient)(nil)
	_ fosite.OpenIDConnectClient            = (*OIDCClient)(nil)
	_ fosite.ResponseModeClient             = (*OIDCClient)(nil)
	_ fosite.ClientWithSecretRotation       = (*OIDCClient)(nil)
	_ fosite.ClientWithCustomTokenLifespans = (*OIDCClient)(nil)
)

// OIDCClient represents a configuration of the OIDC client for an app
// enabled in an organization.
type OIDCClient struct {
	ID                      identifier.Identifier
	OrganizationID          identifier.Identifier
	AppID                   identifier.Identifier
	Type                    ClientType
	TokenEndpointAuthMethod string
	Scopes                  []string
	RedirectURIs            []string
	Secret                  []byte
	AccessTokenLifespan     Duration
	IDTokenLifespan         Duration
	RefreshTokenLifespan    *Duration
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
	return c.TokenEndpointAuthMethod
}

// GetTokenEndpointAuthSigningAlgorithm implements fosite.OpenIDConnectClient.
func (*OIDCClient) GetTokenEndpointAuthSigningAlgorithm() string {
	// TODO: Support JWKs for authentication.
	return ""
}

// GetAudience implements fosite.Client.
func (c *OIDCClient) GetAudience() fosite.Arguments {
	return fosite.Arguments{c.OrganizationID.String(), c.AppID.String(), c.GetID()}
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
		errE := errors.New("unknown client type")
		errors.Details(errE)["type"] = c.Type
		// Internal error: this should never happen.
		panic(errE)
	}
}

// GetHashedSecret implements fosite.Client.
func (c *OIDCClient) GetHashedSecret() []byte {
	return c.Secret
}

// GetID implements fosite.Client.
func (c *OIDCClient) GetID() string {
	return c.ID.String()
}

// GetRedirectURIs implements fosite.Client.
func (c *OIDCClient) GetRedirectURIs() []string {
	return c.RedirectURIs
}

// GetResponseTypes implements fosite.Client.
func (*OIDCClient) GetResponseTypes() fosite.Arguments {
	// We allow only code and require apps to use token endpoint to retrieve tokens.
	// This prevents tokens from being logged anywhere.
	return fosite.Arguments{"code"}
}

// GetScopes implements fosite.Client.
func (c *OIDCClient) GetScopes() fosite.Arguments {
	return fosite.Arguments(c.Scopes)
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

// GetEffectiveLifespan implements fosite.ClientWithCustomTokenLifespans.
func (c *OIDCClient) GetEffectiveLifespan(_ fosite.GrantType, tt fosite.TokenType, fallback time.Duration) time.Duration {
	switch tt {
	case fosite.AccessToken:
		return time.Duration(c.AccessTokenLifespan)
	case fosite.RefreshToken:
		if c.RefreshTokenLifespan == nil {
			return -1
		}
		return time.Duration(*c.RefreshTokenLifespan)
	case fosite.IDToken:
		return time.Duration(c.IDTokenLifespan)
	case fosite.AuthorizeCode, fosite.PushedAuthorizeRequestContext:
		return fallback
	default:
		panic(errors.Errorf("unknown token type: %s", tt))
	}
}
