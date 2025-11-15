package charon

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/ory/fosite"
	saml2 "github.com/russellhaering/gosaml2"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
	"golang.org/x/text/secure/precis"
	"golang.org/x/text/unicode/norm"
)

const (
	sessionCookiePrefix = "__Host-session-"
)

var ErrIdentityNotPresent = errors.Base("identity not present")

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation.
type contextKey struct {
	name string
}

// identityIDContextKey provides current identity ID.
var identityIDContextKey = &contextKey{"identity"} //nolint:gochecknoglobals

// accountIDContextKey provides current account ID.
var accountIDContextKey = &contextKey{"account"} //nolint:gochecknoglobals

// serviceContextKey provides current service instance.
var serviceContextKey = &contextKey{"service"} //nolint:gochecknoglobals

// sessionIDContextKey provides current session ID.
var sessionIDContextKey = &contextKey{"sessionID"} //nolint:gochecknoglobals

//nolint:gochecknoglobals
var (
	// This is similar to precis.UsernameCasePreserved, but also disallows empty usernames.
	// See: https://github.com/golang/go/issues/64531
	usernameCasePreserved = precis.NewIdentifier(
		precis.FoldWidth,
		precis.Norm(norm.NFC),
		precis.BidiRule,
		precis.DisallowEmpty,
	)
	// This is similar to precis.UsernameCaseMapped, but also disallows empty usernames.
	// See: https://github.com/golang/go/issues/64531
	usernameCaseMapped = precis.NewIdentifier(
		precis.FoldWidth,
		precis.LowerCase(),
		precis.Norm(norm.NFC),
		precis.BidiRule,
		precis.DisallowEmpty,
	)
)

type emptyRequest struct{}

func getBearerToken(req *http.Request) string {
	const prefix = "Bearer "
	auth := req.Header.Get("Authorization")
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return auth[len(prefix):]
}

func (s *Service) withAccountID(ctx context.Context, accountID identifier.Identifier) context.Context {
	return context.WithValue(ctx, accountIDContextKey, accountID)
}

func (s *Service) withIdentityID(ctx context.Context, identityID identifier.Identifier) context.Context {
	return context.WithValue(ctx, identityIDContextKey, identityID)
}

func (s *Service) withSessionID(ctx context.Context, sessionID identifier.Identifier) context.Context {
	return context.WithValue(ctx, sessionIDContextKey, sessionID)
}

// TODO: In getIdentityFromRequest we should probably differentiate between header not present and header having invalid access token.
//       If header is not present, caller probably expects public data. If header is present then caller probably expects
//       that the token is valid and if not it might be a surprise to return just public data (like that the header wa not present).

// getIdentityFromRequest uses an Authorization header to obtain the OIDC access token
// and determines the identity, account, and session IDs from it.
func (s *Service) getIdentityFromRequest(
	w http.ResponseWriter, req *http.Request, audience string,
) (identifier.Identifier, identifier.Identifier, identifier.Identifier, errors.E) {
	// OIDC GetClient requires ctx with serviceContextKey set.
	ctx := context.WithValue(req.Context(), serviceContextKey, s)
	oidc := s.oidc()

	// We use this header so responses might depend on it.
	if !slices.Contains(w.Header().Values("Vary"), "Authorization") {
		// This function might have been called multiple times, but
		// we want to add this header with this value only once.
		w.Header().Add("Vary", "Authorization")
	}

	token := getBearerToken(req)
	if token == "" {
		return identifier.Identifier{}, identifier.Identifier{}, identifier.Identifier{}, errors.WithStack(ErrIdentityNotPresent)
	}

	// Create an empty session object which serves as a prototype of the reconstructed session object.
	session := new(OIDCSession)

	// TODO: Require some scope the access token must have?
	tu, ar, err := oidc.IntrospectToken(ctx, token, fosite.AccessToken, session)
	if err != nil {
		// Any error from this function is seen also in Fosite as an inactive token.
		errE := withFositeError(err)
		return identifier.Identifier{}, identifier.Identifier{}, identifier.Identifier{}, errors.WrapWith(errE, ErrIdentityNotPresent)
	}

	if tu != fosite.AccessToken {
		return identifier.Identifier{}, identifier.Identifier{}, identifier.Identifier{}, errors.WithStack(ErrIdentityNotPresent)
	}

	// We have to make sure the access token provided is really meant for the audience.
	// See: https://github.com/ory/fosite/issues/845
	if slices.Contains(ar.GetGrantedAudience(), audience) {
		session = ar.GetSession().(*OIDCSession) //nolint:errcheck,forcetypeassert
		return session.Subject, session.AccountID, session.SessionID, nil
	}

	return identifier.Identifier{}, identifier.Identifier{}, identifier.Identifier{}, errors.WithStack(ErrIdentityNotPresent)
}

func (s *Service) getSessionFromCookieValue(ctx context.Context, cookieValue string) (*session, errors.E) {
	// We use a prefix to aid secret scanners.
	if !strings.HasPrefix(cookieValue, SecretPrefixSession) {
		return nil, errors.Wrapf(errSessionNotFound, `cookie value does not have "%s" prefix`, SecretPrefixSession)
	}

	token := strings.TrimPrefix(cookieValue, SecretPrefixSession)

	err := s.hmac.Validate(ctx, token)
	if err != nil {
		return nil, errors.WrapWith(err, errSessionNotFound)
	}

	secretID, err := base64.RawURLEncoding.DecodeString(s.hmac.Signature(token))
	if err != nil {
		// This should not happen as we validated the token.
		return nil, errors.WithStack(err)
	}

	return s.getSessionBySecretID(ctx, [32]byte(secretID))
}

// getSessionFromRequest uses a session cookie to determine current session for flow's ID, if any.
func (s *Service) getSessionFromRequest(w http.ResponseWriter, req *http.Request, flowID identifier.Identifier) (*session, errors.E) {
	ctx := req.Context()

	// We use this header so responses might depend on it.
	if !slices.Contains(w.Header().Values("Vary"), "Cookie") {
		// This function might have been called multiple times, but
		// we want to add this header with this value only once.
		w.Header().Add("Vary", "Cookie")
	}

	cookie, err := req.Cookie(sessionCookiePrefix + flowID.String())
	if errors.Is(err, http.ErrNoCookie) {
		return nil, errors.WithStack(errSessionNotFound)
	} else if err != nil {
		return nil, errors.WithStack(err)
	}

	return s.getSessionFromCookieValue(ctx, cookie.Value)
}

// validateSession returns session only if current session matches one made by the flow.
func (s *Service) validateSession(w http.ResponseWriter, req *http.Request, api bool, flow *flow) (*session, bool) {
	session, errE := s.getSessionFromRequest(w, req, flow.ID)
	if errors.Is(errE, errSessionNotFound) {
		if api {
			waf.Error(w, req, http.StatusUnauthorized)
			return nil, true
		}
		// We return false and leave to frontend to load the flow using API to show the error.
		return nil, false
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil, true
	}

	// Caller should call validateSession only when flow.Session is set.
	if *flow.SessionID == session.ID {
		// Fast path so that we do not have to fetch another session if it is the same session.
		return session, false
	}

	flowSession, errE := s.getSession(req.Context(), *flow.SessionID)
	if errors.Is(errE, errSessionNotFound) {
		if api {
			waf.Error(w, req, http.StatusUnauthorized)
			return nil, true
		}
		// We return false and leave to frontend to load the flow using API to show the error.
		return nil, false
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil, true
	}

	// Session might have changed, but is it still the same account? This should be pretty rare,
	// because every session cookie is bound to a particular flow, so having an active session
	// for one flow does not mean you can access another flow. But we check anyway because somebody
	// might be manually changing to which flow the session cookie is bound to by renaming it.
	if flowSession.AccountID != session.AccountID {
		if api {
			waf.Error(w, req, http.StatusUnauthorized)
			return nil, true
		}
		// We return false and leave to frontend to load the flow using API to show the error.
		return nil, false
	}

	return session, false
}

// getFlowFromID obtains Flow from its string ID.
func (s *Service) getFlowFromID(ctx context.Context, value string) (*flow, errors.E) {
	id, errE := identifier.MaybeString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrFlowNotFound)
	}

	return s.getFlow(ctx, id)
}

func getAccountID(ctx context.Context) (identifier.Identifier, bool) {
	i, ok := ctx.Value(accountIDContextKey).(identifier.Identifier)
	return i, ok
}

func mustGetAccountID(ctx context.Context) identifier.Identifier {
	a, ok := getAccountID(ctx)
	if !ok {
		// Internal error: this should never happen.
		panic(errors.New("account not found in context"))
	}
	return a
}

func getIdentityID(ctx context.Context) (identifier.Identifier, bool) {
	i, ok := ctx.Value(identityIDContextKey).(identifier.Identifier)
	return i, ok
}

func mustGetIdentityID(ctx context.Context) identifier.Identifier {
	i, ok := getIdentityID(ctx)
	if !ok {
		// Internal error: this should never happen.
		panic(errors.New("identity not found in context"))
	}
	return i
}

func getSessionID(ctx context.Context) (identifier.Identifier, bool) {
	s, ok := ctx.Value(sessionIDContextKey).(identifier.Identifier)
	return s, ok
}

func mustGetSessionID(ctx context.Context) identifier.Identifier {
	s, ok := getSessionID(ctx)
	if !ok {
		// Internal error: this should never happen.
		panic(errors.New("session not found in context"))
	}
	return s
}

// RequireAuthenticated requires valid Authorization header with the OIDC access token
// and returns context with access token's identity stored in the context.
//
// It is expected to be used from API calls.
func (s *Service) RequireAuthenticated(w http.ResponseWriter, req *http.Request) context.Context {
	ctx := req.Context()
	co := s.charonOrganization()

	identityID, accountID, sessionID, errE := s.getIdentityFromRequest(w, req, co.AppID.String())
	if errE == nil {
		ctx = s.withAccountID(ctx, accountID)
		ctx = s.withIdentityID(ctx, identityID)
		ctx = s.withSessionID(ctx, sessionID)
		return ctx
	} else if !errors.Is(errE, ErrIdentityNotPresent) {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}

	waf.Error(w, req, http.StatusUnauthorized)
	return nil
}

// requireAuthenticatedForIdentity is similar to RequireAuthenticated but it checks both
// the Authorization header for the OIDC access token and the session cookie and returns
// context with account ID stored in the context. When used with the Authorization header,
// identity ID is also stored in the context under identityIDContextKey.
//
// It is expected to be used from API calls. There has to be a query string parameter
// "flow" with the flow ID when not used with the Authorization header.
func (s *Service) requireAuthenticatedForIdentity(w http.ResponseWriter, req *http.Request) context.Context {
	ctx := req.Context()
	co := s.charonOrganization()

	identityID, accountID, sessionID, errE := s.getIdentityFromRequest(w, req, co.AppID.String())
	if errE == nil {
		ctx = s.withAccountID(ctx, accountID)
		ctx = s.withIdentityID(ctx, identityID)
		ctx = s.withSessionID(ctx, sessionID)
		return ctx
	} else if !errors.Is(errE, ErrIdentityNotPresent) {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}

	flow, errE := s.getFlowFromID(ctx, req.Form.Get("flow"))
	if errors.Is(errE, ErrFlowNotFound) {
		s.WithError(ctx, errE)
		waf.Error(w, req, http.StatusUnauthorized)
		return nil
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}

	session, handled := s.validateSession(w, req, true, flow)
	if handled {
		return nil
	}

	// Because we called validateSession with api set to true, session should never be nil here.
	ctx = s.withAccountID(ctx, session.AccountID)
	ctx = s.withSessionID(ctx, session.ID)
	return ctx
}

func (s *Service) getFlowHandler(w http.ResponseWriter, req *http.Request, value string) *flow {
	flow, errE := s.getFlowFromID(req.Context(), value)
	if errors.Is(errE, ErrFlowNotFound) {
		s.NotFoundWithError(w, req, errE)
		return nil
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}

	return flow
}

func (s *Service) getActiveFlow(w http.ResponseWriter, req *http.Request, value string) *flow {
	flow := s.getFlowHandler(w, req, value)
	if flow == nil {
		return nil
	}

	// Has flow already completed?
	if flow.IsFinished() {
		waf.Error(w, req, http.StatusUnauthorized)
		return nil
	}

	return flow
}

func (s *Service) getActiveFlowNoAuthStep(w http.ResponseWriter, req *http.Request, value string) *flow {
	flow := s.getActiveFlow(w, req, value)
	if flow == nil {
		return nil
	}

	// Has auth step already been completed?
	if len(flow.Completed) > 0 {
		s.BadRequestWithError(w, req, errors.New("auth step already completed"))
		return nil
	}

	return flow
}

func (s *Service) getActiveFlowWithSession(w http.ResponseWriter, req *http.Request, value string) (identifier.Identifier, *flow) {
	flow := s.getActiveFlow(w, req, value)
	if flow == nil {
		return identifier.Identifier{}, nil
	}

	// Flow should already successfully (session is not nil) completed auth step,
	// but not the final step (we checked that in GetActiveFlow() above).
	if flow.SessionID == nil {
		s.BadRequestWithError(w, req, errors.New("auth step not completed"))
		return identifier.Identifier{}, nil
	}

	// Current session should match the session in the flow.
	session, handled := s.validateSession(w, req, true, flow)
	if handled {
		return identifier.Identifier{}, nil
	}

	// session cannot be nil because we call validateSession with api parameter set to true.
	return session.AccountID, flow
}

func getHost(config *Config, domain string) (string, errors.E) {
	// ListenAddr blocks until the server runs.
	listenAddr := config.Server.ListenAddr()
	if listenAddr == "" {
		// Server failed to start. We just return in this case.
		return "", nil
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", errors.WithStack(err)
	}
	if port == "" {
		return "", errors.New("port empty")
	}
	host := domain
	if port != "443" {
		host = net.JoinHostPort(host, port)
	}
	return host, nil
}

func initWithHost[T any](config *Config, domain string, init func(string) T) (func() T, errors.E) {
	// Port is explicitly provided.
	if config.ExternalPort != 0 {
		host := domain
		if config.ExternalPort != 443 { //nolint:mnd
			host = net.JoinHostPort(host, strconv.Itoa(config.ExternalPort))
		}
		value := init(host)
		return func() T {
			return value
		}, nil
	}

	_, port, err := net.SplitHostPort(config.Server.Addr)
	if err != nil {
		errE := errors.WithMessage(err, "server address")
		errors.Details(errE)["address"] = config.Server.Addr
		return nil, errE
	} else if port == "" {
		return nil, errors.New("server address: port empty")
	}

	// The common case: port is known in advance.
	if port != "0" {
		host := domain
		if port != "443" {
			host = net.JoinHostPort(host, port)
		}
		value := init(host)
		return func() T {
			return value
		}, nil
	}

	return sync.OnceValue[T](func() T {
		// This blocks until the server runs.
		host, errE := getHost(config, domain)
		if errE != nil {
			// Internal error: this should never happen.
			panic(errE)
		}
		if host == "" {
			// Server failed to start. We just return in this case.
			return *new(T)
		}

		return init(host)
	}), nil
}

func hasConnectionUpgrade(req *http.Request) bool {
	for _, value := range strings.Split(req.Header.Get("Connection"), ",") {
		if strings.ToLower(strings.TrimSpace(value)) == "upgrade" {
			return true
		}
	}
	return false
}

// normalizeUsernameCasePreserved normalizes username according to the
// UsernameCasePreserved profile from RFC 8265 with addition of removing
// leading and trailing whitespace and not allowing whitespace anywhere else.
func normalizeUsernameCasePreserved(username string) (string, errors.E) {
	// Our addition: remove leading and trailing whitespace.
	username = strings.TrimSpace(username)
	username, err := usernameCasePreserved.String(username)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return username, nil
}

// normalizeUsernameCaseMapped normalizes username according to the
// UsernameCaseMapped profile from RFC 8265 with addition of removing
// leading and trailing whitespace.
func normalizeUsernameCaseMapped(username string) (string, errors.E) {
	// Our addition: remove leading and trailing whitespace.
	username = strings.TrimSpace(username)
	username, err := usernameCaseMapped.String(username)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return username, nil
}

// normalizePassword normalizes password according to the OpaqueString profile
// from RFC 8265.
func normalizePassword(password []byte) ([]byte, errors.E) {
	password, err := precis.OpaqueString.Bytes(password)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return password, nil
}

func getRandomCode() (string, errors.E) {
	randomNumber, err := rand.Int(rand.Reader, big.NewInt(1000000)) //nolint:mnd
	if err != nil {
		return "", errors.WithStack(err)
	}
	return fmt.Sprintf("%06d", randomNumber), nil
}

// pointerEqual returns true if both pointers are nil or if they point to equal values.
func pointerEqual[T comparable](a *T, b *T) bool {
	if a == nil && b == nil {
		return true
	}
	if a != nil && b != nil {
		return *a == *b
	}
	return false
}

// getKeyThumbprint computes SHA256 key thumbprint as described in RFC 7638,
// which we use for the "kid" (key ID) field of a JWK.
// See: https://tools.ietf.org/html/rfc7638
func getKeyThumbprint(publicKey interface{}, algorithm string) (string, errors.E) {
	thumbprint, err := (&jose.JSONWebKey{ //nolint:exhaustruct
		Key:       publicKey,
		Algorithm: algorithm,
		Use:       "sig",
	}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// getKeyThumbprints computes SHA1 and SHA256 key thumbprints as described in RFC 7517,
// section 4.8, used for the "x5t" and "x5t#S256" fields of a JWK.
// See: https://tools.ietf.org/html/rfc7517#section-4.8
func getKeyThumbprints(publicKey interface{}) ([]byte, []byte, errors.E) {
	pemKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	thumbprintsSha1 := sha1.Sum(pemKey) //nolint:gosec
	thumbprintsSha256 := sha256.Sum256(pemKey)
	return thumbprintsSha1[:], thumbprintsSha256[:], nil
}

// makeJSONWebKey makes a JWK of the private key.
func makeJSONWebKey(privateKey crypto.Signer, algorithm string) (*jose.JSONWebKey, errors.E) {
	thumbprint, errE := getKeyThumbprint(privateKey.Public(), algorithm)
	if errE != nil {
		return nil, errE
	}
	thumbprintsSha1, thumbprintsSha256, errE := getKeyThumbprints(privateKey.Public())
	if errE != nil {
		return nil, errE
	}
	return &jose.JSONWebKey{
		Key:       privateKey,
		Algorithm: algorithm,
		Use:       "sig",
		KeyID:     thumbprint,
		// We initialize this explicitly to an empty slice so that it is not nil. Otherwise JSON
		// serialization and deserialization is not an identity, as it converts nil to an empty slice.
		Certificates:    []*x509.Certificate{},
		CertificatesURL: nil,
		// This is made into the "x5t" field.
		CertificateThumbprintSHA1: thumbprintsSha1,
		// This is made into the "x5t#S256" field.
		CertificateThumbprintSHA256: thumbprintsSha256,
	}, nil
}

func generateEllipticKey(c elliptic.Curve, algorithm string) (*jose.JSONWebKey, errors.E) {
	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return makeJSONWebKey(privateKey, algorithm)
}

//nolint:unused
func makeEllipticKey(privateKey []byte, c elliptic.Curve, algorithm string) (*jose.JSONWebKey, errors.E) {
	var jwk jose.JSONWebKey
	err := json.Unmarshal(privateKey, &jwk)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	key, ok := jwk.Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA private key")
	}

	if key.Params().Name != c.Params().Name {
		errE := errors.New("a different curve than expected")
		errors.Details(errE)["got"] = key.Params().Name
		errors.Details(errE)["expected"] = c.Params().Name
		return nil, errE
	}

	// We on purpose ignore all other fields and reconstruct JWK from scratch.
	// This assures all our keys have same JWK representation.
	return makeJSONWebKey(key, algorithm)
}

func generateRSAKey() (*jose.JSONWebKey, errors.E) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096) //nolint:mnd
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// TODO: This is currently hard-coded to RS256 until we can support all from signingAlgValuesSupported.
	//       See: https://github.com/ory/fosite/issues/788
	return makeJSONWebKey(privateKey, "RS256")
}

func makeRSAKey(privateKey []byte) (*jose.JSONWebKey, errors.E) {
	var jwk jose.JSONWebKey
	err := json.Unmarshal(privateKey, &jwk)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	key, ok := jwk.Key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	// We on purpose ignore all other fields and reconstruct JWK from scratch.
	// This assures all our keys have same JWK representation.
	// TODO: This is currently hard-coded to RS256 until we can support all from signingAlgValuesSupported.
	//       See: https://github.com/ory/fosite/issues/788
	return makeJSONWebKey(key, "RS256")
}

func makeAnyKey(privateKey []byte) (*jose.JSONWebKey, errors.E) {
	var jwk jose.JSONWebKey
	err := json.Unmarshal(privateKey, &jwk)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// We on purpose ignore all other fields and reconstruct JWK from scratch.
	// This assures all our keys have same JWK representation.
	switch key := jwk.Key.(type) {
	case *rsa.PrivateKey:
		// TODO: This is currently hard-coded to RS256 until we can support all from signingAlgValuesSupported.
		//       See: https://github.com/ory/fosite/issues/788
		return makeJSONWebKey(key, "RS256")
	case *ecdsa.PrivateKey:
		switch key.Params().Name {
		case elliptic.P256().Params().Name:
			return makeJSONWebKey(key, "ES256")
		case elliptic.P384().Params().Name:
			return makeJSONWebKey(key, "ES384")
		case elliptic.P521().Params().Name:
			return makeJSONWebKey(key, "ES512")
		}
	}

	return nil, errors.New("unsupported private key")
}

func validRedirectLocation(service *Service, location string) (string, errors.E) {
	if location == "" {
		return "", errors.New("invalid location")
	}

	u, err := url.Parse(location)
	if err != nil {
		return "", errors.WithMessage(err, "invalid location")
	}

	if u.Scheme != "" || u.Host != "" || u.Opaque != "" || u.User != nil {
		return "", errors.New("invalid location")
	}

	_, errE := service.GetRoute(u.Path, http.MethodGet)
	if errE != nil {
		return "", errors.WithMessage(errE, "invalid location")
	}

	return u.String(), nil
}

func withWebauthnError(err error) errors.E {
	if err == nil {
		return nil
	}

	errE := errors.WithStack(err)
	var e *protocol.Error
	if errors.As(err, &e) {
		details := errors.Details(errE)
		if e.Type != "" {
			details["type"] = e.Type
		}
		if e.DevInfo != "" {
			details["debug"] = e.DevInfo
		}
	}

	return errE
}

type unwrapper interface {
	Unwrap() error
}

func withGosamlError(err error) errors.E {
	if err == nil {
		return nil
	}

	errE := errors.WithStack(err)
	var errVerification saml2.ErrVerification
	var errMissingElement saml2.ErrMissingElement
	var errSaml saml2.ErrSaml
	var errParsing saml2.ErrParsing
	var errInvalidValue saml2.ErrInvalidValue
	if errors.As(err, &errVerification) { //nolint:nestif
		// We check if errVerification maybe already implements Unwrap.
		// See: https://github.com/russellhaering/gosaml2/pull/242
		if _, ok := interface{}(errVerification).(unwrapper); errVerification.Cause != nil && !ok {
			errE = errors.WrapWith(errVerification.Cause, errE)
		}
	} else if errors.As(err, &errMissingElement) {
		details := errors.Details(errE)
		if errMissingElement.Tag != "" {
			details["tag"] = errMissingElement.Tag
		}
		if errMissingElement.Attribute != "" {
			details["namespace"] = errMissingElement.Attribute
		}
	} else if errors.As(err, &errSaml) {
		// We check if errSaml maybe already implements Unwrap.
		// See: https://github.com/russellhaering/gosaml2/pull/242
		if _, ok := interface{}(errSaml).(unwrapper); errSaml.System != nil && !ok {
			errE = errors.WrapWith(errSaml.System, errE)
		}
	} else if errors.As(err, &errParsing) {
		details := errors.Details(errE)
		if errParsing.Tag != "" {
			details["tag"] = errParsing.Tag
		}
		if errParsing.Value != "" {
			details["value"] = errParsing.Value
		}
		if errParsing.Type != "" {
			details["type"] = errParsing.Type
		}
	} else if errors.As(err, &errInvalidValue) {
		details := errors.Details(errE)
		if errInvalidValue.Key != "" {
			details["key"] = errInvalidValue.Key
		} else if errInvalidValue.Expected != "" {
			details["expected"] = errInvalidValue.Expected
		} else if errInvalidValue.Actual != "" {
			details["actual"] = errInvalidValue.Actual
		} else if errInvalidValue.Reason != "" {
			details["reason"] = errInvalidValue.Reason
		}
	}

	return errE
}

func withFositeError(err error) errors.E {
	if err == nil {
		return nil
	}

	errE := errors.WithStack(err)
	var e *fosite.RFC6749Error
	if errors.As(err, &e) {
		details := errors.Details(errE)
		if e.DescriptionField != "" {
			details["description"] = e.DescriptionField
		}
		if e.HintField != "" {
			details["hint"] = e.HintField
		}
		if e.CodeField != 0 {
			details["code"] = e.CodeField
		}
		if e.DebugField != "" {
			details["debug"] = e.DebugField
		}
	}

	return errE
}

func removeDuplicates[T comparable](input []T) []T {
	seen := mapset.NewThreadUnsafeSet[T]()
	result := make([]T, 0, len(input))
	for _, val := range input {
		if !seen.Contains(val) {
			result = append(result, val)
			seen.Add(val)
		}
	}
	return result
}

// detectSliceChanges compares two slices and returns elements that were added and removed.
func detectSliceChanges[T comparable](oldSlice, newSlice []T) (mapset.Set[T], mapset.Set[T]) {
	oldSet := mapset.NewThreadUnsafeSet[T](oldSlice...)
	newSet := mapset.NewThreadUnsafeSet[T](newSlice...)

	return newSet.Difference(oldSet), oldSet.Difference(newSet)
}

// findFirstString returns the first non-empty string value (after whitespace trimming) for keyNames in the map.
// It returns an empty string if no such value is found.
func findFirstString(m map[string]interface{}, keyNames ...string) string {
	for _, key := range keyNames {
		value, _ := m[key].(string)
		v := strings.TrimSpace(value)
		if v != "" {
			return v
		}

		// TODO: What to do here? Should we create multiple identities for each of the value?
		arr, _ := m[key].([]interface{})
		for _, item := range arr {
			s, _ := item.(string)
			s = strings.TrimSpace(s)
			if s != "" {
				return s
			}
		}
	}
	return ""
}

func generatePasswordEncryptionKeys() ([]byte, []byte, []byte, int, errors.E) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, 0, errors.WithStack(err)
	}

	// We create a dummy cipher so that we can obtain nonce size later on.
	block, err := aes.NewCipher(make([]byte, secretSize))
	if err != nil {
		return nil, nil, nil, 0, errors.WithStack(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, 0, errors.WithStack(err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, nil, 0, errors.WithStack(err)
	}

	return privateKey.Bytes(), privateKey.PublicKey().Bytes(), nonce, aesgcm.Overhead(), nil
}

func decryptEncryptedPassword(privateKeyBytes []byte, publicKeyBytes []byte, nonce []byte, encryptedPassword []byte,
) ([]byte, errors.E) {
	privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	remotePublicKey, err := ecdh.P256().NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	secret, err := privateKey.ECDH(remotePublicKey)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// TODO: Use memguard to protect plain password in memory.
	//       See: https://github.com/awnumar/memguard
	plainPassword, err := aesgcm.Open(nil, nonce, encryptedPassword, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return plainPassword, nil
}

func newPasswordEncryptionResponse(publicKeyBytes, nonce []byte, overhead int) *AuthFlowResponsePassword {
	return &AuthFlowResponsePassword{
		PublicKey: publicKeyBytes,
		DeriveOptions: AuthFlowResponsePasswordDeriveOptions{
			Name:       "ECDH",
			NamedCurve: "P-256",
		},
		EncryptOptions: AuthFlowResponsePasswordEncryptOptions{
			Name:      "AES-GCM",
			Nonce:     nonce,
			TagLength: 8 * overhead,   //nolint:mnd
			Length:    8 * secretSize, //nolint:mnd
		},
	}
}

func beginPasskeyRegistration(provider *webauthn.WebAuthn, userID identifier.Identifier, label string,
) (*protocol.CredentialCreation, *webauthn.SessionData, errors.E) {
	options, session, err := provider.BeginRegistration(
		passkeyCredential{
			ID:         userID,
			Label:      label,
			Credential: nil,
		},
		webauthn.WithExtensions(protocol.AuthenticationExtensions{
			"credentialProtectionPolicy":        "userVerificationRequired",
			"enforceCredentialProtectionPolicy": false,
		}),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: "",
			RequireResidentKey:      protocol.ResidentKeyRequired(),
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			UserVerification:        protocol.VerificationRequired,
		}),
		withPreferredCredentialAlgorithms([]webauthncose.COSEAlgorithmIdentifier{
			webauthncose.AlgEdDSA,
			webauthncose.AlgES256,
			webauthncose.AlgRS256,
		}),
	)
	if err != nil {
		return nil, nil, withWebauthnError(err)
	}
	return options, session, nil
}

// EmailOrUsernameCheck specifies validation requirements for email or username input.
type EmailOrUsernameCheck int

const (
	// EmailOrUsernameCheckAny does not check for "@".
	EmailOrUsernameCheckAny EmailOrUsernameCheck = iota
	// EmailOrUsernameCheckEmail requires "@" (email format).
	EmailOrUsernameCheckEmail
	// EmailOrUsernameCheckUsername requires NO "@" (username format).
	EmailOrUsernameCheckUsername
)

func normalizeEmailOrUsername(emailOrUsername string, check EmailOrUsernameCheck) (string, string, ErrorCode, errors.E) {
	preserved, errE := normalizeUsernameCasePreserved(emailOrUsername)
	if errE != nil {
		return "", "", "", errE
	}

	if len(preserved) < emailOrUsernameMinLength {
		return "", "", ErrorCodeShortEmailOrUsername, nil
	}

	containsAt := strings.Contains(preserved, "@")

	switch check {
	case EmailOrUsernameCheckAny:
	case EmailOrUsernameCheckEmail:
		if !containsAt {
			return "", "", ErrorCodeInvalidEmailOrUsername, nil
		}
	case EmailOrUsernameCheckUsername:
		if containsAt {
			return "", "", ErrorCodeInvalidEmailOrUsername, nil
		}
	}

	mapped, errE := normalizeUsernameCaseMapped(preserved)
	if errE != nil {
		return "", "", "", errE
	}

	return preserved, mapped, "", nil
}

func (s *Service) completePasskeyRegistration(
	createResponse protocol.CredentialCreationResponse,
	label string,
	sessionData *webauthn.SessionData,
) (*passkeyCredential, string, errors.E) {
	parsedResponse, err := createResponse.Parse()
	if err != nil {
		return nil, "", errors.WithStack(err)
	}

	userID := identifier.Data([16]byte(sessionData.UserID))

	pkCredential := passkeyCredential{
		ID:         userID,
		Label:      label,
		Credential: nil,
	}

	pkCredential.Credential, err = s.passkeyProvider().CreateCredential(pkCredential, *sessionData, parsedResponse)
	if err != nil {
		return nil, "", withWebauthnError(err)
	}

	providerID := base64.RawURLEncoding.EncodeToString(pkCredential.Credential.ID)

	return &pkCredential, providerID, nil
}
