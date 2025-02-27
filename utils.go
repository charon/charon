package charon

import (
	"context"
	"crypto"
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
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/ory/fosite"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
	"golang.org/x/text/secure/precis"
	"golang.org/x/text/unicode/norm"
)

const (
	SessionCookieName = "__Host-session"
)

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation.
type contextKey struct {
	name string
}

// accountIDContextKey provides current account ID.
var accountIDContextKey = &contextKey{"account"} //nolint:gochecknoglobals

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

func (s *Service) getSessionFromRequest(w http.ResponseWriter, req *http.Request) (*Session, errors.E) {
	ctx := req.Context()

	// We use this header so responses might depend on it.
	if !slices.Contains(w.Header().Values("Vary"), "Cookie") {
		// This function might have been called multiple times, but
		// we want to add this header with this value only once.
		w.Header().Add("Vary", "Cookie")
	}

	cookie, err := req.Cookie(SessionCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, errors.WithStack(ErrSessionNotFound)
	} else if err != nil {
		return nil, errors.WithStack(err)
	}

	// We use a prefix to aid secret scanners.
	if !strings.HasPrefix(cookie.Value, SecretPrefixSession) {
		return nil, errors.Wrapf(ErrSessionNotFound, `cookie value does not have "%s" prefix`, SecretPrefixSession)
	}

	token := strings.TrimPrefix(cookie.Value, SecretPrefixSession)

	err = s.hmac.Validate(ctx, token)
	if err != nil {
		return nil, errors.WrapWith(err, ErrSessionNotFound)
	}

	secretID, err := base64.RawURLEncoding.DecodeString(s.hmac.Signature(token))
	if err != nil {
		// This should not happen as we validated the token.
		return nil, errors.WithStack(err)
	}

	return GetSessionBySecretID(ctx, [32]byte(secretID))
}

// getFlowFromID obtains Flow from its string ID.
func getFlowFromID(ctx context.Context, value string) (*Flow, errors.E) {
	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrFlowNotFound)
	}

	return GetFlow(ctx, id)
}

func getAccountID(ctx context.Context) (identifier.Identifier, bool) {
	a, ok := ctx.Value(accountIDContextKey).(identifier.Identifier)
	return a, ok
}

func mustGetAccountID(ctx context.Context) identifier.Identifier {
	a, ok := getAccountID(ctx)
	if !ok {
		panic(errors.New("account not found in context"))
	}
	return a
}

func (s *Service) RequireAuthenticated(w http.ResponseWriter, req *http.Request, api bool) context.Context {
	session, errE := s.getSessionFromRequest(w, req)
	if errE == nil {
		return context.WithValue(req.Context(), accountIDContextKey, session.AccountID)
	} else if !errors.Is(errE, ErrSessionNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}

	if api {
		waf.Error(w, req, http.StatusUnauthorized)
		return nil
	}

	id := identifier.New()
	errE = SetFlow(req.Context(), &Flow{
		ID:                   id,
		CreatedAt:            time.Now().UTC(),
		Session:              nil,
		Completed:            "",
		AuthTime:             nil,
		Target:               TargetSession,
		TargetLocation:       req.URL.String(),
		TargetName:           "Charon Dashboard",
		TargetOrganizationID: nil,
		Provider:             "",
		EmailOrUsername:      "",
		Attempts:             0,
		OIDCAuthorizeRequest: nil,
		Identity:             nil,
		OIDCRedirectReady:    false,
		OIDCProvider:         nil,
		Passkey:              nil,
		Password:             nil,
		Code:                 nil,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}

	location, errE := s.Reverse("AuthFlowGet", waf.Params{"id": id.String()}, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}
	s.TemporaryRedirectGetMethod(w, req, location)
	return nil
}

func (s *Service) GetFlow(w http.ResponseWriter, req *http.Request, value string) *Flow {
	flow, errE := getFlowFromID(req.Context(), value)
	if errors.Is(errE, ErrFlowNotFound) {
		s.NotFoundWithError(w, req, errE)
		return nil
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}

	return flow
}

func (s *Service) GetActiveFlow(w http.ResponseWriter, req *http.Request, value string) *Flow {
	flow := s.GetFlow(w, req, value)
	if flow == nil {
		return nil
	}

	// Has flow already completed?
	if flow.IsCompleted() {
		waf.Error(w, req, http.StatusGone)
		return nil
	}

	return flow
}

func (s *Service) GetActiveFlowNoAuthStep(w http.ResponseWriter, req *http.Request, value string) *Flow {
	flow := s.GetActiveFlow(w, req, value)
	if flow == nil {
		return nil
	}

	// Has auth step already been completed?
	if flow.Completed != "" {
		s.BadRequestWithError(w, req, errors.New("auth step already completed"))
		return nil
	}

	return flow
}

func (s *Service) GetActiveFlowAfterAuthStep(w http.ResponseWriter, req *http.Request, value string) (identifier.Identifier, *Flow) {
	flow := s.GetActiveFlow(w, req, value)
	if flow == nil {
		return identifier.Identifier{}, nil
	}

	// Flow should already successfully (session is not nil) completed auth step,
	// but not the final step (we checked that in GetActiveFlow() above).
	if flow.Completed == "" || flow.Session == nil {
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

func (s *Service) GetActiveFlowOIDCTarget(w http.ResponseWriter, req *http.Request, value string) (identifier.Identifier, *Flow) {
	flow := s.GetActiveFlow(w, req, value)
	if flow == nil {
		return identifier.Identifier{}, nil
	}

	if flow.Target != TargetOIDC {
		s.BadRequestWithError(w, req, errors.New("not OIDC target"))
		return identifier.Identifier{}, nil
	}
	// Flow already successfully (session is not nil) completed auth step, but not the final redirect step for the OIDC
	// target (we checked that flow.Completed != CompletedRedirect in flow.IsCompleted() check in GetActiveFlow() above).
	if flow.Completed == "" || flow.Session == nil {
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

func GenerateEllipticKey(c elliptic.Curve, algorithm string) (*jose.JSONWebKey, errors.E) {
	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return makeJSONWebKey(privateKey, algorithm)
}

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

func GenerateRSAKey() (*jose.JSONWebKey, errors.E) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096) //nolint:mnd
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// TODO: This is currently hard-coded to RS256 until we can support all from signingAlgValuesSupported.
	//       See: https://github.com/ory/fosite/issues/788
	return makeJSONWebKey(privateKey, "RS256")
}

func MakeRSAKey(privateKey []byte) (*jose.JSONWebKey, errors.E) {
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
