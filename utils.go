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
	"strings"
	"sync"

	"github.com/go-jose/go-jose/v3"
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

// accountContextKey provides current account ID.
var accountContextKey = &contextKey{"account"} //nolint:gochecknoglobals

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

func getSessionFromRequest(req *http.Request) (*Session, errors.E) {
	cookie, err := req.Cookie(SessionCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, errors.WithStack(ErrSessionNotFound)
	} else if err != nil {
		return nil, errors.WithStack(err)
	}

	id, errE := identifier.FromString(cookie.Value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrSessionNotFound)
	}

	return GetSession(req.Context(), id)
}

// getFlowFromID obtains Flow from its string ID.
func getFlowFromID(ctx context.Context, value string) (*Flow, errors.E) {
	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrFlowNotFound)
	}

	return GetFlow(ctx, id)
}

func getAccount(ctx context.Context) (identifier.Identifier, bool) {
	a, ok := ctx.Value(accountContextKey).(identifier.Identifier)
	return a, ok
}

func mustGetAccount(ctx context.Context) identifier.Identifier {
	a, ok := getAccount(ctx)
	if !ok {
		panic(errors.New("account not found in context"))
	}
	return a
}

func (s *Service) RequireAuthenticated(w http.ResponseWriter, req *http.Request, api bool) context.Context {
	session, errE := getSessionFromRequest(req)
	if errE == nil {
		return context.WithValue(req.Context(), accountContextKey, session.Account)
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
		Session:              nil,
		Completed:            "",
		Target:               TargetSession,
		TargetLocation:       req.URL.String(),
		TargetName:           "Charon Dashboard",
		TargetOrganization:   nil,
		Provider:             "",
		EmailOrUsername:      "",
		Attempts:             0,
		OIDCAuthorizeRequest: nil,
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
		s.WithError(req.Context(), errE)
		s.NotFound(w, req)
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

func (s *Service) GetActiveFlowOIDCTarget(w http.ResponseWriter, req *http.Request, value string) *Flow {
	flow := s.GetActiveFlow(w, req, value)
	if flow == nil {
		return nil
	}

	if flow.Target != TargetOIDC {
		s.BadRequestWithError(w, req, errors.New("not OIDC target"))
		return nil
	}
	// Flow already successfully (session is not nil) completed auth step, but not the final redirect step for the OIDC
	// target (we checked that flow.Completed != CompletedRedirect in flow.IsCompleted() check in GetActiveFlow() above).
	if flow.Completed == "" || flow.Session == nil {
		s.BadRequestWithError(w, req, errors.New("auth step not completed"))
		return nil
	}

	// Current session should match the session in the flow.
	if !s.validateSession(w, req, flow) {
		return nil
	}

	return flow
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
	_, port, err := net.SplitHostPort(config.Server.Addr)
	if err != nil {
		return nil, errors.WithMessage(err, "server address")
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
	randomNumber, err := rand.Int(rand.Reader, big.NewInt(1000000)) //nolint:gomnd
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

func makeEllipticKey(privateKey string, c elliptic.Curve, algorithm string) (*jose.JSONWebKey, errors.E) {
	var jwk jose.JSONWebKey
	err := json.Unmarshal([]byte(privateKey), &jwk)
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
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096) //nolint:gomnd
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// TODO: This is currently hard-coded to RS256 until we can support all from signingAlgValuesSupported.
	//       See: https://github.com/ory/fosite/issues/788
	return makeJSONWebKey(privateKey, "RS256")
}

func makeRSAKey(privateKey string) (*jose.JSONWebKey, errors.E) {
	var jwk jose.JSONWebKey
	err := json.Unmarshal([]byte(privateKey), &jwk)
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
