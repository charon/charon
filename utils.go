package charon

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"

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

func (s *Service) RequireAuthenticated(w http.ResponseWriter, req *http.Request, api bool, targetName string) context.Context {
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
		ID:              id,
		Session:         nil,
		Completed:       "",
		TargetLocation:  req.URL.String(),
		TargetName:      targetName,
		Provider:        "",
		EmailOrUsername: "",
		Attempts:        0,
		OIDC:            nil,
		Passkey:         nil,
		Password:        nil,
		Code:            nil,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}

	location, errE := s.Reverse("AuthFlow", waf.Params{"id": id.String()}, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}
	s.TemporaryRedirectGetMethod(w, req, location)
	return nil
}

func (s *Service) GetActiveFlow(w http.ResponseWriter, req *http.Request, value string) *Flow {
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
	host := domain
	if port != "443" {
		host = net.JoinHostPort(host, port)
	}
	return host, nil
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
func getKeyThumbprint(publicKey *ecdsa.PublicKey) (string, errors.E) {
	thumbprint, err := (&jose.JSONWebKey{
		Key:       publicKey,
		Algorithm: "ES256",
		Use:       "sig",
	}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// getKeyFingerprints computes SHA1 and SHA256 key fingerprints as described in RFC 7517, section 4.8,
// used for the "x5t" and "x5t#S256" fields of a JWK.
// See: https://tools.ietf.org/html/rfc7517#section-4.8
func getKeyFingerprints(publicKey *ecdsa.PublicKey) ([]byte, []byte, errors.E) {
	pemKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	fingerprintsSha1 := sha1.Sum(pemKey) //nolint:gosec
	fingerprintsSha256 := sha256.Sum256(pemKey)
	return fingerprintsSha1[:], fingerprintsSha256[:], nil
}

// makeJSONWebKey makes a JWK of the public key from the ECDSA public key.
func makeJSONWebKey(publicKey *ecdsa.PublicKey) (jose.JSONWebKey, errors.E) {
	thumbprint, errE := getKeyThumbprint(publicKey)
	if errE != nil {
		return jose.JSONWebKey{}, errE
	}
	fingerprintsSha1, fingerprintsSha256, errE := getKeyFingerprints(publicKey)
	if errE != nil {
		return jose.JSONWebKey{}, errE
	}
	return jose.JSONWebKey{
		Key:       publicKey,
		Algorithm: "ES256",
		Use:       "sig",
		KeyID:     thumbprint,
		// We initialize this explicitly to an empty slice so that it is not nil. Otherwise JSON
		// serialization and deserialization is not an identity, as it converts nil to an empty slice.
		Certificates: []*x509.Certificate{},
		// This is made into the "x5t" field.
		CertificateThumbprintSHA1: fingerprintsSha1,
		// This is made into the "x5t#S256" field.
		CertificateThumbprintSHA256: fingerprintsSha256,
	}, nil
}
