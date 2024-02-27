package charon_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	smtpmock "github.com/mocktools/go-smtp-mock/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	z "gitlab.com/tozd/go/zerolog"
	"gitlab.com/tozd/waf"
	"golang.org/x/net/publicsuffix"

	"gitlab.com/charon/charon"
)

//go:embed dist/index.html
var indexFile string

func TestRouteHome(t *testing.T) {
	t.Parallel()

	ts, service, _ := startTestServer(t)

	path, errE := service.Reverse("Home", nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Regular GET should just return the SPA index page.
	resp, err := ts.Client().Get(ts.URL + path) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"))
		assert.Equal(t, indexFile, string(out))
	}
}

func startTestServer(t *testing.T) (*httptest.Server, *charon.Service, *smtpmock.Server) {
	t.Helper()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test_cert.pem")
	keyPath := filepath.Join(tempDir, "test_key.pem")

	err := createTempCertificateFiles(certPath, keyPath, []string{"localhost"})
	require.NoError(t, err)

	logger := zerolog.New(zerolog.NewTestWriter(t))

	smtpServer := smtpmock.New(smtpmock.ConfigurationAttr{
		// See: https://github.com/mocktools/go-smtp-mock/issues/172
		MultipleMessageReceiving: true,
	})
	err = smtpServer.Start()
	require.NoError(t, err)
	t.Cleanup(func() { smtpServer.Stop() }) //nolint:errcheck

	config := charon.Config{
		LoggingConfig: z.LoggingConfig{
			Logger: logger,
		},
		Server: waf.Server[*charon.Site]{
			TLS: waf.TLS{
				CertFile: certPath,
				KeyFile:  keyPath,
			},
			// httptest.Server allocates a random port for its listener (but does not use config.Server.Addr to do so).
			// Having 0 for port here makes the rest of the codebase expect a random port and wait for its assignment.
			Addr: "localhost:0",
		},
		Mail: charon.Mail{
			Host: "127.0.0.1",
			Port: smtpServer.PortNumber(),
			From: "noreply@example.com",
			// go-smtp-mock does not support STARTTLS.
			// See: https://github.com/mocktools/go-smtp-mock/issues/76
			NotRequiredTLS: true,
		},
		OIDC: charon.OIDC{
			Development: true,
		},
	}

	handler, service, errE := config.Init()
	require.NoError(t, errE, "% -+#.1v", errE)

	ts := httptest.NewUnstartedServer(nil)
	ts.EnableHTTP2 = true
	t.Cleanup(ts.Close)

	ts.Config = config.Server.HTTPServer
	ts.Config.Handler = handler
	ts.TLS = config.Server.HTTPServer.TLSConfig.Clone()

	// We have to call GetCertificate ourselves.
	// See: https://github.com/golang/go/issues/63812
	cert, err := ts.TLS.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "localhost",
	})
	require.NoError(t, err, "% -+#.1v", err)
	// By setting Certificates, we force testing server and testing client to use our certificate.
	ts.TLS.Certificates = []tls.Certificate{*cert}

	// This does not start server.server's managers, but that is OK for this test.
	ts.StartTLS()

	// Our certificate is for localhost domain and not 127.0.0.1 IP.
	ts.URL = strings.ReplaceAll(ts.URL, "127.0.0.1", "localhost")

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	require.NoError(t, err)

	ts.Client().Jar = jar

	return ts, service, smtpServer
}

// Same as in waf package.
// TODO: Move it to tozd/go/x package?
func createTempCertificateFiles(certPath, keyPath string, domains []string) error {
	// Generate a new ECDSA private key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// Create a self-signed certificate.
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour), // Set an expiration time.
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              domains,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Write the certificate to a file.
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err != nil {
		return err
	}

	// Write the private key to a file.
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}

	err = pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	if err != nil {
		return err
	}

	return nil
}
