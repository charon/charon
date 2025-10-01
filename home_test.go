package charon_test

import (
	"crypto/tls"
	"embed"
	"io"
	"io/fs"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	smtpmock "github.com/mocktools/go-smtp-mock/v2"
	"github.com/ory/fosite"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	z "gitlab.com/tozd/go/zerolog"
	"gitlab.com/tozd/waf"
	"golang.org/x/net/publicsuffix"

	"gitlab.com/charon/charon"
)

//go:embed public
var publicFiles embed.FS

var testFiles = fstest.MapFS{ //nolint:gochecknoglobals
	"dist/index.html": &fstest.MapFile{
		Data: []byte("<html><body>dummy test content</body></html>"),
	},
	// Symlinks are not included in publicFiles.
	"dist/LICENSE.txt": &fstest.MapFile{
		Data: []byte("test license file"),
	},
	"dist/NOTICE.txt": &fstest.MapFile{
		Data: []byte("test notice file"),
	},
}

func init() { //nolint:gochecknoinits
	f, err := fs.Sub(publicFiles, "public")
	if err != nil {
		panic(err)
	}

	err = fs.WalkDir(f, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		data, err := f.(fs.ReadFileFS).ReadFile(path) //nolint:forcetypeassert,errcheck
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		testFiles[filepath.Join("dist", path)] = &fstest.MapFile{
			Data:    data,
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
			Sys:     info.Sys(),
		}

		return nil
	})
	if err != nil {
		panic(err)
	}
}

func testStaticFile(t *testing.T, route, filePath, contentType string) {
	t.Helper()

	ts, service, _, _, _ := startTestServer(t) //nolint:dogsled

	path, errE := service.Reverse(route, nil, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	expected, err := testFiles.ReadFile(filePath)
	require.NoError(t, err)

	resp, err := ts.Client().Get(ts.URL + path) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, contentType, resp.Header.Get("Content-Type"))
		assert.Equal(t, string(expected), string(out))
	}
}

func TestRouteHome(t *testing.T) {
	t.Parallel()

	// Regular GET should just return the SPA index page.
	testStaticFile(t, "Home", "dist/index.html", "text/html; charset=utf-8")
}

func init() { //nolint:gochecknoinits
	zerolog.ErrorMarshalFunc = z.ErrorMarshalFunc //nolint:reassign
}

func startTestServer(t *testing.T) (*httptest.Server, *charon.Service, *smtpmock.Server, *httptest.Server, *httptest.Server) {
	t.Helper()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test_cert.pem")
	keyPath := filepath.Join(tempDir, "test_key.pem")

	errE := x.CreateTempCertificateFiles(certPath, keyPath, []string{"localhost"})
	require.NoError(t, errE)

	logger := zerolog.New(zerolog.NewTestWriter(t)).With().Timestamp().Logger()

	smtpServer := smtpmock.New(smtpmock.ConfigurationAttr{
		// See: https://github.com/mocktools/go-smtp-mock/issues/172
		MultipleMessageReceiving: true,
	})
	err := smtpServer.Start()
	require.NoError(t, err)
	t.Cleanup(func() { smtpServer.Stop() }) //nolint:errcheck

	oidcTS, oidcStore := startOIDCTestServer(t)
	samlTS := startSAMLTestServer(t)

	config := charon.Config{
		LoggingConfig: z.LoggingConfig{
			Logger: logger,
		},
		Server: waf.Server[*charon.Site]{
			TLS: waf.TLS{
				CertFile: certPath,
				KeyFile:  keyPath,
			},
			Development: true,
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
		Providers: charon.Providers{
			OIDCTesting: charon.GenericOIDCProvider{
				OIDCProvider: charon.OIDCProvider{
					ClientID: oidcTestingClientID,
					Secret:   []byte(oidcTestingSecret),
				},
				Issuer: oidcTS.URL,
			},
			SAMLTesting: charon.SAMLProvider{
				EntityID:    samlTestingEntityID,
				MetadataURL: samlTS.URL + "/saml/metadata",
			},
		},
	}

	handler, service, errE := config.Init(testFiles)
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

	// This does not start server's managers, but that is OK for this test.
	ts.StartTLS()

	// Our certificate is for localhost domain and not 127.0.0.1 IP.
	ts.URL = strings.ReplaceAll(ts.URL, "127.0.0.1", "localhost")

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	require.NoError(t, err)

	ts.Client().Jar = jar

	// We do not follow redirects automatically.
	ts.Client().CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	oidcTS.Client().CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	samlTS.Client().CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	authThirdPartyProviderOIDCTesting, errE := service.Reverse("AuthThirdPartyProvider", waf.Params{"provider": "oidcTesting"}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// We have the location testing server listens on now, so we can set the redirect URI.
	oidcStore.Clients[oidcTestingClientID].(*fosite.DefaultClient).RedirectURIs = []string{ts.URL + authThirdPartyProviderOIDCTesting} //nolint:forcetypeassert,errcheck

	return ts, service, smtpServer, oidcTS, samlTS
}
