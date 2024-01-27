package charon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/ory/fosite"
	"github.com/wneessen/go-mail"
	"gitlab.com/tozd/go/cli"
	"gitlab.com/tozd/go/errors"
	z "gitlab.com/tozd/go/zerolog"

	"gitlab.com/tozd/waf"
)

const (
	DefaultProxyTo  = "http://localhost:5173"
	DefaultTLSCache = "letsencrypt"
)

const oidcCSecretSize = 32

//go:embed routes.json
var routesConfiguration []byte

//go:embed dist
var files embed.FS

type OIDCProvider struct {
	ClientID string `env:"CLIENT_ID" help:"${provider}'s client ID. Environment variable: ${env}." yaml:"clientId"`
	Secret   string `env:"SECRET"    help:"${provider}'s secret. Environment variable: ${env}."    yaml:"secret"`
}

// TODO: Add Kong validator to OIDCProvider to validate that or both or none fields are set.
//       See: https://github.com/alecthomas/kong/issues/90

type Providers struct {
	Google   OIDCProvider `embed:"" envprefix:"GOOGLE_"   prefix:"google."   set:"provider=Google"   yaml:"google"`
	Facebook OIDCProvider `embed:"" envprefix:"FACEBOOK_" prefix:"facebook." set:"provider=Facebook" yaml:"facebook"`
}

//nolint:lll
type Mail struct {
	Host     string `                                                                    help:"Host to send e-mails to. If not set, e-mails are logged instead."                                                      yaml:"host"`
	Port     int    `default:"25"                                                        help:"Port to send e-mails to. Default: ${default}."                                        placeholder:"INT"                yaml:"port"`
	Username string `                                                                    help:"Username to use to send e-mails."                                                                                      yaml:"username"`
	Password string `                                                     env:"PASSWORD" help:"Password to use to send e-mails. Environment variable: ${env}."                                                        yaml:"password"`
	Auth     string `default:"${defaultMailAuth}" enum:"${mailAuthTypes}"                help:"Authentication type to use. Possible: ${mailAuthTypes}. Default: ${defaultMailAuth}." placeholder:"STRING"             yaml:"auth"`
	From     string `                                                                    help:"From header for e-mails."                                                             placeholder:"EMAIL"  required:"" yaml:"from"`
}

//nolint:lll
type OIDC struct {
	Development bool   `             help:"Run OIDC in development mode: send debug messages to clients, generate secret and key if not provided. LEAKS SENSITIVE INFORMATION!"                      short:"O" yaml:"development"`
	Secret      string `env:"SECRET" help:"Base64 (URL encoding, no padding) encoded 32 bytes used for tokens' HMAC. Environment variable: ${env}."                             placeholder:"STRING"           yaml:"secret"`
	Key         string `env:"KEY"    help:"ECDSA private key in JWK format for signing tokens. Only the key is used, other fields are ignored. Environment variable: ${env}."   placeholder:"JWK"              yaml:"key"`
}

//nolint:lll
type Config struct {
	z.LoggingConfig `yaml:",inline"`

	Version kong.VersionFlag  `         help:"Show program's version and exit."                                              short:"V" yaml:"-"`
	Config  cli.ConfigFlag    `         help:"Load configuration from a JSON or YAML file." name:"config" placeholder:"PATH" short:"c" yaml:"-"`
	Server  waf.Server[*Site] `embed:""                                                                                                yaml:",inline"`

	Domains    []string `help:"Domain name(s) to use. If not provided, they are determined from domain names found in TLS certificates." name:"domain" placeholder:"STRING" short:"D" yaml:"domains"`
	MainDomain string   `help:"When using multiple domains, which one is the main one."                                                                                               yaml:"mainDomain"`

	Providers Providers `embed:"" group:"Providers:" yaml:"providers"`

	Mail Mail `embed:"" envprefix:"MAIL_" group:"Mail" prefix:"mail." yaml:"mail"`

	OIDC OIDC `embed:"" envprefix:"OIDC_" group:"OIDC" prefix:"oidc." yaml:"oidc"`
}

type Service struct {
	waf.Service[*Site]

	oidc          func() fosite.OAuth2Provider
	oidcPublicKey jose.JSONWebKey

	oidcProviders   func() map[Provider]oidcProvider
	passkeyProvider func() *webauthn.WebAuthn
	codeProvider    func() *codeProvider

	domain string

	mailClient *mail.Client
	mailFrom   string
}

func (config *Config) Run() errors.E { //nolint:maintidx
	var secret []byte
	if config.OIDC.Secret != "" {
		var err error
		secret, err = base64.RawURLEncoding.DecodeString(config.OIDC.Secret)
		if err != nil {
			return errors.WithMessage(err, "invalid OIDC secret")
		}
		if len(secret) != oidcCSecretSize {
			return errors.Errorf("OIDC secret does not have 32 bytes, but %d", len(secret))
		}
	} else if config.OIDC.Development {
		secret = make([]byte, oidcCSecretSize)
		_, err := rand.Read(secret)
		if err != nil {
			return errors.WithStack(err)
		}
	} else {
		return errors.New("OIDC secret not provided")
	}

	var privateKey *ecdsa.PrivateKey
	if config.OIDC.Key != "" {
		var jwk jose.JSONWebKey
		err := json.Unmarshal([]byte(config.OIDC.Key), &jwk)
		if err != nil {
			return errors.WithMessage(err, "invalid OIDC private key")
		}
		var ok bool
		privateKey, ok = jwk.Key.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("OIDC private key is not an ECDSA private key")
		}
	} else if config.OIDC.Development {
		var err error
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return errors.WithStack(err)
		}
	} else {
		return errors.New("OIDC private key not provided")
	}

	// We on purpose ignore all other fields and reconstruct JWK from scratch.
	// This assures all our keys have same JWK representation.
	oidcPublicKey, errE := makeJSONWebKey(&privateKey.PublicKey)
	if errE != nil {
		return errE
	}

	// Routes come from a single source of truth, e.g., a file.
	var routesConfig struct {
		Routes []waf.Route `json:"routes"`
	}
	err := json.Unmarshal(routesConfiguration, &routesConfig)
	if err != nil {
		return errors.WithStack(err)
	}

	config.Server.Logger = config.Logger

	sites := map[string]*Site{}
	// If domains are provided, we create sites based on those domains.
	for _, domain := range config.Domains {
		sites[domain] = &Site{
			Site: waf.Site{
				Domain:   domain,
				CertFile: "",
				KeyFile:  "",
			},
			// We will set the rest later for all sites.
			Build:     nil,
			Providers: nil,
		}
	}
	// If domains are not provided, sites are automatically constructed based on the certificate.
	sites, errE = config.Server.Init(nil)
	if errE != nil {
		return errE
	}

	// We set build information on sites.
	if cli.Version != "" || cli.BuildTimestamp != "" || cli.Revision != "" {
		for _, site := range sites {
			site.Build = &Build{
				Version:        cli.Version,
				BuildTimestamp: cli.BuildTimestamp,
				Revision:       cli.Revision,
			}
		}
	}

	providers := []SiteProvider{}
	if config.Providers.Google.ClientID != "" && config.Providers.Google.Secret != "" {
		providers = append(providers, SiteProvider{
			Key:       "google",
			Name:      "Google",
			Type:      "oidc",
			issuer:    "https://accounts.google.com",
			clientID:  config.Providers.Google.ClientID,
			secret:    config.Providers.Google.Secret,
			forcePKCE: false,
			authURL:   "",
			tokenURL:  "",
		})
	}
	if config.Providers.Facebook.ClientID != "" && config.Providers.Facebook.Secret != "" {
		providers = append(providers, SiteProvider{
			Key:       "facebook",
			Name:      "Facebook",
			Type:      "oidc",
			issuer:    "https://www.facebook.com",
			clientID:  config.Providers.Facebook.ClientID,
			secret:    config.Providers.Facebook.Secret,
			forcePKCE: true,
			authURL:   "",
			tokenURL:  "https://graph.facebook.com/oauth/access_token",
		})
	}
	for _, site := range sites {
		site.Providers = providers
	}

	// We remove "dist" prefix.
	f, err := fs.Sub(files, "dist")
	if err != nil {
		return errors.WithStack(err)
	}

	var domain string
	if len(sites) > 1 {
		if config.MainDomain == "" {
			return errors.New("main domain is not configured, but multiple domains are used")
		}
		if _, ok := sites[config.MainDomain]; !ok {
			errE = errors.New("main domain is not among domains")
			errors.Details(errE)["main"] = config.MainDomain
			domains := []string{}
			for site := range sites {
				domains = append(domains, site)
			}
			sort.Strings(domains)
			errors.Details(errE)["domains"] = domains
			return errE
		}

		domain = config.MainDomain
	} else {
		// There is only one really here. config.Server.Init errors if there are not sites.
		for d := range sites {
			domain = d
			break
		}
	}

	service := &Service{ //nolint:forcetypeassert
		Service: waf.Service[*Site]{ //nolint:exhaustruct
			Logger:          config.Logger,
			CanonicalLogger: config.Logger,
			WithContext:     config.WithContext,
			StaticFiles:     f.(fs.ReadFileFS),
			Routes:          routesConfig.Routes,
			Sites:           sites,
			SiteContextPath: "/context.json",
			Development:     config.Server.InDevelopment(),
			SkipServingFile: func(path string) bool {
				// We want the file to be served by Home route at / and not be
				// available at index.html (as well).
				return path == "/index.html"
			},
		},
		oidc:            nil,
		oidcPublicKey:   oidcPublicKey,
		oidcProviders:   nil,
		passkeyProvider: nil,
		codeProvider:    nil,
		domain:          domain,
		mailClient:      nil,
		mailFrom:        config.Mail.From,
	}

	if config.Mail.Host != "" {
		c, err := mail.NewClient(
			config.Mail.Host,
			mail.WithPort(config.Mail.Port),
			mail.WithSMTPAuth(MailAuthTypes[config.Mail.Auth]),
			mail.WithUsername(config.Mail.Username),
			mail.WithPassword(config.Mail.Password),
			mail.WithLogger(loggerAdapter{config.Logger}),
		)
		if err != nil {
			return errors.WithStack(err)
		}
		service.mailClient = c
	}

	if len(sites) > 1 {
		service.Middleware = append(service.Middleware, service.RedirectToMainSite(domain))
	}

	service.oidc = sync.OnceValue(initOIDC(config, service, domain, secret, privateKey))

	service.oidcProviders = sync.OnceValue(initOIDCProviders(config, service, domain, providers))
	service.passkeyProvider = sync.OnceValue(initPasskeyProvider(config, domain))
	service.codeProvider = sync.OnceValue(initCodeProvider(config, domain))

	// Construct the main handler for the service using the router.
	handler, errE := service.RouteWith(service, new(waf.Router))
	if errE != nil {
		return errE
	}

	// We start initialization of OIDC and providers.
	// Initialization will block until the server runs.
	go service.oidc()
	go service.oidcProviders()
	go service.passkeyProvider()
	go service.codeProvider()

	// We stop the server gracefully on ctrl-c and TERM signal.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// It returns only on error or if the server is gracefully shut down using ctrl-c.
	return config.Server.Run(ctx, handler)
}
