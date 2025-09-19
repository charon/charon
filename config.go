package charon

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/ory/fosite"
	"github.com/ory/fosite/token/hmac"
	"github.com/wneessen/go-mail"
	"gitlab.com/tozd/go/cli"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	z "gitlab.com/tozd/go/zerolog"
	"gitlab.com/tozd/identifier"

	"gitlab.com/tozd/waf"
)

const (
	DefaultProxyTo  = "http://localhost:5173"
	DefaultTLSCache = "letsencrypt"
)

const (
	SecretPrefixClientSecret = "chc-"
	SecretPrefixCharonConfig = "chs-"
	SecretPrefixSession      = "chse-"
)

const expectedSecretSize = 32

//go:embed routes.json
var routesConfiguration []byte

//go:embed dist
var files embed.FS

type ThirdPartyProviderType string

const (
	ThirdPartyProviderOIDC ThirdPartyProviderType = "oidc"
	ThirdPartyProviderSAML ThirdPartyProviderType = "saml"
)

type OIDCProvider struct {
	ClientID string               `env:"CLIENT_ID"   help:"${provider}'s client ID."                                  yaml:"clientId"`
	Secret   kong.FileContentFlag `env:"SECRET_PATH" help:"File with ${provider}'s client secret." placeholder:"PATH" yaml:"secret"`
}

func (p *OIDCProvider) Validate() error {
	if p.ClientID != "" || p.Secret != nil {
		if p.ClientID == "" {
			return errors.New("missing client ID for provided secret")
		}
		if p.Secret == nil {
			return errors.New("missing client ID's matching secret")
		}
	}
	return nil
}

type GenericOIDCProvider struct {
	OIDCProvider

	Issuer    string
	ForcePKCE bool
	AuthURL   string
	TokenURL  string
}

type SAMLProvider struct {
	MetadataURL string `env:"METADATA_URL" help:"${provider}'s metadata URL. Environment variable: ${env}."         yaml:"metadataUrl"`
	EntityID    string `env:"ENTITY_ID"    help:"${provider}'s entity ID (optional). Environment variable: ${env}." yaml:"entityId"`
}

func (p *SAMLProvider) Validate() error {
	if p.MetadataURL == "" {
		return errors.New("metadata URL is required for SAML provider")
	}
	return nil
}

type GenericSAMLProvider struct {
	SAMLProvider
	Key  Provider `required:"" yaml:"key"`
	Name string   `            yaml:"name"`
}

type Providers struct {
	Google   OIDCProvider `embed:"" envprefix:"GOOGLE_"   prefix:"google."   set:"provider=Google"   yaml:"google"`
	Facebook OIDCProvider `embed:"" envprefix:"FACEBOOK_" prefix:"facebook." set:"provider=Facebook" yaml:"facebook"`

	SIPASS        SAMLProvider          `embed:"" envprefix:"SIPASS_" prefix:"sipass." set:"provider=SIPASS" yaml:"sipass"`
	SAMLProviders []GenericSAMLProvider `                                                                    yaml:"samlProviders"`

	// Exposed primarily for use in tests.
	OIDCTesting GenericOIDCProvider `json:"-" kong:"-" yaml:"-"`
}

// We have to call Validate on kong-embedded structs ourselves.
// See: https://github.com/alecthomas/kong/issues/90
func (p *Providers) Validate() error {
	if err := p.Google.Validate(); err != nil {
		return err
	}
	if err := p.Facebook.Validate(); err != nil {
		return err
	}
	if p.SIPASS.MetadataURL == "" {
		p.SIPASS.MetadataURL = sipassDefaultMetadataURL
	}
	for i, samlProvider := range p.SAMLProviders {
		if err := samlProvider.Validate(); err != nil {
			return fmt.Errorf("SAMLProvider[%d]: %w", i, err)
		}
	}
	if err := p.SIPASS.Validate(); err != nil {
		return err
	}
	if err := p.OIDCTesting.Validate(); err != nil {
		return err
	}
	return nil
}

//nolint:lll
type Mail struct {
	Host     string               `                                                                         help:"Host to send e-mails to. If not set, e-mails are logged instead."                      yaml:"host"`
	Port     int                  `default:"25"                                                             help:"Port to send e-mails to."                                         placeholder:"INT"    yaml:"port"`
	Username string               `                                                                         help:"Username to use to send e-mails."                                                      yaml:"username"`
	Password kong.FileContentFlag `                                                     env:"PASSWORD_PATH" help:"File with password to use to send e-mails."                       placeholder:"PATH"   yaml:"password"`
	Auth     string               `default:"${defaultMailAuth}" enum:"${mailAuthTypes}"                     help:"Authentication type to use."                                      placeholder:"STRING" yaml:"auth"`
	From     string               `default:"${defaultMailFrom}"                                             help:"From header for e-mails."                                         placeholder:"EMAIL"  yaml:"from"`

	// Exposed primarily for use in tests.
	NotRequiredTLS bool `json:"-" kong:"-" yaml:"-"`
}

type Keys struct {
	RSA  kong.FileContentFlag `env:"RSA_PATH"  help:"File with RSA private key."               placeholder:"PATH" yaml:"rsa"`
	P256 kong.FileContentFlag `env:"P256_PATH" help:"File with P-256 private key." name:"p256" placeholder:"PATH" yaml:"p256"`
	P384 kong.FileContentFlag `env:"P384_PATH" help:"File with P-384 private key." name:"p384" placeholder:"PATH" yaml:"p384"`
	P521 kong.FileContentFlag `env:"P521_PATH" help:"File with P-521 private key." name:"p521" placeholder:"PATH" yaml:"p521"`

	rsa  *jose.JSONWebKey
	p256 *jose.JSONWebKey
	p384 *jose.JSONWebKey
	p521 *jose.JSONWebKey
}

func (k *Keys) Init(development bool) errors.E {
	if k.RSA != nil {
		key, errE := MakeRSAKey(k.RSA)
		if errE != nil {
			return errors.WithMessage(errE, "invalid RSA private key")
		}
		k.rsa = key
	} else if development {
		key, errE := GenerateRSAKey()
		if errE != nil {
			return errE
		}
		k.rsa = key
	} else {
		return errors.New("OIDC RSA private key not provided")
	}

	if k.P256 != nil {
		key, errE := makeEllipticKey(k.P256, elliptic.P256(), "ES256")
		if errE != nil {
			return errors.WithMessage(errE, "invalid P256 private key")
		}
		k.p256 = key
	} else if development {
		key, errE := GenerateEllipticKey(elliptic.P256(), "ES256")
		if errE != nil {
			return errE
		}
		k.p256 = key
	}

	if k.P384 != nil {
		key, errE := makeEllipticKey(k.P384, elliptic.P384(), "ES384")
		if errE != nil {
			return errors.WithMessage(errE, "invalid P384 private key")
		}
		k.p384 = key
	} else if development {
		key, errE := GenerateEllipticKey(elliptic.P384(), "ES384")
		if errE != nil {
			return errE
		}
		k.p384 = key
	}

	if k.P521 != nil {
		key, errE := makeEllipticKey(k.P521, elliptic.P521(), "ES512")
		if errE != nil {
			return errors.WithMessage(errE, "invalid P521 private key")
		}
		k.p521 = key
	} else if development {
		key, errE := GenerateEllipticKey(elliptic.P521(), "ES512")
		if errE != nil {
			return errE
		}
		k.p521 = key
	}

	return nil
}

type OIDC struct {
	Keys Keys `embed:"" envprefix:"KEYS_" prefix:"keys." yaml:"keys"`
}

//nolint:lll
type Config struct {
	z.LoggingConfig `yaml:",inline"`

	Version kong.VersionFlag  `         help:"Show program's version and exit."                                              short:"V" yaml:"-"`
	Config  cli.ConfigFlag    `         help:"Load configuration from a JSON or YAML file." name:"config" placeholder:"PATH" short:"c" yaml:"-"`
	Server  waf.Server[*Site] `embed:""                                                                                                yaml:",inline"`

	Domains      []string             `                  help:"Domain name(s) to use. If not provided, they are determined from domain names found in TLS certificates."                                 name:"domain" placeholder:"STRING" yaml:"domains"`
	MainDomain   string               `                  help:"When using multiple domains, which one is the main one."                                                                                                                     yaml:"mainDomain"`
	ExternalPort int                  `                  help:"Port on which Charon is accessible when it is different from the port on which the program listens."                                                    placeholder:"INT"    yaml:"externalPort"`
	Secret       kong.FileContentFlag `env:"SECRET_PATH" help:"File with base64 (URL encoding, no padding) encoded 32 bytes with \"${secretPrefixCharonConfig}\" prefix used for session and OIDC HMAC."               placeholder:"PATH"   yaml:"secret"`

	Providers Providers `embed:"" group:"Providers:" yaml:"providers"`

	Mail Mail `embed:"" envprefix:"MAIL_" group:"Mail:" prefix:"mail." yaml:"mail"`

	OIDC OIDC `embed:"" envprefix:"OIDC_" group:"OIDC:" prefix:"oidc." yaml:"oidc"`
}

// We have to call Validate on kong-embedded structs ourselves.
// See: https://github.com/alecthomas/kong/issues/90
func (config *Config) Validate() error {
	if err := config.Server.TLS.Validate(); err != nil {
		return err //nolint:wrapcheck
	}
	if err := config.Providers.Validate(); err != nil {
		return err
	}
	return nil
}

type Service struct {
	waf.Service[*Site]

	hmac *hmac.HMACStrategy

	oidc     func() *fosite.Fosite
	oidcKeys *Keys

	oidcProviders      func() map[Provider]oidcProvider
	samlProviders      func() map[Provider]samlProvider
	passkeyProvider    func() *webauthn.WebAuthn
	codeProvider       func() *codeProvider
	charonOrganization func() charonOrganization

	domain string

	mailClient *mail.Client
	mailFrom   string

	// TODO: Move to a database.
	accounts               map[identifier.Identifier][]byte
	accountsMu             sync.RWMutex
	applicationTemplates   map[identifier.Identifier][]byte
	applicationTemplatesMu sync.RWMutex
	flows                  map[identifier.Identifier][]byte
	flowsMu                sync.RWMutex
	identities             map[identifier.Identifier][]byte
	identitiesMu           sync.RWMutex
	organizations          map[identifier.Identifier][]byte
	organizationsMu        sync.RWMutex
	sessions               map[identifier.Identifier][]byte
	sessionsMu             sync.RWMutex
	activities             map[identifier.Identifier][]byte
	activitiesMu           sync.RWMutex
	// Map from account ID to map from identity refs (to which account ID has access) to
	// paths which are the support for the access.
	identitiesAccess map[identifier.Identifier]map[IdentityRef][][]IdentityRef
	// Map from identity ref to the account ID that created it.
	// TODO: Should creator be just an internal field of Identity struct?
	identityCreators map[IdentityRef]identifier.Identifier
	// We use only one mutex for both identitiesAccess and identityCreators as they are always used together.
	identitiesAccessMu sync.RWMutex
	// Map from organization ID to map of organization-scoped identity IDs which have been blocked in the organization, to corresponding notes.
	identitiesBlocked map[identifier.Identifier]map[identifier.Identifier]BlockedIdentity
	// Map from organization ID to map of account IDs which have been blocked in the organization,
	// to a map between identity ID which was blocked with the account and corresponding notes.
	accountsBlocked map[identifier.Identifier]map[identifier.Identifier]map[identifier.Identifier]BlockedIdentity
	// We use only one mutex for both identitiesBlocked and accountsBlocked as they are always used together.
	identitiesBlockedMu sync.RWMutex
}

// Init is used primarily in tests. Use Run otherwise.
func (config *Config) Init(files fs.ReadFileFS) (http.Handler, *Service, errors.E) { //nolint:maintidx
	var secret []byte
	if config.Secret != nil {
		// We use a prefix to aid secret scanners.
		if !bytes.HasPrefix(config.Secret, []byte(SecretPrefixCharonConfig)) {
			return nil, nil, errors.Errorf(`secret does not have "%s" prefix`, SecretPrefixCharonConfig)
		}
		encodedSecret := bytes.TrimPrefix(config.Secret, []byte(SecretPrefixCharonConfig))
		// We trim space so that the file can contain whitespace (e.g., a newline) at the end.
		encodedSecret = bytes.TrimSpace(encodedSecret)
		secret = make([]byte, base64.RawURLEncoding.DecodedLen(len(encodedSecret)))
		n, err := base64.RawURLEncoding.Decode(secret, encodedSecret)
		secret = secret[:n]
		if err != nil {
			return nil, nil, errors.WithMessage(err, "invalid secret")
		}
		if len(secret) != expectedSecretSize {
			errE := errors.New("secret does not have valid length")
			errors.Details(errE)["got"] = len(secret)
			errors.Details(errE)["expected"] = 32
			return nil, nil, errE
		}
	} else if config.Server.Development {
		secret = make([]byte, expectedSecretSize)
		_, err := rand.Read(secret)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}
	} else {
		return nil, nil, errors.New("secret not provided")
	}

	errE := config.OIDC.Keys.Init(config.Server.Development)
	if errE != nil {
		return nil, nil, errE
	}

	// Routes come from a single source of truth, e.g., a file.
	var routesConfig struct {
		Routes []waf.Route `json:"routes"`
	}
	errE = x.UnmarshalWithoutUnknownFields(routesConfiguration, &routesConfig)
	if errE != nil {
		return nil, nil, errE
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
	sites, errE = config.Server.Init(sites)
	if errE != nil {
		return nil, nil, errE
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
	if config.Providers.Google.ClientID != "" && config.Providers.Google.Secret != nil {
		providers = append(providers, SiteProvider{
			Key:          "google",
			Name:         "Google",
			Type:         ThirdPartyProviderOIDC,
			oidcIssuer:   "https://accounts.google.com",
			oidcClientID: config.Providers.Google.ClientID,
			// We trim space so that the file can contain whitespace (e.g., a newline) at the end.
			oidcSecret:      strings.TrimSpace(string(config.Providers.Google.Secret)),
			oidcForcePKCE:   false,
			oidcAuthURL:     "",
			oidcTokenURL:    "",
			oidcScopes:      []string{oidc.ScopeOpenID, "email", "profile"},
			samlEntityID:    "",
			samlMetadataURL: "",
			samlKeyStore:    nil,
			samlAttributeMapping: SAMLAttributeMapping{
				CredentialIDAttribute: "NameID",
				Mappings:              map[string]string{},
			},
		})
	}
	if config.Providers.Facebook.ClientID != "" && config.Providers.Facebook.Secret != nil {
		providers = append(providers, SiteProvider{
			Key:          "facebook",
			Name:         "Facebook",
			Type:         ThirdPartyProviderOIDC,
			oidcIssuer:   "https://www.facebook.com",
			oidcClientID: config.Providers.Facebook.ClientID,
			// We trim space so that the file can contain whitespace (e.g., a newline) at the end.
			oidcSecret:      strings.TrimSpace(string(config.Providers.Facebook.Secret)),
			oidcForcePKCE:   true,
			oidcAuthURL:     "",
			oidcTokenURL:    "https://graph.facebook.com/oauth/access_token",
			oidcScopes:      []string{oidc.ScopeOpenID, "email", "public_profile"},
			samlEntityID:    "",
			samlMetadataURL: "",
			samlKeyStore:    nil,
			samlAttributeMapping: SAMLAttributeMapping{
				CredentialIDAttribute: "NameID",
				Mappings:              map[string]string{},
			},
		})
	}
	if config.Providers.OIDCTesting.ClientID != "" && config.Providers.OIDCTesting.Secret != nil && config.Providers.OIDCTesting.Issuer != "" {
		providers = append(providers, SiteProvider{
			Key:          "oidcTesting",
			Name:         "OIDC Testing",
			Type:         ThirdPartyProviderOIDC,
			oidcIssuer:   config.Providers.OIDCTesting.Issuer,
			oidcClientID: config.Providers.OIDCTesting.ClientID,
			// We trim space so that the file can contain whitespace (e.g., a newline) at the end.
			oidcSecret:      strings.TrimSpace(string(config.Providers.OIDCTesting.Secret)),
			oidcForcePKCE:   config.Providers.OIDCTesting.ForcePKCE,
			oidcAuthURL:     config.Providers.OIDCTesting.AuthURL,
			oidcTokenURL:    config.Providers.OIDCTesting.TokenURL,
			oidcScopes:      []string{oidc.ScopeOpenID},
			samlEntityID:    "",
			samlMetadataURL: "",
			samlKeyStore:    nil,
			samlAttributeMapping: SAMLAttributeMapping{
				CredentialIDAttribute: "NameID",
				Mappings:              map[string]string{},
			},
		})
	}

	entityID := config.Providers.SIPASS.EntityID
	if entityID == "" {
		entityID = samlSIPASSEntityIDPrefix

		providers = append(providers, SiteProvider{
			Key:                  "sipass",
			Name:                 "SIPASS",
			Type:                 ThirdPartyProviderSAML,
			oidcIssuer:           "",
			oidcClientID:         "",
			oidcSecret:           "",
			oidcForcePKCE:        false,
			oidcAuthURL:          "",
			oidcTokenURL:         "",
			oidcScopes:           nil,
			samlEntityID:         entityID,
			samlMetadataURL:      sipassDefaultMetadataURL,
			samlKeyStore:         nil,
			samlAttributeMapping: getSIPASSAttributeMapping(),
		})
	}

	if config.Server.Development {
		providers = append(providers, SiteProvider{
			Key:                  "MockSAML",
			Name:                 "MockSAML",
			Type:                 ThirdPartyProviderSAML,
			oidcIssuer:           "",
			oidcClientID:         "",
			oidcSecret:           "",
			oidcForcePKCE:        false,
			oidcAuthURL:          "",
			oidcTokenURL:         "",
			oidcScopes:           nil,
			samlEntityID:         mockSAMLEntityID,
			samlMetadataURL:      mockSAMLMetadataURL,
			samlKeyStore:         nil,
			samlAttributeMapping: getDefaultAttributeMapping(),
		})
	}

	for _, samlConfig := range config.Providers.SAMLProviders {
		entityID := samlConfig.EntityID
		if entityID == "" {
			entityID = samlEntityIDPrefix + string(samlConfig.Key)
		}

		providers = append(providers, SiteProvider{
			Key:                  samlConfig.Key,
			Name:                 samlConfig.Name,
			Type:                 ThirdPartyProviderSAML,
			oidcIssuer:           "",
			oidcClientID:         "",
			oidcSecret:           "",
			oidcForcePKCE:        false,
			oidcAuthURL:          "",
			oidcTokenURL:         "",
			oidcScopes:           nil,
			samlEntityID:         entityID,
			samlMetadataURL:      samlConfig.MetadataURL,
			samlKeyStore:         nil,
			samlAttributeMapping: getDefaultAttributeMapping(),
		})
	}

	for _, site := range sites {
		site.Providers = providers
	}

	// We remove "dist" prefix.
	f, err := fs.Sub(files, "dist")
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	var domain string
	if len(sites) > 1 {
		if config.MainDomain == "" {
			return nil, nil, errors.New("main domain is not configured, but multiple domains are used")
		}
		if _, ok := sites[config.MainDomain]; !ok {
			errE = errors.New("main domain is not among domains")
			errors.Details(errE)["main"] = config.MainDomain
			domains := []string{}
			for site := range sites {
				domains = append(domains, site)
			}
			slices.Sort(domains)
			errors.Details(errE)["domains"] = domains
			return nil, nil, errE
		}

		domain = config.MainDomain
	} else {
		// There is only one really here. config.Server.Init errors if there are not sites.
		for d := range sites {
			domain = d
			break
		}
	}

	hmacStrategy := &hmac.HMACStrategy{
		Mutex:  sync.Mutex{},
		Config: &hmacStrategyConfigurator{Secret: secret},
	}

	service := &Service{ //nolint:forcetypeassert
		Service: waf.Service[*Site]{
			Logger:          config.Logger,
			CanonicalLogger: config.Logger,
			WithContext:     config.WithContext,
			StaticFiles:     f.(fs.ReadFileFS), //nolint:errcheck
			Routes:          routesConfig.Routes,
			Sites:           sites,
			// We serve our own context.json file.
			SiteContextPath: "",
			ProxyStaticTo:   config.Server.ProxyToInDevelopment(),
			SkipServingFile: func(path string) bool {
				switch path {
				case "/index.html":
					// We want the file to be served by Home route at / and not be
					// available at index.html (as well).
					return true
				case "/LICENSE.txt":
					// We want the file to be served by License route at /LICENSE and not be
					// available at LICENSE.txt (as well).
					return true
				case "/NOTICE.txt":
					// We want the file to be served by Notice route at /NOTICE and not be
					// available at NOTICE.txt (as well).
					return true
				default:
					return false
				}
			},
		},
		hmac:                   hmacStrategy,
		oidc:                   nil,
		oidcKeys:               &config.OIDC.Keys,
		oidcProviders:          nil,
		samlProviders:          nil,
		passkeyProvider:        nil,
		codeProvider:           nil,
		charonOrganization:     nil,
		domain:                 domain,
		mailClient:             nil,
		mailFrom:               config.Mail.From,
		accounts:               map[identifier.Identifier][]byte{},
		accountsMu:             sync.RWMutex{},
		applicationTemplates:   map[identifier.Identifier][]byte{},
		applicationTemplatesMu: sync.RWMutex{},
		flows:                  map[identifier.Identifier][]byte{},
		flowsMu:                sync.RWMutex{},
		identities:             map[identifier.Identifier][]byte{},
		identitiesMu:           sync.RWMutex{},
		organizations:          map[identifier.Identifier][]byte{},
		organizationsMu:        sync.RWMutex{},
		sessions:               map[identifier.Identifier][]byte{},
		sessionsMu:             sync.RWMutex{},
		activities:             map[identifier.Identifier][]byte{},
		activitiesMu:           sync.RWMutex{},
		identitiesAccess:       map[identifier.Identifier]map[IdentityRef][][]IdentityRef{},
		identityCreators:       map[IdentityRef]identifier.Identifier{},
		identitiesAccessMu:     sync.RWMutex{},
		identitiesBlocked:      map[identifier.Identifier]map[identifier.Identifier]BlockedIdentity{},
		accountsBlocked:        map[identifier.Identifier]map[identifier.Identifier]map[identifier.Identifier]BlockedIdentity{},
		identitiesBlockedMu:    sync.RWMutex{},
	}

	if config.Mail.Host != "" {
		c, err := mail.NewClient(
			config.Mail.Host,
			mail.WithHELO(domain),
			mail.WithPort(config.Mail.Port),
			mail.WithSMTPAuth(MailAuthTypes[config.Mail.Auth]),
			mail.WithUsername(config.Mail.Username),
			mail.WithPassword(string(config.Mail.Password)),
			mail.WithLogger(loggerAdapter{config.Logger}),
		)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}
		if config.Mail.NotRequiredTLS {
			// go-smtp-mock does not support STARTTLS.
			// See: https://github.com/mocktools/go-smtp-mock/issues/76
			c.SetTLSPolicy(mail.TLSOpportunistic)
		}
		service.mailClient = c
	}

	if len(sites) > 1 {
		service.Middleware = append(service.Middleware, service.RedirectToMainSite(domain))
	}

	router := new(waf.Router)

	// Construct the main handler for the service using the router.
	handler, errE := service.RouteWith(service, router)
	if errE != nil {
		return nil, nil, errE
	}

	// We prepare initialization of OIDC and providers and in the common case
	// (when server's bind port is not 0) immediately do the initialization.
	service.oidc, errE = initOIDC(config, service, domain, hmacStrategy)
	if errE != nil {
		return nil, nil, errE
	}
	service.oidcProviders, errE = initOIDCProviders(config, service, domain, providers)
	if errE != nil {
		return nil, nil, errE
	}
	service.samlProviders, errE = initSAMLProviders(config, service, domain, providers)
	if errE != nil {
		return nil, nil, errE
	}
	service.passkeyProvider, errE = initPasskeyProvider(config, domain)
	if errE != nil {
		return nil, nil, errE
	}
	service.codeProvider, errE = initCodeProvider(config, domain)
	if errE != nil {
		return nil, nil, errE
	}
	service.charonOrganization, errE = initCharonOrganization(config, service, domain)
	if errE != nil {
		return nil, nil, errE
	}

	return handler, service, nil
}

func (config *Config) Run() errors.E {
	handler, service, errE := config.Init(files)
	if errE != nil {
		return errE
	}

	// In the case when server's bind port is 0, we access values once to start
	// delayed initialization (initialization will block until the server runs).
	go service.oidc()
	go service.oidcProviders()
	go service.samlProviders()
	go service.passkeyProvider()
	go service.codeProvider()
	go service.charonOrganization()

	// We stop the server gracefully on ctrl-c and TERM signal.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// It returns only on error or if the server is gracefully shut down using ctrl-c.
	return config.Server.Run(ctx, handler)
}
