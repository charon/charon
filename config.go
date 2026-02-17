package charon

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
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
	mapset "github.com/deckarep/golang-set/v2"
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
	"golang.org/x/oauth2"

	"gitlab.com/tozd/waf"
)

// Default configuration values.
const (
	// DefaultListen is the default TCP listen address.
	DefaultListen = ":8080"
	// DefaultProxyTo is the default URL to proxy to during development.
	DefaultProxyTo = "http://localhost:5173"
	// DefaultTitle is the default application title.
	DefaultTitle = "Charon"
)

// Prefixes used by Charon for secrets.
const (
	SecretPrefixClientSecret = "chc-"
	SecretPrefixCharonConfig = "chs-"
	SecretPrefixSession      = "chse-"
)

var secretPrefixCharonConfig = x.String2ByteSlice(SecretPrefixCharonConfig) //nolint:gochecknoglobals

const expectedSecretSize = 32

// ThirdPartyProviderType represents the type of the third-party provider.
type ThirdPartyProviderType string

// ThirdPartyProviderType values.
const (
	ThirdPartyProviderOIDC ThirdPartyProviderType = "oidc"
	ThirdPartyProviderSAML ThirdPartyProviderType = "saml"
)

// OIDCProvider represents the configuration of the OIDC provider.
type OIDCProvider struct {
	ClientID string               `env:"CLIENT_ID"   help:"${provider}'s client ID."                                  yaml:"clientId"`
	Secret   kong.FileContentFlag `env:"SECRET_PATH" help:"File with ${provider}'s client secret." placeholder:"PATH" yaml:"secret"`
}

// Validate validates the OIDCProvider struct.
func (p *OIDCProvider) Validate() error {
	if p.ClientID != "" || p.Secret != nil {
		if p.ClientID == "" {
			return errors.New("missing client ID for provided secret")
		}
		if p.Secret == nil {
			return errors.New("missing client secret for provided client ID")
		}
	}
	return nil
}

// GenericOIDCProvider represents the configuration of the generic OIDC provider.
type GenericOIDCProvider struct {
	OIDCProvider

	Issuer    string
	ForcePKCE bool
	AuthURL   string
	TokenURL  string
}

// SAMLProvider represents the configuration of the SAML provider.
//
//nolint:lll
type SAMLProvider struct {
	MetadataURL string               `default:"${defaultMetadataURL}" env:"METADATA_URL" help:"${provider}'s metadata URL."                                                                                              placeholder:"URL"  yaml:"metadataUrl"`
	EntityID    string               `                                env:"ENTITY_ID"    help:"${provider}'s entity ID."                                                                                                                    yaml:"entityId"`
	Key         kong.FileContentFlag `                                env:"KEY_PATH"     help:"File with RSA private key for this provider. In JWK format. Only the key from the JWK is used, other fields are ignored." placeholder:"PATH" yaml:"key"`
}

// Validate validates the SAMLProvider struct.
func (s *SAMLProvider) Validate() error {
	// TODO: When Kong will call Validate, we can get *kong.Context argument to check that this is SIPASS provider and not use DefaultSIPASSMetadataURL.
	//       Or a provider with MetadataURL set and not the default value (and not an empty string).
	//       See: https://github.com/alecthomas/kong/issues/554
	if (s.MetadataURL != "" && s.MetadataURL != DefaultSIPASSMetadataURL) || s.EntityID != "" {
		if s.MetadataURL == "" {
			return errors.New("missing metadata URL for provided entity ID")
		}
		if s.EntityID == "" {
			return errors.New("missing entity ID for provided metadata URL")
		}
	}
	return nil
}

// Providers represents the configuration of third-party providers.
//
//nolint:lll
type Providers struct {
	Google   OIDCProvider `embed:"" envprefix:"GOOGLE_"   prefix:"google."   set:"provider=Google"   yaml:"google"`
	Facebook OIDCProvider `embed:"" envprefix:"FACEBOOK_" prefix:"facebook." set:"provider=Facebook" yaml:"facebook"`

	SIPASS SAMLProvider `embed:"" envprefix:"SIPASS_" prefix:"sipass." set:"provider=SIPASS" set:"defaultMetadataURL=${defaultSIPASSMetadataURL}" yaml:"sipass"` //nolint:staticcheck

	// Exposed primarily for use in tests.
	OIDCTesting GenericOIDCProvider `json:"-" kong:"-" yaml:"-"`
	SAMLTesting SAMLProvider        `json:"-" kong:"-" yaml:"-"`
}

// Validate validates the Providers struct.
//
// We have to call Validate on kong-embedded structs ourselves.
// See: https://github.com/alecthomas/kong/issues/554
func (p *Providers) Validate() error {
	err := p.Google.Validate()
	if err != nil {
		return err
	}
	err = p.Facebook.Validate()
	if err != nil {
		return err
	}
	err = p.SIPASS.Validate()
	if err != nil {
		return err
	}
	err = p.OIDCTesting.Validate()
	if err != nil {
		return err
	}
	err = p.SAMLTesting.Validate()
	if err != nil {
		return err
	}
	return nil
}

// Mail represents the configuration of e-mail sending.
//
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

// OIDC represents the configuration of OIDC.
//
//nolint:lll
type OIDC struct {
	Keys []kong.NamedFileContentFlag `env:"KEY_PATH" help:"File(s) with RSA, P-256, P-384, or P-521 private key(s) for signing tokens. In JWK format. Only the key from the JWK is used, other fields are ignored." name:"key" placeholder:"PATH" yaml:"keys"`

	keys []*jose.JSONWebKey
}

// Init initializes the Keys struct.
func (o *OIDC) Init(development bool) errors.E {
	for _, key := range o.Keys {
		k, errE := makeAnyKey(key.Contents)
		if errE != nil {
			errE = errors.WithMessage(errE, "invalid private key")
			errors.Details(errE)["path"] = key.Filename
			return errE
		}
		o.keys = append(o.keys, k)
	}

	if len(o.keys) == 0 && development {
		key, errE := generateRSAKey()
		if errE != nil {
			return errE
		}
		o.keys = append(o.keys, key)

		key, errE = generateEllipticKey(elliptic.P256(), "ES256")
		if errE != nil {
			return errE
		}
		o.keys = append(o.keys, key)

		key, errE = generateEllipticKey(elliptic.P384(), "ES384")
		if errE != nil {
			return errE
		}
		o.keys = append(o.keys, key)

		key, errE = generateEllipticKey(elliptic.P521(), "ES512")
		if errE != nil {
			return errE
		}
		o.keys = append(o.keys, key)
	}

	// We currently require RSA private key (among others).
	// TODO: Replace with check that at least one key is provided, once we support all algorithms from signingAlgValuesSupported.
	for _, key := range o.keys {
		// TODO: This is currently hard-coded to RS256 until we can support all from signingAlgValuesSupported.
		//       See: https://github.com/ory/fosite/issues/788
		if key.Algorithm == "RS256" {
			// We have the right key.
			return nil
		}
	}

	return errors.New("OIDC RSA private key not provided")
}

// Config represents the Charon configuration.
//
//nolint:lll
type Config struct {
	z.LoggingConfig `yaml:",inline"`

	Version kong.VersionFlag  `         help:"Show program's version and exit."                                              short:"V" yaml:"-"`
	Config  cli.ConfigFlag    `         help:"Load configuration from a JSON or YAML file." name:"config" placeholder:"PATH" short:"c" yaml:"-"`
	Server  waf.Server[*Site] `embed:""                                                                                                yaml:",inline"`

	Sites []Site `help:"Site configuration as JSON or YAML. Can be provided multiple times." name:"site" placeholder:"SITE" sep:"none" short:"s" yaml:"sites"`

	Domains      []string             `                  help:"Domain name(s) to use. If not provided, they are determined from domain names found in TLS certificates."                                 name:"domain" placeholder:"STRING" yaml:"domains"`
	MainDomain   string               `                  help:"When using multiple domains, which one is the main one."                                                                                                                     yaml:"mainDomain"`
	ExternalPort int                  `                  help:"Port on which Charon is accessible when it is different from the port on which the program listens."                                                    placeholder:"INT"    yaml:"externalPort"`
	Secret       kong.FileContentFlag `env:"SECRET_PATH" help:"File with base64 (URL encoding, no padding) encoded 32 bytes with \"${secretPrefixCharonConfig}\" prefix used for session and OIDC HMAC."               placeholder:"PATH"   yaml:"secret"`

	Providers Providers `                          embed:"" group:"Providers:"                                                                                                                    yaml:"providers"`
	Title     string    `default:"${defaultTitle}"                             help:"Title of this Charon instance as shown to users when sites are not configured." placeholder:"NAME" short:"T" yaml:"title"`

	// TODO: This is just temporary. Once we have PeerDB as backend we should just create PeerDB documents with these during populate.
	TermsOfService kong.FileContentFlag `help:"File with terms of service." placeholder:"PATH" yaml:"termsOfService"`
	PrivacyPolicy  kong.FileContentFlag `help:"File with privacy policy."   placeholder:"PATH" yaml:"privacyPolicy"`

	Mail Mail `embed:"" envprefix:"MAIL_" group:"Mail:" prefix:"mail." yaml:"mail"`

	OIDC OIDC `embed:"" envprefix:"OIDC_" group:"OIDC:" prefix:"oidc." yaml:"oidc"`
}

// Validate validates the Config struct.
//
// We have to call Validate on kong-embedded structs ourselves.
// See: https://github.com/alecthomas/kong/issues/554
func (config *Config) Validate() error {
	err := config.Server.HTTPS.Validate()
	if err != nil {
		return err //nolint:wrapcheck
	}
	err = config.Providers.Validate()
	if err != nil {
		return err
	}

	domains := mapset.NewThreadUnsafeSet[string]()
	for i, site := range config.Sites {
		if site.Domain == "" {
			return errors.Errorf(`domain is required for site at index %d`, i)
		}
		err := site.Validate()
		if err != nil {
			return errors.WithStack(err)
		}
		if site.Title == "" {
			site.Title = DefaultTitle
		}
		if !domains.Add(site.Domain) {
			return errors.Errorf(`duplicate site for domain "%s"`, site.Domain)
		}
		config.Sites[i] = site
	}
	return nil
}

// Service represents the Charon service.
type Service struct {
	waf.Service[*Site]

	hmac *hmac.HMACStrategy

	oidc     func() *fosite.Fosite
	oidcKeys []*jose.JSONWebKey

	providers []SiteProvider

	oidcProviders      func() map[Provider]oidcProvider
	samlProviders      func() map[Provider]samlProvider
	passkeyProvider    func() *webauthn.WebAuthn
	codeProvider       func() *codeProvider
	charonOrganization func() charonOrganization

	domain         string
	title          string
	termsOfService []byte
	privacyPolicy  []byte

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
	identitiesBlocked map[identifier.Identifier]map[identifier.Identifier]blockedNotes
	// Map from organization ID to map of account IDs which have been blocked in the organization,
	// to a map between identity ID which was blocked with the account and corresponding notes.
	accountsBlocked map[identifier.Identifier]map[identifier.Identifier]map[identifier.Identifier]blockedNotes
	// We use only one mutex for both identitiesBlocked and accountsBlocked as they are always used together.
	identitiesBlockedMu sync.RWMutex
}

// Init initializes the HTTP service and is used together with Prepare to implement Run.
func (config *Config) Init(files fs.ReadFileFS) (*Service, errors.E) { //nolint:maintidx
	var secret []byte
	if config.Secret != nil {
		// We use a prefix to aid secret scanners.
		if !bytes.HasPrefix(config.Secret, secretPrefixCharonConfig) {
			return nil, errors.Errorf(`secret does not have "%s" prefix`, SecretPrefixCharonConfig)
		}
		encodedSecret := bytes.TrimPrefix(config.Secret, secretPrefixCharonConfig)
		// We trim space so that the file can contain whitespace (e.g., a newline) at the end.
		encodedSecret = bytes.TrimSpace(encodedSecret)
		secret = make([]byte, base64.RawURLEncoding.DecodedLen(len(encodedSecret)))
		n, err := base64.RawURLEncoding.Decode(secret, encodedSecret)
		secret = secret[:n]
		if err != nil {
			return nil, errors.WithMessage(err, "invalid secret")
		}
		if len(secret) != expectedSecretSize {
			errE := errors.New("secret does not have valid length")
			errors.Details(errE)["got"] = len(secret)
			errors.Details(errE)["expected"] = 32
			return nil, errE
		}
	} else if config.Server.Development {
		secret = make([]byte, expectedSecretSize)
		_, err := rand.Read(secret)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	} else {
		return nil, errors.New("secret not provided")
	}

	errE := config.OIDC.Init(config.Server.Development)
	if errE != nil {
		return nil, errE
	}

	config.Server.Logger = config.Logger

	sites := map[string]*Site{}
	for i := range config.Sites {
		site := &config.Sites[i]

		sites[site.Domain] = site
	}

	if len(sites) == 0 && len(config.Domains) > 0 {
		// If sites are not provided, but default domain is,
		// we create a site based on the default domain.
		for _, domain := range config.Domains {
			sites[domain] = &Site{
				Site: waf.Site{
					Domain:   domain,
					CertFile: "",
					KeyFile:  "",
				},
				Build:          nil,
				Title:          config.Title,
				Providers:      nil,
				TermsOfService: false,
				PrivacyPolicy:  false,
			}
		}
	}

	// If sites are not provided (and no default domain), sites
	// are automatically constructed based on the certificate.
	sitesProvided := len(sites) > 0
	sites, errE = config.Server.Init(sites)
	if errE != nil {
		return nil, errE
	}

	if !sitesProvided {
		// We set fields not set when sites are automatically constructed.
		for domain, site := range sites {
			site.Title = config.Title
			// We copy the site to config.Sites.
			config.Sites = append(config.Sites, *site)
			// And then we update the reference to this copy.
			sites[domain] = &config.Sites[len(config.Sites)-1]
		}
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

	for _, site := range sites {
		site.TermsOfService = config.TermsOfService != nil
		site.PrivacyPolicy = config.PrivacyPolicy != nil
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
			oidcSecret:              strings.TrimSpace(string(config.Providers.Google.Secret)),
			oidcForcePKCE:           false,
			oidcAuthURL:             "",
			oidcTokenURL:            "",
			oidcScopes:              []string{oidc.ScopeOpenID, "email", "profile"},
			samlEntityID:            "",
			samlMetadataURL:         "",
			samlKeyStore:            nil,
			samlAttributeMapping:    samlAttributeMapping{},
			oidcEndpoint:            oauth2.Endpoint{},
			oidcClient:              nil,
			oidcSupportsPKCE:        false,
			oidcProvider:            nil,
			samlSSOURL:              "",
			samlIDPIssuer:           "",
			samlIDPCertificateStore: nil,
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
			oidcSecret:              strings.TrimSpace(string(config.Providers.Facebook.Secret)),
			oidcForcePKCE:           true,
			oidcAuthURL:             "",
			oidcTokenURL:            "https://graph.facebook.com/oauth/access_token",
			oidcScopes:              []string{oidc.ScopeOpenID, "email", "public_profile"},
			samlEntityID:            "",
			samlMetadataURL:         "",
			samlKeyStore:            nil,
			samlAttributeMapping:    samlAttributeMapping{},
			oidcEndpoint:            oauth2.Endpoint{},
			oidcClient:              nil,
			oidcSupportsPKCE:        false,
			oidcProvider:            nil,
			samlSSOURL:              "",
			samlIDPIssuer:           "",
			samlIDPCertificateStore: nil,
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
			oidcSecret:              strings.TrimSpace(string(config.Providers.OIDCTesting.Secret)),
			oidcForcePKCE:           config.Providers.OIDCTesting.ForcePKCE,
			oidcAuthURL:             config.Providers.OIDCTesting.AuthURL,
			oidcTokenURL:            config.Providers.OIDCTesting.TokenURL,
			oidcScopes:              []string{oidc.ScopeOpenID},
			samlEntityID:            "",
			samlMetadataURL:         "",
			samlKeyStore:            nil,
			samlAttributeMapping:    samlAttributeMapping{},
			oidcEndpoint:            oauth2.Endpoint{},
			oidcClient:              nil,
			oidcSupportsPKCE:        false,
			oidcProvider:            nil,
			samlSSOURL:              "",
			samlIDPIssuer:           "",
			samlIDPCertificateStore: nil,
		})
	}

	if config.Providers.SIPASS.EntityID != "" {
		samlKeyStore, errE := initSAMLKeyStore(config, config.Providers.SIPASS.Key)
		if errE != nil {
			errors.Details(errE)["provider"] = "sipass"
			return nil, errE
		}
		providers = append(providers, SiteProvider{
			Key:                     "sipass",
			Name:                    "SIPASS",
			Type:                    ThirdPartyProviderSAML,
			oidcIssuer:              "",
			oidcClientID:            "",
			oidcSecret:              "",
			oidcForcePKCE:           false,
			oidcAuthURL:             "",
			oidcTokenURL:            "",
			oidcScopes:              nil,
			samlEntityID:            config.Providers.SIPASS.EntityID,
			samlMetadataURL:         config.Providers.SIPASS.MetadataURL,
			samlKeyStore:            samlKeyStore,
			samlAttributeMapping:    getSIPASSAttributeMapping(),
			oidcEndpoint:            oauth2.Endpoint{},
			oidcClient:              nil,
			oidcSupportsPKCE:        false,
			oidcProvider:            nil,
			samlSSOURL:              "",
			samlIDPIssuer:           "",
			samlIDPCertificateStore: nil,
		})
	}
	if config.Server.Development {
		samlKeyStore, errE := initSAMLKeyStore(config, nil)
		if errE != nil {
			errors.Details(errE)["provider"] = "mockSAML"
			return nil, errE
		}
		providers = append(providers, SiteProvider{
			Key:                     "mockSAML",
			Name:                    "MockSAML",
			Type:                    ThirdPartyProviderSAML,
			oidcIssuer:              "",
			oidcClientID:            "",
			oidcSecret:              "",
			oidcForcePKCE:           false,
			oidcAuthURL:             "",
			oidcTokenURL:            "",
			oidcScopes:              nil,
			samlEntityID:            mockSAMLEntityID,
			samlMetadataURL:         mockSAMLMetadataURL,
			samlKeyStore:            samlKeyStore,
			samlAttributeMapping:    getDefaultAttributeMapping(),
			oidcEndpoint:            oauth2.Endpoint{},
			oidcClient:              nil,
			oidcSupportsPKCE:        false,
			oidcProvider:            nil,
			samlSSOURL:              "",
			samlIDPIssuer:           "",
			samlIDPCertificateStore: nil,
		})
	}
	if config.Providers.SAMLTesting.MetadataURL != "" && config.Providers.SAMLTesting.EntityID != "" {
		samlKeyStore, errE := initSAMLKeyStore(config, nil)
		if errE != nil {
			errors.Details(errE)["provider"] = "samlTesting"
			return nil, errE
		}
		providers = append(providers, SiteProvider{
			Key:                     "samlTesting",
			Name:                    "SAML Testing",
			Type:                    ThirdPartyProviderSAML,
			oidcIssuer:              "",
			oidcClientID:            "",
			oidcSecret:              "",
			oidcForcePKCE:           false,
			oidcAuthURL:             "",
			oidcTokenURL:            "",
			oidcScopes:              nil,
			samlEntityID:            config.Providers.SAMLTesting.EntityID,
			samlMetadataURL:         config.Providers.SAMLTesting.MetadataURL,
			samlKeyStore:            samlKeyStore,
			samlAttributeMapping:    getDefaultAttributeMapping(),
			oidcEndpoint:            oauth2.Endpoint{},
			oidcClient:              nil,
			oidcSupportsPKCE:        false,
			oidcProvider:            nil,
			samlSSOURL:              "",
			samlIDPIssuer:           "",
			samlIDPCertificateStore: nil,
		})
	}

	for _, site := range sites {
		site.Providers = providers
		if site.Title == "" {
			site.Title = config.Title
		}
	}

	var domain string
	if len(sites) > 1 {
		if config.MainDomain == "" {
			return nil, errors.New("main domain is not configured, but multiple domains are used")
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
			return nil, errE
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

	service := &Service{
		Service: waf.Service[*Site]{
			Logger:          config.Logger,
			CanonicalLogger: config.Logger,
			WithContext:     config.WithContext,
			StaticFiles:     files.(fs.ReadFileFS), //nolint:errcheck
			Routes:          nil,
			Sites:           sites,
			// We serve our own context.json file.
			SiteContextPath: "",
			RoutesPath:      "/routes.json",
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
		oidcKeys:               config.OIDC.keys,
		providers:              providers,
		oidcProviders:          nil,
		samlProviders:          nil,
		passkeyProvider:        nil,
		codeProvider:           nil,
		charonOrganization:     nil,
		domain:                 domain,
		title:                  config.Title,
		termsOfService:         config.TermsOfService,
		privacyPolicy:          config.PrivacyPolicy,
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
		identitiesBlocked:      map[identifier.Identifier]map[identifier.Identifier]blockedNotes{},
		accountsBlocked:        map[identifier.Identifier]map[identifier.Identifier]map[identifier.Identifier]blockedNotes{},
		identitiesBlockedMu:    sync.RWMutex{},
	}

	service.setRoutes()

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
			return nil, errors.WithStack(err)
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

	// We iterate over providers using an index to be able to mutate them.
	for i := range providers {
		errE = providers[i].initProvider(config)
		if errE != nil {
			errors.Details(errE)["provider"] = providers[i].Key
			return nil, errE
		}
	}

	return service, nil
}

// Prepare prepares the HTTP service for serving.
func (config *Config) Prepare(service *Service) (http.Handler, errors.E) {
	// Construct the main handler for the service using the router.
	router := new(waf.Router)
	handler, errE := service.RouteWith(router)
	if errE != nil {
		return nil, errE
	}

	// We prepare initialization of OIDC and providers and in the common case
	// (when server's bind port is not 0) immediately do the initialization.
	service.oidc, errE = initOIDC(config, service)
	if errE != nil {
		return nil, errE
	}
	service.oidcProviders, errE = initOIDCProviders(config, service)
	if errE != nil {
		return nil, errE
	}
	service.samlProviders, errE = initSAMLProviders(config, service)
	if errE != nil {
		return nil, errE
	}
	service.passkeyProvider, errE = initPasskeyProvider(config, service)
	if errE != nil {
		return nil, errE
	}
	service.codeProvider, errE = initCodeProvider(config, service)
	if errE != nil {
		return nil, errE
	}
	service.charonOrganization, errE = initCharonOrganization(config, service)
	if errE != nil {
		return nil, errE
	}

	// In the case when server's bind port is 0, we access values once to start
	// delayed initialization (initialization will block until the server runs).
	go service.oidc()
	go service.oidcProviders()
	go service.samlProviders()
	go service.passkeyProvider()
	go service.codeProvider()
	go service.charonOrganization()

	return handler, nil
}

// Run starts the HTTP server and serves the Charon application.
func (config *Config) Run(files fs.FS) errors.E {
	f, ok := files.(fs.ReadFileFS)
	if !ok {
		return errors.New("files fs.ReadFileFS error")
	}

	// We stop the server gracefully on ctrl-c and TERM signal.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	service, errE := config.Init(f)
	if errE != nil {
		return errE
	}

	handler, errE := config.Prepare(service)
	if errE != nil {
		return errE
	}

	// It returns only on error or if the server is gracefully shut down using ctrl-c.
	return config.Server.Run(ctx, handler)
}
