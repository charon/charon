package charon

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"

	"github.com/alecthomas/kong"
	"gitlab.com/tozd/go/cli"
	"gitlab.com/tozd/go/errors"
	z "gitlab.com/tozd/go/zerolog"

	"gitlab.com/tozd/waf"
)

const (
	DefaultProxyTo  = "http://localhost:5173"
	DefaultTLSCache = "letsencrypt"
)

//go:embed routes.json
var routesConfiguration []byte

//go:embed dist
var files embed.FS

type Provider struct {
	ClientID string `env:"CLIENT_ID" help:"${provider}'s client ID. Environment variable: ${env}." yaml:"clientId"`
	Secret   string `env:"SECRET"    help:"${provider}'s secret. Environment variable: ${env}."    yaml:"secret"`
}

// TODO: Add Kong validator to Provider to validate that or both or none fields are set.
//       See: https://github.com/alecthomas/kong/issues/90

type Providers struct {
	Google   Provider `embed:"" envprefix:"GOOGLE_"   prefix:"google."   set:"provider=Google"   yaml:"google"`
	Facebook Provider `embed:"" envprefix:"FACEBOOK_" prefix:"facebook." set:"provider=Facebook" yaml:"facebook"`
}

//nolint:lll
type App struct {
	z.LoggingConfig `yaml:",inline"`

	Version kong.VersionFlag  `         help:"Show program's version and exit."                                              short:"V" yaml:"-"`
	Config  cli.ConfigFlag    `         help:"Load configuration from a JSON or YAML file." name:"config" placeholder:"PATH" short:"c" yaml:"-"`
	Server  waf.Server[*Site] `embed:""                                                                                                yaml:",inline"`

	Domains    []string `help:"Domain name(s) to use. If not provided, they are determined from domain names found in TLS certificates." name:"domain" placeholder:"STRING" short:"D" yaml:"domains"`
	MainDomain string   `help:"When using multiple domains, which one is the main one."                                                                                               yaml:"mainDomain"`

	Providers Providers `embed:"" group:"Providers:" yaml:"providers"`
}

type Service struct {
	waf.Service[*Site]

	providers func() map[string]oidcProvider
}

func (app *App) Run() errors.E {
	// Routes come from a single source of truth, e.g., a file.
	var routesConfig struct {
		Routes []waf.Route `json:"routes"`
	}
	err := json.Unmarshal(routesConfiguration, &routesConfig)
	if err != nil {
		return errors.WithStack(err)
	}

	app.Server.Logger = app.Logger

	sites := map[string]*Site{}
	// If domains are provided, we create sites based on those domains.
	for _, domain := range app.Domains {
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
	sites, errE := app.Server.Init(nil)
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
	if app.Providers.Google.ClientID != "" && app.Providers.Google.Secret != "" {
		providers = append(providers, SiteProvider{
			Key:       "google",
			Name:      "Google",
			issuer:    "https://accounts.google.com",
			clientID:  app.Providers.Google.ClientID,
			secret:    app.Providers.Google.Secret,
			forcePKCE: false,
			authURL:   "",
			tokenURL:  "",
		})
	}
	if app.Providers.Facebook.ClientID != "" && app.Providers.Facebook.Secret != "" {
		providers = append(providers, SiteProvider{
			Key:       "facebook",
			Name:      "Facebook",
			issuer:    "https://www.facebook.com",
			clientID:  app.Providers.Facebook.ClientID,
			secret:    app.Providers.Facebook.Secret,
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

	service := &Service{ //nolint:forcetypeassert
		waf.Service[*Site]{ //nolint:exhaustruct
			Logger:          app.Logger,
			CanonicalLogger: app.Logger,
			WithContext:     app.WithContext,
			StaticFiles:     f.(fs.ReadFileFS),
			Routes:          routesConfig.Routes,
			Sites:           sites,
			SiteContextPath: "/index.json",
			Development:     app.Server.InDevelopment(),
			SkipServingFile: func(path string) bool {
				// We want files to be served by Home route at / and /api and not be
				// available at index.html and index.json (as well).
				return path == "/index.html" || path == "/index.json"
			},
		},
		nil,
	}

	var domain string
	if len(sites) > 1 {
		if app.MainDomain == "" {
			return errors.New("main domain is not configured, but multiple domains are used")
		}
		if _, ok := sites[app.MainDomain]; !ok {
			errE = errors.New("main domain is not among domains")
			errors.Details(errE)["main"] = app.MainDomain
			domains := []string{}
			for domain := range sites {
				domains = append(domains, domain)
			}
			sort.Strings(domains)
			errors.Details(errE)["domains"] = domains
			return errE
		}

		service.Middleware = append(service.Middleware, service.RedirectToMainSite(app.MainDomain))
		domain = app.MainDomain
	} else {
		// There is only one really here. app.Server.Init errors if there are not sites.
		for d := range sites {
			domain = d
			break
		}
	}

	service.providers = sync.OnceValue(initProviders(app, service, domain, providers))

	// Construct the main handler for the service using the router.
	handler, errE := service.RouteWith(service, &waf.Router{}) //nolint:exhaustruct
	if errE != nil {
		return errE
	}

	// We start initialization of providers.
	// Initialization will block until the server runs.
	go service.providers()

	// We stop the server gracefully on ctrl-c and TERM signal.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// It returns only on error or if the server is gracefully shut down using ctrl-c.
	return app.Server.Run(ctx, handler)
}
