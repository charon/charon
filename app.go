package charon

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"os"
	"os/signal"
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

type App struct {
	z.LoggingConfig `yaml:",inline"`

	Version kong.VersionFlag  `         help:"Show program's version and exit."                                              short:"V" yaml:"-"`
	Config  cli.ConfigFlag    `         help:"Load configuration from a JSON or YAML file." name:"config" placeholder:"PATH" short:"c" yaml:"-"`
	Server  waf.Server[*Site] `embed:""                                                                                                yaml:",inline"`
}

type Service struct {
	waf.Service[*Site]
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

	// Sites are automatically constructed based on the certificate or domain name for Let's Encrypt.
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
	}

	// Construct the main handler for the service using the router.
	handler, errE := service.RouteWith(service, &waf.Router{}) //nolint:exhaustruct
	if errE != nil {
		return errE
	}

	// We stop the server gracefully on ctrl-c and TERM signal.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// It returns only on error or if the server is gracefully shut down using ctrl-c.
	return app.Server.Run(ctx, handler)
}
