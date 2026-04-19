package charon

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/coreos/go-oidc/v3/oidc"
	dsig "github.com/russellhaering/goxmldsig"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/waf"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

// Build represents the build information of the site.
type Build struct {
	Version        string `json:"version,omitempty"`
	BuildTimestamp string `json:"buildTimestamp,omitempty"`
	Revision       string `json:"revision,omitempty"`
}

// SiteProvider represents a third-party authentication provider available on the site.
type SiteProvider struct {
	Key  Provider               `json:"key"`
	Name string                 `json:"name"`
	Type ThirdPartyProviderType `json:"type"`

	// OIDC provider configuration fields.
	oidcIssuer    string
	oidcClientID  string
	oidcSecret    string
	oidcForcePKCE bool
	oidcAuthURL   string
	oidcTokenURL  string
	oidcScopes    []string

	// OIDC provider initialization fields.
	oidcEndpoint     oauth2.Endpoint
	oidcClient       *http.Client
	oidcSupportsPKCE bool
	oidcProvider     *oidc.Provider

	// SAML provider configuration fields.
	samlEntityID         string
	samlMetadataURL      string
	samlKeyStore         dsig.X509KeyStore
	samlAttributeMapping samlAttributeMapping

	// SAML provider initialization fields.
	samlSSOURL              string
	samlIDPIssuer           string
	samlIDPCertificateStore dsig.X509CertificateStore
}

// Site represents the site configuration.
type Site struct {
	waf.Site `yaml:",inline"`

	Build *Build `json:"build,omitempty" yaml:"-"`

	Title     string         `json:"title,omitempty" yaml:"title,omitempty"`
	Providers []SiteProvider `json:"providers"       yaml:"-"`

	PrivacyPolicy  bool `json:"privacyPolicy,omitempty"  yaml:"-"`
	TermsOfService bool `json:"termsOfService,omitempty" yaml:"-"`
}

func (p *SiteProvider) initProvider(ctx context.Context, config *Config) errors.E {
	switch p.Type {
	case ThirdPartyProviderOIDC:
		return p.initOIDCProvider(ctx, config)
	case ThirdPartyProviderSAML:
		return p.initSAMLProvider(ctx, config)
	default:
		errE := errors.New("unsupported provider type")
		errors.Details(errE)["type"] = p.Type
		return errE
	}
}

// Decode implements kong.MapperValue to decode Site from JSON/YAML configuration.
func (s *Site) Decode(ctx *kong.DecodeContext) error {
	var value string
	err := ctx.Scan.PopValueInto("value", &value)
	if err != nil {
		return errors.WithStack(err)
	}
	decoder := yaml.NewDecoder(strings.NewReader(value))
	decoder.KnownFields(true)
	err = decoder.Decode(s)
	if err != nil {
		var yamlErr *yaml.TypeError
		if errors.As(err, &yamlErr) {
			e := "error"
			if len(yamlErr.Errors) > 1 {
				e = "errors"
			}
			return errors.Errorf("yaml: unmarshal %s: %s", e, strings.Join(yamlErr.Errors, "; "))
		} else if errors.Is(err, io.EOF) {
			return nil
		}
		return errors.WithStack(err)
	}
	return nil
}
