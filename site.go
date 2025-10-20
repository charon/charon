package charon

import (
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	dsig "github.com/russellhaering/goxmldsig"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/waf"
	"golang.org/x/oauth2"
)

type Build struct {
	Version        string `json:"version,omitempty"`
	BuildTimestamp string `json:"buildTimestamp,omitempty"`
	Revision       string `json:"revision,omitempty"`
}

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
	samlAttributeMapping SAMLAttributeMapping

	// SAML provider initialization fields.
	samlSSOURL              string
	samlIDPIssuer           string
	samlIDPCertificateStore dsig.X509CertificateStore
}

type Site struct {
	waf.Site

	Build     *Build         `json:"build,omitempty"`
	Providers []SiteProvider `json:"providers"`
}

func (p *SiteProvider) initProvider(config *Config) errors.E {
	switch p.Type {
	case ThirdPartyProviderOIDC:
		return p.initOIDCProvider(config)
	case ThirdPartyProviderSAML:
		return p.initSAMLProvider(config)
	default:
		errE := errors.New("unsupported provider type")
		errors.Details(errE)["type"] = p.Type
		return errE
	}
}
