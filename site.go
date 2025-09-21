package charon

import (
	dsig "github.com/russellhaering/goxmldsig"
	"gitlab.com/tozd/waf"
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

	// Private fields.
	oidcIssuer    string
	oidcClientID  string
	oidcSecret    string
	oidcForcePKCE bool
	oidcAuthURL   string
	oidcTokenURL  string
	oidcScopes    []string

	samlEntityID         string
	samlMetadataURL      string
	samlKeyStore         dsig.X509KeyStore
	samlAttributeMapping SAMLAttributeMapping
}

type Site struct {
	waf.Site

	Build     *Build         `json:"build,omitempty"`
	Providers []SiteProvider `json:"providers"`
}
