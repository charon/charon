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

type SAMLAttributeMapping struct {
	CredentialIDAttribute string            `yaml:"credentialIdAttribute"`
	Mappings              map[string]string `yaml:"mappings"`
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

func getSIPASSAttributeMapping() SAMLAttributeMapping {
	return SAMLAttributeMapping{
		CredentialIDAttribute: "1.3.6.1.4.1.44044.1.1.3.2", // VATNumber.
		Mappings: map[string]string{
			"1.3.6.1.4.1.44044.1.1.3.1":  "token", // SICAS Token - unique identifier.
			"1.3.6.1.4.1.44044.1.1.3.2":  "authMethod",
			"1.3.6.1.4.1.44044.1.1.3.3":  "authMechanism",
			"1.3.6.1.4.1.44044.1.1.3.10": "language",
		},
	}
}

func getDefaultAttributeMapping() SAMLAttributeMapping {
	return SAMLAttributeMapping{
		CredentialIDAttribute: "NameID",
		Mappings:              map[string]string{},
	}
}
