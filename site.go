package charon

import (
	"gitlab.com/tozd/waf"
)

type Build struct {
	Version        string `json:"version,omitempty"`
	BuildTimestamp string `json:"buildTimestamp,omitempty"`
	Revision       string `json:"revision,omitempty"`
}

type SiteProvider struct {
	Key  Provider `json:"key"`
	Name string   `json:"name"`
	Type string   `json:"type"`

	// Private fields.
	oidcIssuer    string
	oidcClientID  string
	oidcSecret    string
	oidcForcePKCE bool
	oidcAuthURL   string
	oidcTokenURL  string
	oidcScopes    []string

	metadataURL string
}

type Site struct {
	waf.Site

	Build     *Build         `json:"build,omitempty"`
	Providers []SiteProvider `json:"providers"`
}
