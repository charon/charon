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
	issuer    string
	clientID  string
	secret    string
	forcePKCE bool
	authURL   string
	tokenURL  string
}

type Site struct {
	waf.Site

	Build     *Build         `json:"build,omitempty"`
	Providers []SiteProvider `json:"providers"`
}
