package main

import (
	"slices"
	"strings"

	"github.com/alecthomas/kong"
	"gitlab.com/tozd/go/cli"
	"gitlab.com/tozd/go/errors"

	"gitlab.com/charon/charon"
)

func main() {
	mailAuthTypes := []string{}
	for t := range charon.MailAuthTypes {
		mailAuthTypes = append(mailAuthTypes, t)
	}
	slices.Sort(mailAuthTypes)
	var config charon.Config
	cli.Run(&config, kong.Vars{
		"defaultProxyTo":           charon.DefaultProxyTo,
		"defaultTLSCache":          charon.DefaultTLSCache,
		"defaultMailAuth":          "none",
		"defaultMailFrom":          "noreply@example.com",
		"mailAuthTypes":            strings.Join(mailAuthTypes, ","),
		"secretPrefixCharonConfig": charon.SecretPrefixCharonConfig,
		"developmentModeHelp":      " Proxy unknown requests, send debug messages to clients, generate secret and keys if not provided. LEAKS SENSITIVE INFORMATION!",
	}, func(ctx *kong.Context) errors.E {
		return errors.WithStack(ctx.Run())
	}, kong.Groups{
		"OIDC:": "OIDC:\nPrivate keys for signing tokens should be in JWK format. Only keys in JWKs are used, other fields are ignored.",
	})
}
