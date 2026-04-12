// Command charon provides the command-line interface for Charon.
package main

import (
	"slices"
	"strings"

	"github.com/alecthomas/kong"
	"gitlab.com/tozd/go/cli"
	"gitlab.com/tozd/go/errors"

	"gitlab.com/charon/charon"
	"gitlab.com/charon/charon/dist"
)

func main() {
	mailAuthTypes := []string{}
	for t := range charon.MailAuthTypes {
		mailAuthTypes = append(mailAuthTypes, t)
	}
	slices.Sort(mailAuthTypes)
	var config charon.Config
	//nolint:lll
	cli.Run(&config, kong.Vars{
		"defaultListen":            charon.DefaultListen,
		"defaultProxyTo":           charon.DefaultProxyTo,
		"defaultTitle":             charon.DefaultTitle,
		"defaultMailAuth":          "none",
		"defaultMailFrom":          "noreply@example.com",
		"defaultSIPASSMetadataURL": charon.DefaultSIPASSMetadataURL,
		"mailAuthTypes":            strings.Join(mailAuthTypes, ","),
		"secretPrefixCharonConfig": charon.SecretPrefixCharonConfig,
		"developmentModeHelp":      " Proxy unknown requests, send debug messages to clients, generate the secret and private keys if not provided, enable MockSAML provider. LEAKS SENSITIVE INFORMATION!",
	}, func(ctx *cli.Context) errors.E {
		return ctx.Run()
	},
		// We have to use BindFor instead of passing it directly to Run because we are using an interface.
		// See: https://github.com/alecthomas/kong/issues/48
		kong.BindFor(dist.Files),
	)
}
