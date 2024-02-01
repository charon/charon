package main

import (
	"slices"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/wneessen/go-mail"
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
		"defaultProxyTo":  charon.DefaultProxyTo,
		"defaultTLSCache": charon.DefaultTLSCache,
		"defaultMailAuth": strings.ToLower(string(mail.SMTPAuthPlain)),
		"mailAuthTypes":   strings.Join(mailAuthTypes, ","),
	}, func(ctx *kong.Context) errors.E {
		return errors.WithStack(ctx.Run())
	})
}
