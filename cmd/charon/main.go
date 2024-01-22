package main

import (
	"sort"
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
	sort.Strings(mailAuthTypes)
	var app charon.App
	cli.Run(&app, kong.Vars{
		"defaultProxyTo":  charon.DefaultProxyTo,
		"defaultTLSCache": charon.DefaultTLSCache,
		"defaultMailAuth": strings.ToLower(string(mail.SMTPAuthPlain)),
		"mailAuthTypes":   strings.Join(mailAuthTypes, ","),
	}, func(ctx *kong.Context) errors.E {
		return errors.WithStack(ctx.Run())
	})
}
