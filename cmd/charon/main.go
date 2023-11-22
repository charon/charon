package main

import (
	"github.com/alecthomas/kong"
	"gitlab.com/tozd/go/cli"
	"gitlab.com/tozd/go/errors"

	"gitlab.com/charon/charon"
)

func main() {
	var app charon.App
	cli.Run(&app, kong.Vars{
		"defaultProxyTo":  charon.DefaultProxyTo,
		"defaultTLSCache": charon.DefaultTLSCache,
	}, func(ctx *kong.Context) errors.E {
		return errors.WithStack(ctx.Run())
	})
}
