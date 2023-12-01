package charon

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/go-cleanhttp"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
	"golang.org/x/oauth2"
)

type oidcProvider struct {
	Provider     *oidc.Provider
	Verifier     *oidc.IDTokenVerifier
	Config       *oauth2.Config
	Client       *http.Client
	SupportsPKCE bool
}

func initProviders(app *App, service *Service, domain string, providers []SiteProvider) func() map[string]oidcProvider {
	return func() map[string]oidcProvider {
		host, errE := getHost(app, domain)
		if errE != nil {
			panic(errE)
		}
		if host == "" {
			// Server failed to start. We just return in this case.
			return nil
		}

		oidcProviders := map[string]oidcProvider{}
		for _, p := range providers {
			app.Logger.Debug().Msgf("enabling %s provider", p.Name)

			path, errE := service.ReverseAPI("AuthProviderCallback", waf.Params{"provider": p.Key}, nil)
			if errE != nil {
				panic(errE)
			}

			client := cleanhttp.DefaultPooledClient()
			ctx := oidc.ClientContext(context.Background(), client)
			provider, err := oidc.NewProvider(ctx, p.issuer)
			if err != nil {
				panic(errors.WithStack(err))
			}

			// We make sure JWKS URI is provided.
			// See: https://github.com/coreos/go-oidc/pull/328
			var jwksClaims struct {
				JWKSURL string `json:"jwks_uri"` //nolint:tagliatelle
			}
			err = provider.Claims(&jwksClaims)
			if err != nil {
				panic(errors.WithStack(err))
			}
			if jwksClaims.JWKSURL == "" {
				panic(errors.New("jwks_uri is empty"))
			}

			supportsPKCE := p.forcePKCE
			if !supportsPKCE {
				// We have to parse it out ourselves.
				// See: https://github.com/coreos/go-oidc/issues/401
				var pkceClaims struct {
					CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"` //nolint:tagliatelle
				}
				err := provider.Claims(&pkceClaims)
				if err != nil {
					panic(errors.WithStack(err))
				}
				supportsPKCE = slices.Contains(pkceClaims.CodeChallengeMethodsSupported, "S256")
			}

			// Fallback if endpoints are missing (e.g., Facebook does not have token_endpoint
			// in its https://www.facebook.com/.well-known/openid-configuration).
			endpoint := provider.Endpoint()
			if endpoint.AuthURL == "" {
				endpoint.AuthURL = p.authURL
			}
			if endpoint.TokenURL == "" {
				endpoint.TokenURL = p.tokenURL
			}

			config := &oauth2.Config{
				ClientID:     p.clientID,
				ClientSecret: p.secret,
				RedirectURL:  fmt.Sprintf("https://%s%s", host, path),
				Endpoint:     endpoint,
				Scopes:       []string{oidc.ScopeOpenID},
			}

			oidcProviders[p.Key] = oidcProvider{
				Provider:     provider,
				Verifier:     provider.Verifier(&oidc.Config{ClientID: p.clientID}), //nolint:exhaustruct
				Config:       config,
				Client:       client,
				SupportsPKCE: supportsPKCE,
			}
		}
		return oidcProviders
	}
}

func (s *Service) AuthProviderPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	// We redirect user's browser to this endpoint so we set api=false in the following call.
	flow := s.GetActiveFlow(w, req, false, FlowParameterName)
	if flow == nil {
		return
	}

	provider, ok := s.providers()[req.Form.Get("provider")]
	if !ok {
		errE := errors.New("unknown provider")
		errors.Details(errE)["provider"] = req.Form.Get("provider")
		s.BadRequestWithError(w, req, errE)
		return
	}

	opts := []oauth2.AuthCodeOption{}

	// TODO: What if flow.OIDC is already set?
	flow.OIDC = &FlowOIDC{
		Verifier: "",
		Nonce:    identifier.New().String(),
	}
	opts = append(opts, oidc.Nonce(flow.OIDC.Nonce))

	if provider.SupportsPKCE {
		verifier := oauth2.GenerateVerifier()
		flow.OIDC.Verifier = verifier
		opts = append(opts, oauth2.S256ChallengeOption(verifier))
	}

	errE := SetFlow(req.Context(), flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.TemporaryRedirectGetMethod(w, req, provider.Config.AuthCodeURL(flow.ID.String(), opts...))
}

func (s *Service) AuthProviderCallbackGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	provider, ok := s.providers()[params["provider"]]
	if !ok {
		errE := errors.New("unknown provider")
		errors.Details(errE)["provider"] = params["provider"]
		s.BadRequestWithError(w, req, errE)
		return
	}

	// We redirect user's browser to this endpoint so we set api=false in the following call.
	// State should be provided even in the case of an error.
	flow := s.GetActiveFlow(w, req, false, "state")
	if flow == nil {
		return
	}

	if flow.OIDC == nil {
		s.BadRequestWithError(w, req, errors.New("provider not started"))
		return
	}

	errorCode := req.Form.Get("error")
	errorDescription := req.Form.Get("error_description")
	if errorCode != "" || errorDescription != "" {
		errE := errors.New("authorization error")
		errors.Details(errE)["code"] = errorCode
		errors.Details(errE)["description"] = errorDescription
		s.BadRequestWithError(w, req, errE)
		return
	}

	ctx := oidc.ClientContext(req.Context(), provider.Client)

	opts := []oauth2.AuthCodeOption{}

	if provider.SupportsPKCE {
		opts = append(opts, oauth2.VerifierOption(flow.OIDC.Verifier))
	}

	oauth2Token, err := provider.Config.Exchange(ctx, req.Form.Get("code"), opts...)
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		s.BadRequestWithError(w, req, errors.New("ID token missing"))
		return
	}

	idToken, err := provider.Verifier.Verify(ctx, rawIDToken)
	if !ok {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	if idToken.Nonce != flow.OIDC.Nonce {
		s.BadRequestWithError(w, req, errors.New("nonce mismatch"))
		return
	}

	s.completeAuthStep(w, req, flow, params["provider"], idToken.Subject)
}
