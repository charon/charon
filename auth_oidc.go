package charon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/go-cleanhttp"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
	"golang.org/x/oauth2"
)

type oidcProvider struct {
	Key          Provider
	Name         string
	Provider     *oidc.Provider
	Verifier     *oidc.IDTokenVerifier
	Config       *oauth2.Config
	Client       *http.Client
	SupportsPKCE bool
}

func initOIDCProviders(config *Config, service *Service, domain string, providers []SiteProvider) (func() map[Provider]oidcProvider, errors.E) {
	return initWithHost(config, domain, func(host string) map[Provider]oidcProvider {
		oidcProviders := map[Provider]oidcProvider{}
		for _, p := range providers {
			if p.Type != ThirdPartyProviderOIDC {
				continue
			}

			provider, errE := initOIDCProvider(service, host, p)
			if errE != nil {
				errors.Details(errE)["provider"] = p.Key
				// Internal error: this should never happen.
				panic(errE)
			}

			oidcProviders[p.Key] = provider
		}

		return oidcProviders
	})
}

func initOIDCProvider(service *Service, host string, p SiteProvider) (oidcProvider, errors.E) {
	path, errE := service.Reverse("AuthThirdPartyProvider", waf.Params{"provider": string(p.Key)}, nil)
	if errE != nil {
		return oidcProvider{}, errE
	}

	c := &oauth2.Config{
		ClientID:     p.oidcClientID,
		ClientSecret: p.oidcSecret,
		RedirectURL:  fmt.Sprintf("https://%s%s", host, path),
		Endpoint:     p.oidcEndpoint,
		Scopes:       p.oidcScopes,
	}

	return oidcProvider{
		Key:          p.Key,
		Name:         p.Name,
		Provider:     p.oidcProvider,
		Verifier:     p.oidcProvider.Verifier(&oidc.Config{ClientID: p.oidcClientID}), //nolint:exhaustruct
		Config:       c,
		Client:       p.oidcClient,
		SupportsPKCE: p.oidcSupportsPKCE,
	}, nil
}

func (p *SiteProvider) initOIDCProvider(config *Config) errors.E {
	config.Logger.Debug().Msgf("enabling %s OIDC provider", p.Key)

	client := cleanhttp.DefaultPooledClient()
	ctx := oidc.ClientContext(context.Background(), client)
	provider, err := oidc.NewProvider(ctx, p.oidcIssuer)
	if err != nil {
		return errors.WithStack(err)
	}

	// We make sure JWKS URI is provided.
	// See: https://github.com/coreos/go-oidc/pull/328
	var jwksClaims struct {
		JWKSURL string `json:"jwks_uri"` //nolint:tagliatelle
	}
	err = provider.Claims(&jwksClaims)
	if err != nil {
		return errors.WithStack(err)
	}
	if jwksClaims.JWKSURL == "" {
		return errors.New("jwks_uri is empty")
	}

	supportsPKCE := p.oidcForcePKCE
	if !supportsPKCE {
		// We have to parse it out ourselves.
		// See: https://github.com/coreos/go-oidc/issues/401
		var pkceClaims struct {
			CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"` //nolint:tagliatelle
		}
		err := provider.Claims(&pkceClaims)
		if err != nil {
			return errors.WithStack(err)
		}
		supportsPKCE = slices.Contains(pkceClaims.CodeChallengeMethodsSupported, "S256")
	}

	// Fallback if endpoints are missing (e.g., Facebook does not have token_endpoint
	// in its https://www.facebook.com/.well-known/openid-configuration).
	endpoint := provider.Endpoint()
	if endpoint.AuthURL == "" {
		endpoint.AuthURL = p.oidcAuthURL
	}
	if endpoint.TokenURL == "" {
		endpoint.TokenURL = p.oidcTokenURL
	}

	p.oidcEndpoint = endpoint
	p.oidcClient = client
	p.oidcSupportsPKCE = supportsPKCE
	p.oidcProvider = provider

	return nil
}

func (s *Service) handlerOIDCStart(provider oidcProvider) func(*flow) (string, errors.E) {
	return func(flow *flow) (string, errors.E) {
		flow.OIDCProvider = &flowOIDCProvider{
			Verifier: "",
			Nonce:    identifier.New().String(),
		}

		opts := []oauth2.AuthCodeOption{}
		opts = append(opts, oidc.Nonce(flow.OIDCProvider.Nonce))

		if provider.SupportsPKCE {
			flow.OIDCProvider.Verifier = oauth2.GenerateVerifier()
			opts = append(opts, oauth2.S256ChallengeOption(flow.OIDCProvider.Verifier))
		}

		return provider.Config.AuthCodeURL(flow.ID.String(), opts...), nil
	}
}

func (s *Service) handleOIDCCallback(w http.ResponseWriter, req *http.Request, providerKey Provider, provider oidcProvider) {
	ctx := req.Context()

	// State should be provided even in the case of an error.
	flow := s.getActiveFlowNoAuthStep(w, req, req.Form.Get("state"))
	if flow == nil {
		return
	}

	if flow.OIDCProvider == nil {
		s.BadRequestWithError(w, req, errors.New("OIDC provider not started"))
		return
	}

	flowOIDC := *flow.OIDCProvider

	// We reset flow.OIDCProvider to nil always after this point, even if there is a failure,
	// so that nonce cannot be reused.
	flow.OIDCProvider = nil
	errE := s.setFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	errorCode := req.Form.Get("error")
	errorDescription := req.Form.Get("error_description")
	if errorCode != "" || errorDescription != "" {
		errE = errors.New("OIDC authorization error")
		errors.Details(errE)["code"] = errorCode
		errors.Details(errE)["description"] = errorDescription
		errors.Details(errE)["provider"] = providerKey
		s.failAuthStep(w, req, false, flow, errE)
		return
	}

	ctx = oidc.ClientContext(ctx, provider.Client)

	opts := []oauth2.AuthCodeOption{}
	if provider.SupportsPKCE {
		opts = append(opts, oauth2.VerifierOption(flowOIDC.Verifier))
	}

	oauth2Token, err := provider.Config.Exchange(ctx, req.Form.Get("code"), opts...)
	if err != nil {
		errE = errors.WithStack(err)
		errors.Details(errE)["provider"] = providerKey
		s.BadRequestWithError(w, req, errE)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		errE = errors.New("ID token missing")
		errors.Details(errE)["provider"] = providerKey
		s.BadRequestWithError(w, req, errE)
		return
	}

	idToken, err := provider.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		errE = errors.WithStack(err)
		errors.Details(errE)["provider"] = providerKey
		s.BadRequestWithError(w, req, errE)
		return
	}

	if idToken.Nonce != flowOIDC.Nonce {
		errE = errors.New("nonce mismatch")
		errors.Details(errE)["provider"] = providerKey
		s.BadRequestWithError(w, req, errE)
		return
	}

	var jsonData json.RawMessage
	err = idToken.Claims(&jsonData)
	if err != nil {
		errE = errors.WithStack(err)
		errors.Details(errE)["provider"] = providerKey
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	var token map[string]interface{}
	errE = x.Unmarshal(jsonData, &token)
	if errE != nil {
		errors.Details(errE)["provider"] = providerKey
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	displayName := findFirstString(token, "username", "preferred_username", "email", "eMailAddress", "emailAddress", "email_address")
	if displayName == "" {
		displayName = idToken.Subject
	}

	account, errE := s.getAccountByCredential(ctx, providerKey, idToken.Subject)
	if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		errors.Details(errE)["provider"] = providerKey
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	displayName = ensureUniqueDisplayName(account, providerKey, displayName)

	s.completeAuthStep(w, req, false, flow, account,
		[]Credential{{
			CredentialPublic: CredentialPublic{
				ID:          identifier.New(),
				Provider:    providerKey,
				DisplayName: displayName,
				Verified:    false,
			},
			ProviderID: idToken.Subject,
			Data:       jsonData,
		}})
}
