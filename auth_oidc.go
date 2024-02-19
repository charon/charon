package charon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	Provider     *oidc.Provider
	Verifier     *oidc.IDTokenVerifier
	Config       *oauth2.Config
	Client       *http.Client
	SupportsPKCE bool
}

func initOIDCProviders(config *Config, service *Service, domain string, providers []SiteProvider) func() map[Provider]oidcProvider {
	return func() map[Provider]oidcProvider {
		host, errE := getHost(config, domain)
		if errE != nil {
			panic(errE)
		}
		if host == "" {
			// Server failed to start. We just return in this case.
			return nil
		}

		oidcProviders := map[Provider]oidcProvider{}
		for _, p := range providers {
			config.Logger.Debug().Msgf("enabling %s provider", p.Name)

			path, errE := service.Reverse("AuthOIDCProvider", waf.Params{"provider": string(p.Key)}, nil)
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

type AuthFlowProviderStartRequest struct {
	Provider Provider `json:"provider"`
}

func (s *Service) AuthFlowProviderStartPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	flow := s.GetActiveFlowNoAuthStep(w, req, params["id"])
	if flow == nil {
		return
	}

	var providerStart AuthFlowProviderStartRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &providerStart)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	providerName := providerStart.Provider

	provider, ok := s.oidcProviders()[providerName]
	if providerName == "" || !ok {
		errE = errors.New("unknown provider")
		errors.Details(errE)["provider"] = providerName
		s.BadRequestWithError(w, req, errE)
		return
	}

	opts := []oauth2.AuthCodeOption{}

	flow.ClearAuthStep("")
	flow.Provider = providerName
	flow.OIDCProvider = &FlowOIDCProvider{
		Verifier: "",
		Nonce:    identifier.New().String(),
	}
	opts = append(opts, oidc.Nonce(flow.OIDCProvider.Nonce))

	if provider.SupportsPKCE {
		verifier := oauth2.GenerateVerifier()
		flow.OIDCProvider.Verifier = verifier
		opts = append(opts, oauth2.S256ChallengeOption(verifier))
	}

	errE = SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Target:          flow.Target,
		Name:            flow.TargetName,
		Homepage:        flow.GetTargetHomepage(),
		OrganizationID:  flow.GetTargetOrganization(),
		Provider:        flow.Provider,
		EmailOrUsername: flow.EmailOrUsername,
		Error:           "",
		Completed:       "",
		Location: &AuthFlowResponseLocation{
			URL:     provider.Config.AuthCodeURL(flow.ID.String(), opts...),
			Replace: false,
		},
		Passkey:  nil,
		Password: nil,
	}, nil)
}

func (s *Service) AuthOIDCProvider(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := req.Context()

	providerName := Provider(params["provider"])

	provider, ok := s.oidcProviders()[providerName]
	if providerName == "" || !ok {
		errE := errors.New("unknown provider")
		errors.Details(errE)["provider"] = providerName
		s.WithError(ctx, errE)
		s.NotFound(w, req)
		return
	}

	// State should be provided even in the case of an error.
	flow := s.GetActiveFlowNoAuthStep(w, req, req.Form.Get("state"))
	if flow == nil {
		return
	}

	if flow.OIDCProvider == nil {
		s.BadRequestWithError(w, req, errors.New("provider not started"))
		return
	}

	flowOIDC := *flow.OIDCProvider

	// We reset flow.OIDCProvider to nil always after this point, even if there is a failure,
	// so that nonce cannot be reused.
	flow.OIDCProvider = nil
	errE := SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	errorCode := req.Form.Get("error")
	errorDescription := req.Form.Get("error_description")
	if errorCode != "" || errorDescription != "" {
		errE = errors.New("authorization error")
		errors.Details(errE)["code"] = errorCode
		errors.Details(errE)["description"] = errorDescription
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

	if idToken.Nonce != flowOIDC.Nonce {
		s.BadRequestWithError(w, req, errors.New("nonce mismatch"))
		return
	}

	var jsonData json.RawMessage
	err = idToken.Claims(&jsonData)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	account, errE := GetAccountByCredential(ctx, providerName, idToken.Subject)
	if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.completeAuthStep(w, req, false, flow, account, []Credential{{ID: idToken.Subject, Provider: providerName, Data: jsonData}})
}
