package charon

import (
	"context"
	"io"
	"net/http"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/waf"
)

type AuthFlowThirdPartyProviderStartRequest struct {
	Provider Provider `json:"provider"`
}

type AuthFlowResponseThirdPartyProvider struct {
	Location string `json:"location"`
}

func (s *Service) AuthThirdPartyProvider(w http.ResponseWriter, req *http.Request, params waf.Params) {
	providerKey := Provider(params["provider"])

	// Only OIDC providers use GET requests for callbacks (response type is code which has response mode query).
	if p, ok := s.oidcProviders()[providerKey]; providerKey != "" && ok {
		s.handleOIDCCallback(w, req, providerKey, p)
		return
	}

	errE := errors.New("unknown provider")
	errors.Details(errE)["provider"] = providerKey
	s.NotFoundWithError(w, req, errE)
}

func (s *Service) AuthThirdPartyProviderPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	providerKey := Provider(params["provider"])

	// Only SAML providers use POST requests for callbacks (HTTP-POST binding).
	if p, ok := s.samlProviders()[providerKey]; providerKey != "" && ok {
		s.handleSAMLCallback(w, req, providerKey, p)
		return
	}

	errE := errors.New("unknown provider")
	errors.Details(errE)["provider"] = providerKey
	s.NotFoundWithError(w, req, errE)
}

func (s *Service) handleAuthFlowThirdPartyProviderStart(
	ctx context.Context, w http.ResponseWriter, req *http.Request, flow *Flow,
	providerName Provider, handler func(flow *Flow) (string, errors.E),
) {
	flow.ClearAuthStep("")
	// Currently we support only one factor.
	flow.Providers = []Provider{providerName}

	location, errE := handler(flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	errE = s.setFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Completed:       flow.Completed,
		OrganizationID:  flow.OrganizationID,
		AppID:           flow.AppID,
		Providers:       flow.Providers,
		EmailOrUsername: flow.EmailOrUsername,
		ThirdPartyProvider: &AuthFlowResponseThirdPartyProvider{
			Location: location,
		},
		Passkey:  nil,
		Password: nil,
		Error:    "",
	}, nil)
}

func (s *Service) AuthFlowThirdPartyProviderStartPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	flow := s.GetActiveFlowNoAuthStep(w, req, params["id"])
	if flow == nil {
		return
	}

	var providerStart AuthFlowThirdPartyProviderStartRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &providerStart)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	providerKey := providerStart.Provider

	if p, ok := s.oidcProviders()[providerKey]; providerKey != "" && ok {
		s.handleAuthFlowThirdPartyProviderStart(ctx, w, req, flow, providerKey, s.handlerOIDCStart(p))
		return
	}

	if p, ok := s.samlProviders()[providerKey]; providerKey != "" && ok {
		s.handleAuthFlowThirdPartyProviderStart(ctx, w, req, flow, providerKey, s.handlerSAMLStart(p))
		return
	}

	errE = errors.New("unknown provider")
	errors.Details(errE)["provider"] = providerKey
	s.BadRequestWithError(w, req, errE)
}
