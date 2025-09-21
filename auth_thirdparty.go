package charon

import (
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
	s.handleAuthThirdPartyProvider(w, req, params)
}

func (s *Service) AuthThirdPartyProviderPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	s.handleAuthThirdPartyProvider(w, req, params)
}

func (s *Service) handleAuthThirdPartyProvider(w http.ResponseWriter, req *http.Request, params waf.Params) {
	providerName := Provider(params["provider"])

	if p, ok := s.oidcProviders()[providerName]; providerName != "" && ok {
		s.handleOIDCCallback(w, req, providerName, p)
		return
	}

	if p, ok := s.samlProviders()[providerName]; providerName != "" && ok {
		s.handleSAMLCallback(w, req, providerName, p)
		return
	}

	errE := errors.New("unknown provider")
	errors.Details(errE)["provider"] = providerName
	s.NotFoundWithError(w, req, errE)
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

	providerName := providerStart.Provider

	if p, ok := s.oidcProviders()[providerName]; providerName != "" && ok {
		s.handleOIDCProviderStart(ctx, w, req, flow, providerName, p)
		return
	}

	if p, ok := s.samlProviders()[providerName]; providerName != "" && ok {
		s.handleSAMLProviderStart(ctx, w, req, flow, providerName, p)
		return
	}

	errE = errors.New("unknown provider")
	errors.Details(errE)["provider"] = providerName
	s.BadRequestWithError(w, req, errE)
}
