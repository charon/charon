package charon

import (
	"io"
	"net/http"

	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/waf"
)

type AuthFlowProviderStartRequest struct {
	Provider Provider `json:"provider"`
}

func (s *Service) AuthThirdPartyProvider(w http.ResponseWriter, req *http.Request, params waf.Params) {
	providerName := Provider(params["provider"])

	ctx := req.Context()
	logger := zerolog.Ctx(ctx)
	logger.Info().Msgf("AuthThirdPartyProvider called with method: %s, provider: %s", req.Method, params["provider"])

	if oidcProv, ok := s.oidcProviders()[providerName]; ok {
		s.handleOIDCCallback(w, req, providerName, oidcProv)
		return
	}

	if samlProv, ok := s.samlProviders()[providerName]; ok {
		if req.Method != http.MethodPost {
			allowed := []string{"POST"}
			s.MethodNotAllowed(w, req, allowed)
			return
		}
		s.handleSAMLCallback(w, req, providerName, samlProv)
		return
	}

	errE := errors.New("unknown provider")
	errors.Details(errE)["provider"] = providerName
	s.NotFoundWithError(w, req, errE)
}

func (s *Service) AuthThirdPartyProviderPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	s.AuthThirdPartyProvider(w, req, params)
}

func (s *Service) AuthFlowProviderStartPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	logger := zerolog.Ctx(ctx)
	logger.Info().Msgf("available SAML providers: %+v", s.samlProviders())

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

	logger.Info().Msgf("requested provider: %s", providerName)

	if oidcProv, ok := s.oidcProviders()[providerName]; ok {
		s.handleOIDCProviderStart(ctx, w, req, flow, providerName, oidcProv)
		return
	}

	if samlProv, ok := s.samlProviders()[providerName]; ok {
		s.handleSAMLProviderStart(ctx, w, req, flow, providerName, samlProv)
		return
	}

	errE = errors.New("unknown provider")
	errors.Details(errE)["provider"] = providerName
	s.BadRequestWithError(w, req, errE)
}
