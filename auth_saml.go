package charon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/rs/zerolog"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

const (
	// SAMLEntityIDPrefix = "PlastOsem_" // Prefix to be used in production.
	SAMLEntityIDPrefix = "mockSAML_" // Prefix to be used in development, delete before production.
	SAMLRequestTimeout = 30 * time.Second
)

type samlProvider struct {
	Name string
	SP   *saml2.SAMLServiceProvider
}

type AuthFlowResponseThirdPartyProvider struct {
	Location string `json:"location"`
}

func initSAMLProviders(config *Config, service *Service, domain string, providers []SiteProvider) (func() map[Provider]samlProvider, errors.E) {
	return initWithHost(config, domain, func(host string) map[Provider]samlProvider {
		samlProviders := map[Provider]samlProvider{}

		var samlProviderConfigs []SiteProvider

		for _, p := range providers {
			if p.Type == "saml" && p.metadataURL != "" {
				samlProviderConfigs = append(samlProviderConfigs, p)
			}
		}

		if len(samlProviderConfigs) == 0 {
			config.Logger.Debug().Msgf("SAML provider configs are empty")
			return samlProviders
		}

		client := &http.Client{ //nolint:exhaustruct
			Timeout:   SAMLRequestTimeout,
			Transport: cleanhttp.DefaultPooledTransport(),
		}

		for _, p := range samlProviderConfigs {
			config.Logger.Debug().Msgf("enabling SAML provider %s", p.Name)

			provider, errE := initSingleSAMLProvider(config, service, host, client, p)
			if errE != nil {
				config.Logger.Error().Err(errE).Msgf("failed to initialize SAML provider %s", p.Name)
				continue
			}

			samlProviders[p.Key] = *provider
		}

		return samlProviders
	})
}

func initSingleSAMLProvider(config *Config, service *Service, host string, client *http.Client, p SiteProvider) (*samlProvider, errors.E) {
	if err := validateSAMLProvider(p); err != nil {
		return nil, err
	}

	path, errE := service.ReverseAPI("AuthThirdPartyProvider", waf.Params{"provider": string(p.Key)}, nil)
	config.Logger.Info().Msgf("SAML callback URL for provider %s: https://%s%s", p.Name, host, path)
	if errE != nil {
		return nil, errE
	}

	metadata, errE := fetchSAMLMetadata(client, p.metadataURL)
	if errE != nil {
		return nil, errors.WithMessagef(errE, "failed to fetch metadata for provider %s", p.Name)
	}

	certStore, errE := extractIDPCertificates(metadata)
	if errE != nil {
		return nil, errors.WithMessagef(errE, "failed to extract certificates for provider %s", p.Name)
	}

	randomKeyStore, errE := loadOrCreateSPKeyStore(config, p.Key)
	if errE != nil {
		return nil, errors.WithMessagef(errE, "failed to load SP keys for provider %s", p.Name)
	}

	privateKey, cert, err := randomKeyStore.GetKeyPair()
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to get SP KeyPair for provider %s", p.Name)
	}

	// Second keystore for potentially signing AuthnRequests.
	randomSigninKeyStore, errE := loadOrCreateSPKeyStore(config, p.Key)
	if errE != nil {
		return nil, errors.WithMessagef(errE, "failed to load SP keys for provider %s", p.Name)
	}

	privateSigninKey, certSignin, err := randomSigninKeyStore.GetKeyPair()
	if err != nil {
		return nil, errors.WithMessagef(errE, "failed to get SP Signin-KeyPair for provider %s", p.Name)
	}

	// This prefers Redirect binding over POST.
	ssoURL := ""
	if metadata.IDPSSODescriptor != nil {
		for _, ssoService := range metadata.IDPSSODescriptor.SingleSignOnServices {
			if ssoService.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" {
				ssoURL = ssoService.Location
				break
			}
			if ssoService.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" && ssoURL == "" {
				ssoURL = ssoService.Location
			}
		}
	}

	if ssoURL == "" {
		return nil, errors.Errorf("SAML no supported SSO binding in metadata for provider %s", p.Name)
	}

	entityID := SAMLEntityIDPrefix + string(p.Key)
	sp := &saml2.SAMLServiceProvider{ //nolint:exhaustruct
		IdentityProviderSSOURL:      ssoURL,
		IdentityProviderIssuer:      metadata.EntityID,
		ServiceProviderIssuer:       entityID,
		AssertionConsumerServiceURL: fmt.Sprintf("https://%s%s", host, path),
		SignAuthnRequests:           true,
		AudienceURI:                 entityID,
		IDPCertificateStore:         certStore,

		IdentityProviderSSOBinding:     "",
		IdentityProviderSLOURL:         "",
		IdentityProviderSLOBinding:     "",
		ServiceProviderSLOURL:          "",
		SignAuthnRequestsAlgorithm:     "",
		SignAuthnRequestsCanonicalizer: nil,
		ForceAuthn:                     false,
		IsPassive:                      false,
		RequestedAuthnContext:          nil,
		NameIdFormat:                   "",
		ValidateEncryptionCert:         false,
		SkipSignatureValidation:        false,
		AllowMissingAttributes:         false,
		Clock:                          nil,
		MaximumDecompressedBodySize:    0,
	}

	// Avoid setting KeyStore directly as it is marked as deprecated. Instead, use SetSPKeyStore and
	// SetSPSigningKeyStore, so that we can have different keys for signing and encryption in production.
	errKeyStore := sp.SetSPKeyStore(&saml2.KeyStore{
		Signer: privateKey,
		Cert:   cert,
	})
	if errKeyStore != nil {
		return nil, errors.WithMessage(errKeyStore, "failed to set SP keystore")
	}
	errKeySigninStore := sp.SetSPSigningKeyStore(&saml2.KeyStore{
		Signer: privateSigninKey,
		Cert:   certSignin,
	})
	if errKeySigninStore != nil {
		return nil, errors.WithMessage(errKeySigninStore, "failed to set SP keystore")
	}

	config.Logger.Info().
		Str("provider", p.Name).
		Str("entityID", entityID).
		Str("ssoURL", sp.IdentityProviderSSOURL).
		Str("AssertionConsumerServiceURL", sp.AssertionConsumerServiceURL).
		Msg("SAML provider initialized successfully")

	return &samlProvider{
		Name: p.Name,
		SP:   sp,
	}, nil
}

func validateSAMLProvider(p SiteProvider) errors.E {
	if p.Key == "" || p.Name == "" || p.metadataURL == "" {
		errE := errors.New("provider key, name, and metadata URL cannot be empty")
		errors.Details(errE)["name"] = p.Name
		errors.Details(errE)["expected"] = p.metadataURL
		return errE
	}
	return nil
}

func fetchSAMLMetadata(client *http.Client, metadataURL string) (*types.EntityDescriptor, errors.E) {
	ctx, cancel := context.WithTimeout(context.Background(), SAMLRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req.Header.Set("User-Agent", "Charon-SAML/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("metadata request failed with status %d", resp.StatusCode)
	}

	rawMetadata, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	metadata := &types.EntityDescriptor{} //nolint:exhaustruct
	err = xml.Unmarshal(rawMetadata, metadata)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return metadata, nil
}

func extractIDPCertificates(metadata *types.EntityDescriptor) (*dsig.MemoryX509CertificateStore, errors.E) {
	certStore := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{}}

	if metadata.IDPSSODescriptor == nil {
		return nil, errors.New("metadata missing IDPSSODescriptor")
	}

	certificateCount := 0
	for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		if len(kd.KeyInfo.X509Data.X509Certificates) == 0 {
			continue
		}

		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				return nil, errors.Errorf("metadata certificate(%d) must not be empty", idx)
			}

			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				return nil, errors.WithMessagef(err, "failed to decode certificate %d", idx)
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				return nil, errors.WithMessagef(err, "failed to parse certificate %d", idx)
			}

			certStore.Roots = append(certStore.Roots, idpCert)
			certificateCount++
		}
	}

	if certificateCount == 0 {
		return nil, errors.New("no valid certificates found in metadata")
	}

	return certStore, nil
}

func loadOrCreateSPKeyStore(config *Config, providerKey Provider) (dsig.X509KeyStore, errors.E) { //nolint:ireturn
	if config.Server.Development {
		// In development, use random keys (not persistent).
		config.Logger.Warn().Msg("using random SAML keys in development mode")
		return dsig.RandomKeyStoreForTest(), nil
	}

	// In production, use persistent keys.
	keysDir := filepath.Join("saml-keys", string(providerKey))
	keyPath := filepath.Join(keysDir, "sp-key.pem")
	certPath := filepath.Join(keysDir, "sp-cert.pem")

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		config.Logger.Info().Str("provider", string(providerKey)).Msg("generating new SAML SP keys")

		const dirPermissions = 0o700
		if err := os.MkdirAll(keysDir, dirPermissions); err != nil {
			return nil, errors.WithStack(err)
		}

		keyStore := dsig.RandomKeyStoreForTest()

		// TODO: Currently saves keys to disk (we want proper key generation).
		config.Logger.Warn().Msg("SAML key persistence not fully implemented - keys will be regenerated on restart")
		return keyStore, nil
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	keyStore := dsig.TLSCertKeyStore(cert)
	return keyStore, nil
}

func validateSAMLAssertion(assertionInfo *saml2.AssertionInfo) errors.E {
	if assertionInfo == nil {
		return errors.New("assertion info is nil")
	}

	if assertionInfo.WarningInfo.InvalidTime {
		return errors.New("SAML assertion has invalid time")
	}

	if assertionInfo.WarningInfo.NotInAudience {
		return errors.New("SAML assertion audience mismatch")
	}

	if assertionInfo.NameID == "" {
		return errors.New("SAML assertion missing NameID")
	}

	return nil
}

func (s *Service) handleSAMLProviderStart(ctx context.Context, w http.ResponseWriter, req *http.Request, flow *Flow, providerName Provider, provider samlProvider) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msgf("Starting SAML auth for flow ID: %s", flow.ID.String())

	flow.ClearAuthStep("")
	flow.Providers = []Provider{providerName}

	flow.SAMLProvider = &FlowSAMLProvider{
		ID: identifier.New(),
	}

	errE := s.setFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	authURL, err := provider.SP.BuildAuthURL(flow.ID.String())
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	logger.Info().Msgf("Generated SAML auth URL with flow ID as RelayState: %s", authURL)

	s.WriteJSON(w, req, AuthFlowResponse{
		Completed:       flow.Completed,
		OrganizationID:  flow.OrganizationID,
		AppID:           flow.AppID,
		Providers:       flow.Providers,
		EmailOrUsername: flow.EmailOrUsername,
		ThirdPartyProvider: &AuthFlowResponseThirdPartyProvider{
			Location: authURL,
		},
		Passkey:  nil,
		Password: nil,
		Error:    "",
	}, nil)
}

func (s *Service) handleSAMLCallback(w http.ResponseWriter, req *http.Request, providerName Provider, provider samlProvider) {
	ctx := req.Context()

	err := req.ParseForm()
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	relayState := req.FormValue("RelayState")

	logger := zerolog.Ctx(ctx)
	logger.Info().Msgf("SAML callback RelayState: '%s'", relayState)
	logger.Info().Msgf("SAML callback SAMLResponse present: %t", req.FormValue("SAMLResponse") != "")

	if relayState == "" {
		s.BadRequestWithError(w, req, errors.New("missing RelayState parameter"))
		return
	}

	flow := s.GetActiveFlowNoAuthStep(w, req, relayState)
	if flow == nil {
		return
	}

	if flow.SAMLProvider == nil {
		s.BadRequestWithError(w, req, errors.New("SAML provider not started"))
		return
	}

	// We reset flow.SAMLProvider to nil always after this point, even if there is a failure.
	flow.SAMLProvider = nil
	errE := s.setFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	samlResponse := req.FormValue("SAMLResponse")
	if samlResponse == "" {
		if errorCode := req.FormValue("error"); errorCode != "" {
			authErr := errors.New("SAML authentication error")
			errors.Details(authErr)["error"] = errorCode
			errors.Details(authErr)["description"] = req.FormValue("error_description")
			errors.Details(authErr)["provider"] = providerName
			s.failAuthStep(w, req, false, flow, authErr)
			return
		}

		s.failAuthStep(w, req, false, flow, errors.New("missing SAMLResponse parameter"))
		return
	}

	assertionInfo, err := provider.SP.RetrieveAssertionInfo(samlResponse)
	if err != nil {
		errE = errors.WithStack(err)
		errors.Details(errE)["provider"] = providerName
		s.failAuthStep(w, req, false, flow, errE)
		return
	}

	if validateErr := validateSAMLAssertion(assertionInfo); validateErr != nil {
		errors.Details(validateErr)["provider"] = providerName
		s.failAuthStep(w, req, false, flow, validateErr)
		return
	}

	if assertionInfo != nil {
		logger := zerolog.Ctx(ctx)
		logger.Debug().Str("provider", string(providerName)).Msg("SAML assertion info")
		logger.Debug().Str(assertionInfo.NameID, "nameID").Msg("SAML assertion NameID")
		if assertionInfo.ResponseSignatureValidated {
			logger.Debug().Str("SAML signature validation", string(providerName)).Msg("SAML assertion response signature validated")
		} else {
			logger.Debug().Str("SAML signature valdiation", string(providerName)).Msg("SAML NOT VALID signature")
		}
	}

	account, errE := s.getAccountByCredential(ctx, providerName, assertionInfo.NameID)
	if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		errors.Details(errE)["provider"] = providerName
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	attributes := extractSAMLAttributes(assertionInfo, providerName)
	credentialData, err := json.Marshal(attributes)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	s.completeAuthStep(w, req, false, flow, account, []Credential{{
		ID:       assertionInfo.NameID,
		Provider: providerName,
		Data:     credentialData,
	}})
}

func extractSAMLAttributes(assertionInfo *saml2.AssertionInfo, providerName Provider) map[string]interface{} {
	attributes := map[string]interface{}{
		"sub":      assertionInfo.NameID,
		"nameId":   assertionInfo.NameID,
		"provider": string(providerName),
	}

	rawAttrs := make(map[string]interface{})
	for key, attr := range assertionInfo.Values {
		var vals []string
		for _, v := range attr.Values {
			if strings.TrimSpace(v.Value) != "" {
				vals = append(vals, strings.TrimSpace(v.Value))
			}
		}
		rawAttrs[key] = map[string]interface{}{
			"Name":         attr.Name,
			"FriendlyName": attr.FriendlyName,
			"NameFormat":   attr.NameFormat,
			"Values":       vals,
		}
	}
	attributes["raw_attributes"] = rawAttrs

	return attributes
}
