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

	"github.com/hashicorp/go-cleanhttp"
	"github.com/rs/zerolog"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/waf"
)

const (
	samlSIPASSEntityIDPrefix = "PlastOsem_"                                              //nolint:gosec
	samlEntityIDPrefix       = "mockSAML_"                                               //nolint:gosec
	sipassDefaultMetadataURL = "https://sicas.gov.si/static/idp-metadata.xml"            //nolint:gosec
	mockSAMLMetadataURL      = "https://mocksaml.com/api/namespace/charon/saml/metadata" //nolint:gosec
	mockSAMLEntityID         = "mockSAML_charon_dev"
)

type samlProvider struct {
	Name     string
	Provider *saml2.SAMLServiceProvider
	Resolver SAMLCredentialResolver
}

func initSAMLProviders(config *Config, service *Service, domain string, providers []SiteProvider) (func() map[Provider]samlProvider, errors.E) {
	return initWithHost(config, domain, func(host string) map[Provider]samlProvider {
		samlProviders := map[Provider]samlProvider{}
		for _, p := range providers {
			if p.Type != ThirdPartyProviderSAML || p.samlMetadataURL == "" {
				continue
			}

			client := cleanhttp.DefaultPooledClient()
			provider, errE := initSingleSAMLProvider(config, service, host, client, p)
			if errE != nil {
				errors.Details(errE)["name"] = p.Name
				panic(errE)
			}

			samlProviders[p.Key] = provider
		}

		return samlProviders
	})
}

func initSingleSAMLProvider(config *Config, service *Service, host string, client *http.Client, p SiteProvider) (samlProvider, errors.E) {
	config.Logger.Debug().Msgf("enabling SAML provider %s", p.Name)

	path, errE := service.ReverseAPI("AuthThirdPartyProvider", waf.Params{"provider": string(p.Key)}, nil)
	if errE != nil {
		return samlProvider{}, errE
	}

	metadata, errE := fetchSAMLMetadata(context.Background(), client, p.samlMetadataURL)
	if errE != nil {
		return samlProvider{}, errors.WithMessage(errE, "failed to fetch metadata")
	}

	certStore, errE := extractIDPCertificates(metadata)
	if errE != nil {
		return samlProvider{}, errors.WithMessagef(errE, "failed to extract certificates for provider %s", p.Name)
	}

	_, errE = p.loadOrCreateSPKeyStore(config)
	if errE != nil {
		return samlProvider{}, errors.WithMessagef(errE, "failed to load SP keys for provider %s", p.Name)
	}

	privateKey, cert, err := p.samlKeyStore.GetKeyPair()
	if err != nil {
		return samlProvider{}, errors.WithMessagef(err, "failed to get SP KeyPair for provider %s", p.Name)
	}

	ssoURL := ""
	if metadata.IDPSSODescriptor != nil {
		for _, ssoService := range metadata.IDPSSODescriptor.SingleSignOnServices {
			if ssoService.Binding == saml2.BindingHttpRedirect {
				ssoURL = ssoService.Location
				break
			}
		}
	}

	if ssoURL == "" {
		return samlProvider{}, errors.New("HTTP-Redirect binding not supported")
	}

	entityID := p.samlEntityID
	if entityID == "" {
		if p.Key == "sipass" {
			entityID = samlSIPASSEntityIDPrefix + string(p.Key)
		} else {
			entityID = samlEntityIDPrefix + string(p.Key)
		}
	}

	sp := &saml2.SAMLServiceProvider{ //nolint:exhaustruct
		IdentityProviderSSOURL:      ssoURL,
		IdentityProviderSSOBinding:  saml2.BindingHttpRedirect,
		IdentityProviderIssuer:      metadata.EntityID,
		ServiceProviderIssuer:       entityID,
		AssertionConsumerServiceURL: fmt.Sprintf("https://%s%s", host, path),
		SignAuthnRequests:           true,
		AudienceURI:                 entityID,
		IDPCertificateStore:         certStore,
	}

	errKeyStore := sp.SetSPKeyStore(&saml2.KeyStore{
		Signer: privateKey,
		Cert:   cert,
	})
	if errKeyStore != nil {
		return samlProvider{}, errors.WithMessage(errKeyStore, "failed to set SP keystore")
	}

	resolver := CreateSAMLResolver(p)

	return samlProvider{
		Name:     p.Name,
		Provider: sp,
		Resolver: resolver,
	}, nil
}

func fetchSAMLMetadata(ctx context.Context, client *http.Client, metadataURL string) (types.EntityDescriptor, errors.E) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		errE := errors.WithStack(err)
		errors.Details(errE)["metadataURL"] = metadataURL
		return types.EntityDescriptor{}, errE
	}

	resp, err := client.Do(req)
	if err != nil {
		errE := errors.WithStack(err)
		errors.Details(errE)["metadataURL"] = metadataURL
		return types.EntityDescriptor{}, errE
	}
	defer resp.Body.Close()
	defer io.Copy(io.Discard, resp.Body) //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		errE := errors.New("bad response status")
		errors.Details(errE)["url"] = resp.Request.URL.String()
		errors.Details(errE)["code"] = resp.StatusCode
		errors.Details(errE)["body"] = strings.TrimSpace(string(body))
		return types.EntityDescriptor{}, errE
	}

	rawMetadata, err := io.ReadAll(resp.Body)
	if err != nil {
		errE := errors.WithStack(err)
		errors.Details(errE)["metadataURL"] = metadataURL
		errors.Details(errE)["statusCode"] = resp.StatusCode
		return types.EntityDescriptor{}, errE
	}

	var metadata types.EntityDescriptor
	err = xml.Unmarshal(rawMetadata, &metadata)
	if err != nil {
		errE := errors.WithDetails(err, "saml-metadata", string(rawMetadata))
		errors.Details(errE)["metadataURL"] = metadataURL
		return types.EntityDescriptor{}, errE
	}

	return metadata, nil
}

func extractIDPCertificates(metadata types.EntityDescriptor) (*dsig.MemoryX509CertificateStore, errors.E) {
	certStore := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{}}

	if metadata.IDPSSODescriptor == nil {
		errE := errors.WithStack(errors.New("metadata missing IDPSSODescriptor"))
		errors.Details(errE)["entityID"] = metadata.EntityID
		return nil, errE
	}

	for kdIdx, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		if len(kd.KeyInfo.X509Data.X509Certificates) == 0 {
			errE := errors.New("KeyDescriptor missing X509Certificate")
			errors.Details(errE)["entityID"] = metadata.EntityID
			errors.Details(errE)["keyDescriptorIndex"] = kdIdx
			return nil, errE
		}
		for certIdx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if strings.TrimSpace(xcert.Data) == "" {
				errE := errors.New("metadata certificate must not be empty")
				errors.Details(errE)["entityID"] = metadata.EntityID
				errors.Details(errE)["keyDescriptorIndex"] = kdIdx
				errors.Details(errE)["certificateIndex"] = certIdx
				return nil, errE
			}

			certStr := strings.TrimSpace(xcert.Data)
			certStr = strings.ReplaceAll(certStr, "\n", "")
			certStr = strings.ReplaceAll(certStr, "\r", "")
			certStr = strings.ReplaceAll(certStr, " ", "")

			certData, err := base64.StdEncoding.DecodeString(certStr)
			if err != nil {
				errE := errors.New("failed to decode certificate")
				errors.Details(errE)["entityID"] = metadata.EntityID
				errors.Details(errE)["keyDescriptorIndex"] = kdIdx
				errors.Details(errE)["certificateIndex"] = certIdx
				return nil, errE
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				errE := errors.New("failed to parse certificate")
				errors.Details(errE)["entityID"] = metadata.EntityID
				errors.Details(errE)["keyDescriptorIndex"] = kdIdx
				errors.Details(errE)["certificateIndex"] = certIdx
				return nil, errE
			}

			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}

	if len(certStore.Roots) == 0 {
		errE := errors.New("no valid certificates found in metadata")
		errors.Details(errE)["entityID"] = metadata.EntityID
		return nil, errE
	}

	return certStore, nil
}

func (p *SiteProvider) loadOrCreateSPKeyStore(config *Config) (dsig.X509KeyStore, errors.E) { //nolint:ireturn
	if config.Server.Development {
		// In development, use random keys (not persistent).
		config.Logger.Warn().Msg("using random SAML keys in development mode")
		p.samlKeyStore = dsig.RandomKeyStoreForTest()
		return p.samlKeyStore, nil
	}

	// In production, use persistent keys.
	keysDir := filepath.Join("saml-keys", string(p.Key))
	keyPath := filepath.Join(keysDir, "sp-key.pem")
	certPath := filepath.Join(keysDir, "sp-cert.pem")

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		const dirPermissions = 0o700
		if err := os.MkdirAll(keysDir, dirPermissions); err != nil {
			return nil, errors.WithStack(err)
		}

		keyStore := dsig.RandomKeyStoreForTest()
		p.samlKeyStore = keyStore

		// TODO: Currently saves keys to disk (we want proper key generation).
		return keyStore, nil
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	keyStore := dsig.TLSCertKeyStore(cert)
	p.samlKeyStore = keyStore
	return keyStore, nil
}

func validateSAMLAssertion(assertionInfo *saml2.AssertionInfo) errors.E {
	if assertionInfo == nil {
		return errors.New("SAML assertion info is nil")
	}

	if !assertionInfo.ResponseSignatureValidated {
		return errors.New("SAML assertion response signature not validated")
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
	flow.ClearAuthStep("")
	// Currently we support only one factor.
	flow.Providers = []Provider{providerName}
	flow.SAMLProvider = &FlowSAMLProvider{}

	errE := s.setFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	authURL, err := provider.Provider.BuildAuthURL(flow.ID.String())
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

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
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	err := req.ParseForm()
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	flow := s.GetActiveFlowNoAuthStep(w, req, req.Form.Get("RelayState"))
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

	errorCode := req.Form.Get("error")
	errorDescription := req.Form.Get("error_description")
	if errorCode != "" || errorDescription != "" {
		errE = errors.New("SAML authentication error")
		errors.Details(errE)["code"] = errorCode
		errors.Details(errE)["description"] = errorDescription
		errors.Details(errE)["provider"] = providerName
		s.failAuthStep(w, req, false, flow, errE)
		return
	}

	// TODO: Parsing types.Response Status, easier debugging, SAML2.0 includes many statuses like 'AuthnFailed'.
	// We could use their ValidateEncodeResponse and parse which status was returned into our error.
	// If gosaml2 merges our PR, we can add that logging.
	samlResponse := req.Form.Get("SAMLResponse")
	assertionInfo, err := provider.Provider.RetrieveAssertionInfo(samlResponse)
	if err != nil {
		errE = errors.WithStack(err)
		errors.Details(errE)["provider"] = providerName
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = validateSAMLAssertion(assertionInfo)
	if errE != nil {
		errors.Details(errE)["provider"] = providerName
		s.BadRequestWithError(w, req, errE)
		return
	}

	credentialID, errE := provider.Resolver.ResolveCredentialID(assertionInfo)
	if errE != nil {
		errors.Details(errE)["provider"] = providerName
		s.BadRequestWithError(w, req, errE)
		return
	}

	account, errE := s.getAccountByCredential(ctx, providerName, credentialID)
	if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		errors.Details(errE)["provider"] = providerName
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	attributes := extractSAMLAttributes(assertionInfo, provider.Resolver)
	jsonData, err := json.Marshal(attributes)
	if err != nil {
		errors.Details(errE)["provider"] = providerName
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	zerolog.Ctx(ctx).Warn().
		Str("provider", string(providerName)).
		Str("credentialID", credentialID).
		Str("nameID", assertionInfo.NameID).
		Interface("attributes", attributes).
		Msg("SAML ATTRIBUTES RECEIVED - This is what will be stored in the database")

	s.completeAuthStep(w, req, false, flow, account, []Credential{{
		ID:       assertionInfo.NameID,
		Provider: providerName,
		Data:     jsonData,
	}})
}

func extractSAMLAttributes(assertionInfo *saml2.AssertionInfo, resolver SAMLCredentialResolver) map[string]interface{} {
	attributes := map[string]interface{}{}

	mapping := resolver.GetAttributeMapping()

	for samlAttr, standardClaim := range mapping.Mappings {
		if attr, exists := assertionInfo.Values[samlAttr]; exists {
			var values []string
			for _, v := range attr.Values {
				value := strings.TrimSpace(v.Value)
				if value != "" {
					values = append(values, value)
				}
			}
			if len(values) > 0 {
				attributes[standardClaim] = values
			}
		}
	}

	for key, attr := range assertionInfo.Values {
		if _, isMapped := mapping.Mappings[key]; isMapped {
			continue
		}
		attrName := key
		if attr.FriendlyName != "" {
			attrName = attr.FriendlyName
		}
		var values []string
		for _, v := range attr.Values {
			value := strings.TrimSpace(v.Value)
			if value != "" {
				values = append(values, value)
			}
		}
		if len(values) > 0 {
			attributes[attrName] = values
		}
	}

	return attributes
}
