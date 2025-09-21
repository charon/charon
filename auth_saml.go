package charon

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
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
	DefaultSIPASSMetadataURL = "https://sicas.gov.si/static/idp-metadata.xml" //nolint:gosec

	mockSAMLMetadataURL = "https://mocksaml.com/api/namespace/charon/saml/metadata"
	mockSAMLEntityID    = "mockSAML_charon"
)

type samlProvider struct {
	Name     string
	Provider *saml2.SAMLServiceProvider
	Mapping  SAMLAttributeMapping
}

func initSAMLProviders(config *Config, service *Service, domain string, providers []SiteProvider) (func() map[Provider]samlProvider, errors.E) {
	return initWithHost(config, domain, func(host string) map[Provider]samlProvider {
		samlProviders := map[Provider]samlProvider{}
		for _, p := range providers {
			if p.Type != ThirdPartyProviderSAML {
				continue
			}

			provider, errE := initSAMLProvider(config, service, host, p)
			if errE != nil {
				errors.Details(errE)["name"] = p.Name
				panic(errE)
			}

			samlProviders[p.Key] = provider
		}

		return samlProviders
	})
}

func initSAMLProvider(config *Config, service *Service, host string, p SiteProvider) (samlProvider, errors.E) {
	config.Logger.Debug().Msgf("enabling %s SAML provider", p.Name)

	path, errE := service.ReverseAPI("AuthThirdPartyProvider", waf.Params{"provider": string(p.Key)}, nil)
	if errE != nil {
		return samlProvider{}, errE
	}

	client := cleanhttp.DefaultPooledClient()
	metadata, errE := fetchSAMLMetadata(context.Background(), client, p.samlMetadataURL)
	if errE != nil {
		return samlProvider{}, errors.WithMessage(errE, "failed to fetch metadata")
	}

	certStore, errE := extractIDPCertificates(metadata)
	if errE != nil {
		return samlProvider{}, errors.WithMessage(errE, "failed to extract IDP certificates")
	}

	privateKey, cert, err := p.samlKeyStore.GetKeyPair()
	if err != nil {
		return samlProvider{}, errors.WithMessage(err, "failed to get SP key-pair")
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
		return samlProvider{}, errors.New("IDP does not support HTTP-Redirect binding")
	}

	sp := &saml2.SAMLServiceProvider{ //nolint:exhaustruct
		IdentityProviderSSOURL:      ssoURL,
		IdentityProviderSSOBinding:  saml2.BindingHttpRedirect,
		IdentityProviderIssuer:      metadata.EntityID,
		ServiceProviderIssuer:       p.samlEntityID,
		AssertionConsumerServiceURL: fmt.Sprintf("https://%s%s", host, path),
		SignAuthnRequests:           true,
		AudienceURI:                 p.samlEntityID,
		IDPCertificateStore:         certStore,
	}

	errKeyStore := sp.SetSPKeyStore(&saml2.KeyStore{
		Signer: privateKey,
		Cert:   cert,
	})
	if errKeyStore != nil {
		return samlProvider{}, errors.WithMessage(errKeyStore, "failed to set SP keystore")
	}

	return samlProvider{
		Name:     p.Name,
		Provider: sp,
		Mapping:  p.samlAttributeMapping,
	}, nil
}

func fetchSAMLMetadata(ctx context.Context, client *http.Client, metadataURL string) (types.EntityDescriptor, errors.E) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		errE := errors.WithStack(err)
		errors.Details(errE)["url"] = metadataURL
		return types.EntityDescriptor{}, errE
	}
	resp, err := client.Do(req)
	if err != nil {
		errE := errors.WithStack(err)
		errors.Details(errE)["url"] = metadataURL
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
		errors.Details(errE)["url"] = metadataURL
		return types.EntityDescriptor{}, errE
	}

	var metadata types.EntityDescriptor
	err = xml.Unmarshal(rawMetadata, &metadata)
	if err != nil {
		errE := errors.WithStack(err)
		errors.Details(errE)["url"] = metadataURL
		errors.Details(errE)["metadata"] = string(rawMetadata)
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

func (p *SiteProvider) initSAMLKeyStore() errors.E {
	// TODO: Properly load keys from the disk based on configuration for this provider.
	//       Only if the keys are not available, and we are in development mode, generate them.
	p.samlKeyStore = dsig.RandomKeyStoreForTest()
	return nil
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

	attributes, errE := getSAMLAttributes(assertionInfo, provider.Mapping)
	if errE != nil {
		errors.Details(errE)["provider"] = providerName
		s.BadRequestWithError(w, req, errE)
		return
	}

	credentialID, errE := getSAMLCredentialID(assertionInfo, attributes, provider.Mapping.CredentialIDAttributes)
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
