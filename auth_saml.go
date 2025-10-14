package charon

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/hashicorp/go-cleanhttp"
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
	Key      Provider
	Name     string
	Provider *saml2.SAMLServiceProvider
	Mapping  SAMLAttributeMapping
}

type samlMemoryKeyStore struct {
	privateKey *rsa.PrivateKey
	cert       []byte
}

func (ks samlMemoryKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.privateKey, ks.cert, nil
}

func initSAMLProviders(config *Config, service *Service, domain string, providers []SiteProvider) (func() map[Provider]samlProvider, errors.E) {
	return initWithHost(config, domain, func(host string) map[Provider]samlProvider {
		samlProviders := map[Provider]samlProvider{}
		for _, p := range providers {
			if p.Type != ThirdPartyProviderSAML {
				continue
			}

			provider, errE := initSAMLProvider(service, host, p)
			if errE != nil {
				errors.Details(errE)["provider"] = p.Key
				// Internal error: this should never happen.
				panic(errE)
			}

			samlProviders[p.Key] = provider
		}

		return samlProviders
	})
}

func initSAMLProvider(service *Service, host string, p SiteProvider) (samlProvider, errors.E) {
	path, errE := service.ReverseAPI("AuthThirdPartyProvider", waf.Params{"provider": string(p.Key)}, nil)
	if errE != nil {
		return samlProvider{}, errE
	}

	privateKey, cert, err := p.samlKeyStore.GetKeyPair()
	if err != nil {
		return samlProvider{}, errors.WithMessage(err, "failed to get SP key-pair")
	}

	sp := &saml2.SAMLServiceProvider{ //nolint:exhaustruct
		IdentityProviderSSOURL:      p.samlSSOURL,
		IdentityProviderSSOBinding:  saml2.BindingHttpRedirect,
		IdentityProviderIssuer:      p.samlIDPIssuer,
		ServiceProviderIssuer:       p.samlEntityID,
		AssertionConsumerServiceURL: fmt.Sprintf("https://%s%s", host, path),
		SignAuthnRequests:           true,
		AudienceURI:                 p.samlEntityID,
		IDPCertificateStore:         p.samlIDPCertificateStore,
		// It looks like this canonicalizer is supported more than others (Shibboleth supports only this one).
		// So we use it as default. We can see if we have to make it configurable in the future.
		SignAuthnRequestsCanonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
		// TODO: Remove redundant SPKeyStore/SPSigningKeyStore once SAMLServiceProvider.Metadata stops using deprecated GetSigningKey.
		//       It does not work correctly if only SetSPKeyStore is used.
		//       See: https://github.com/russellhaering/gosaml2/issues/250
		//       See: https://github.com/russellhaering/gosaml2/pull/251
		SPKeyStore:        p.samlKeyStore,
		SPSigningKeyStore: p.samlKeyStore,
	}

	err = sp.SetSPKeyStore(&saml2.KeyStore{
		Signer: privateKey,
		Cert:   cert,
	})
	if err != nil {
		return samlProvider{}, withGosamlError(err)
	}
	err = sp.SetSPSigningKeyStore(&saml2.KeyStore{
		Signer: privateKey,
		Cert:   cert,
	})
	if err != nil {
		return samlProvider{}, withGosamlError(err)
	}

	return samlProvider{
		Key:      p.Key,
		Name:     p.Name,
		Provider: sp,
		Mapping:  p.samlAttributeMapping,
	}, nil
}

func (p *SiteProvider) initSAMLProvider(config *Config) errors.E {
	config.Logger.Debug().Msgf("enabling %s SAML provider", p.Key)

	client := cleanhttp.DefaultPooledClient()
	metadata, errE := fetchSAMLMetadata(context.Background(), client, p.samlMetadataURL)
	if errE != nil {
		return errors.WithMessage(errE, "failed to fetch metadata")
	}

	certStore, errE := extractIDPCertificates(metadata)
	if errE != nil {
		return errors.WithMessage(errE, "failed to extract IDP certificates")
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
		return errors.New("IDP does not support HTTP-Redirect binding")
	}

	p.samlSSOURL = ssoURL
	p.samlIDPIssuer = metadata.EntityID
	p.samlIDPCertificateStore = certStore

	return nil
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

func initSAMLKeyStore(config *Config, samlKey []byte) (dsig.X509KeyStore, errors.E) {
	if len(samlKey) > 0 {
		jwk, errE := MakeRSAKey(samlKey)
		if errE != nil {
			return nil, errors.WithMessage(errE, "invalid RSA private key")
		}

		rsaKey, ok := jwk.Key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		cert, err := x509.MarshalPKIXPublicKey(rsaKey.Public())
		if err != nil {
			return nil, errors.WithMessage(err, "failed to generate certificate")
		}

		return samlMemoryKeyStore{
			privateKey: rsaKey,
			cert:       cert,
		}, nil
	}

	if config.Server.Development {
		privateKey, cert, err := dsig.RandomKeyStoreForTest().GetKeyPair()
		if err != nil {
			return nil, errors.WithMessage(err, "failed in development to generate test key-pair")
		}
		return samlMemoryKeyStore{
			privateKey: privateKey,
			cert:       cert,
		}, nil
	}

	return nil, errors.New("SAML RSA private key not provided")
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

	// We do not care about these warnings, so we zero them out.
	assertionInfo.WarningInfo.OneTimeUse = false
	assertionInfo.WarningInfo.ProxyRestriction = nil

	// In the future they might add more flags to WarningInfo.
	// We want all of them to be false (equal to the zero value).
	if !reflect.DeepEqual(*assertionInfo.WarningInfo, saml2.WarningInfo{}) { //nolint:exhaustruct
		errE := errors.New("unexpected SAML assertion warnings")
		errors.Details(errE)["warnings"] = *assertionInfo.WarningInfo
		return errE
	}

	if assertionInfo.NameID == "" {
		return errors.New("SAML assertion missing NameID")
	}

	return nil
}

func (s *Service) handlerSAMLStart(provider samlProvider) func(*Flow) (string, errors.E) {
	return func(flow *Flow) (string, errors.E) {
		authURL, id, err := samlBuildAuthURL(provider.Provider, flow.ID.String())
		if err != nil {
			return "", errors.WithStack(err)
		}

		flow.SAMLProvider = &FlowSAMLProvider{
			RequestID: id,
		}

		return authURL, nil
	}
}

func (s *Service) handleSAMLCallback(w http.ResponseWriter, req *http.Request, providerKey Provider, provider samlProvider) {
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

	flowSAML := *flow.SAMLProvider

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
		errors.Details(errE)["provider"] = providerKey
		s.failAuthStep(w, req, false, flow, errE)
		return
	}
	samlResponse := req.Form.Get("SAMLResponse")
	assertionInfo, response, err := retrieveAssertionInfoWithResponse(provider.Provider, samlResponse)
	if err != nil {
		errE = errors.WithStack(err)
		errors.Details(errE)["provider"] = providerKey
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = validateSAMLAssertion(assertionInfo)
	if errE != nil {
		errors.Details(errE)["provider"] = providerKey
		s.BadRequestWithError(w, req, errE)
		return
	}

	if response.InResponseTo != flowSAML.RequestID {
		errE = errors.New("SAML response ID does not match request ID")
		errors.Details(errE)["provider"] = providerKey
		errors.Details(errE)["request"] = flowSAML.RequestID
		errors.Details(errE)["response"] = response.InResponseTo
		s.BadRequestWithError(w, req, errE)
		return
	}

	attributes, errE := getSAMLAttributes(assertionInfo, provider.Mapping)
	if errE != nil {
		errors.Details(errE)["provider"] = providerKey
		errors.Details(errE)["assertion"] = assertionInfo
		s.BadRequestWithError(w, req, errE)
		return
	}

	jsonData, err := json.Marshal(attributes)
	if err != nil {
		errors.Details(errE)["provider"] = providerKey
		errors.Details(errE)["attributes"] = attributes
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	credentialID, errE := getSAMLCredentialID(assertionInfo, attributes, provider.Mapping.CredentialIDAttributes, samlResponse)
	if errE != nil {
		errors.Details(errE)["provider"] = providerKey
		errors.Details(errE)["attributes"] = attributes
		s.BadRequestWithError(w, req, errE)
		return
	}

	account, errE := s.getAccountByCredential(ctx, providerKey, credentialID)
	if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		errors.Details(errE)["provider"] = providerKey
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.completeAuthStep(w, req, false, flow, account, []Credential{{ID: credentialID, Provider: providerKey, Data: jsonData}})
}

func (s *Service) SAMLMetadataGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	providerKey := Provider(params["provider"])

	samlProviders := s.samlProviders()
	provider, ok := samlProviders[providerKey]
	if !ok {
		errE := errors.New("provider not found")
		errors.Details(errE)["provider"] = providerKey
		s.NotFoundWithError(w, req, errE)
		return
	}

	metadata, errE := generateSAMLMetadata(provider)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(metadata)))
	w.Header().Set("Content-Disposition", `attachment; filename="metadata.xml"`)
	w.WriteHeader(http.StatusOK)

	// TODO: Implement in waf something similar to WriteJSON, but for other content types, and use it here.
	//       To support range requests, etags, and compression.
	_, _ = w.Write(metadata)
}
