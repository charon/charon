package charon

import (
	"strings"

	saml2 "github.com/russellhaering/gosaml2"
	"gitlab.com/tozd/go/errors"
)

type SAMLAttributeMapping struct {
	CredentialIDAttribute string            `yaml:"credentialIdAttribute"`
	Mappings              map[string]string `yaml:"mappings"`
}

func getSIPASSAttributeMapping() SAMLAttributeMapping {
	return SAMLAttributeMapping{
		CredentialIDAttribute: "1.3.6.1.4.1.44044.1.1.3.2", // VATNumber.
		Mappings: map[string]string{
			"1.3.6.1.4.1.44044.1.1.3.1":  "token", // SICAS Token - unique identifier.
			"1.3.6.1.4.1.44044.1.1.3.2":  "authMethod",
			"1.3.6.1.4.1.44044.1.1.3.3":  "authMechanism",
			"1.3.6.1.4.1.44044.1.1.3.10": "language",
		},
	}
}

func getDefaultAttributeMapping() SAMLAttributeMapping {
	return SAMLAttributeMapping{
		CredentialIDAttribute: "NameID",
		Mappings:              map[string]string{},
	}
}

type SAMLCredentialResolver interface {
	ResolveCredentialID(assertionInfo *saml2.AssertionInfo) (string, errors.E)
	GetAttributeMapping() SAMLAttributeMapping
}

type GenericSAMLResolver struct {
	ProviderName     string
	AttributeMapping SAMLAttributeMapping
}

func (r *GenericSAMLResolver) GetAttributeMapping() SAMLAttributeMapping {
	return r.AttributeMapping
}

func NewSAMLResolver(providerName string, mapping SAMLAttributeMapping) *GenericSAMLResolver {
	return &GenericSAMLResolver{
		ProviderName:     providerName,
		AttributeMapping: mapping,
	}
}

func (r *GenericSAMLResolver) ResolveCredentialID(assertionInfo *saml2.AssertionInfo) (string, errors.E) {
	credentialIDAttr := r.AttributeMapping.CredentialIDAttribute

	if credentialIDAttr == "NameID" {
		if assertionInfo.NameID != "" {
			return assertionInfo.NameID, nil
		}
		return "", errors.WithDetails(
			errors.New("NameID credential ID attribute is empty"),
			"provider", r.ProviderName,
			"attribute", credentialIDAttr,
		)
	}

	if attrValue, exists := assertionInfo.Values[credentialIDAttr]; exists && len(attrValue.Values) > 0 {
		credentialID := strings.TrimSpace(attrValue.Values[0].Value)
		if credentialID != "" {
			return credentialID, nil
		}
	}

	return "", errors.WithDetails(
		errors.New("credential ID attribute not found or empty"),
		"provider", r.ProviderName,
		"attribute", credentialIDAttr,
	)
}

type SIPassResolver struct {
	*GenericSAMLResolver
}

func NewSIPassResolver() *SIPassResolver {
	return &SIPassResolver{
		GenericSAMLResolver: &GenericSAMLResolver{
			ProviderName:     "SIPASS",
			AttributeMapping: getSIPASSAttributeMapping(),
		},
	}
}

func (r *SIPassResolver) ResolveCredentialID(assertionInfo *saml2.AssertionInfo) (string, errors.E) {
	if tokenAttr, exists := assertionInfo.Values["1.3.6.1.4.1.44044.1.1.3.1"]; exists && len(tokenAttr.Values) > 0 {
		token := strings.TrimSpace(tokenAttr.Values[0].Value)
		if token != "" {
			return token, nil
		}
	}
	errE := errors.New("sign in is not possible: required authentication token is empty")
	errors.Details(errE)["provider"] = "SIPASS"
	errors.Details(errE)["technicalDetails"] = "OID 1.3.6.1.4.1.44044.1.1.3.1 not found"
	errors.Details(errE)["availableAttributes"] = getAvailableAttributeNames(assertionInfo)
	return "", errE
}

func getAvailableAttributeNames(assertionInfo *saml2.AssertionInfo) []string {
	names := make([]string, 0, len(assertionInfo.Values))
	for name := range assertionInfo.Values {
		names = append(names, name)
	}
	return names
}

func CreateSAMLResolver(provider SiteProvider) SAMLCredentialResolver { //nolint:ireturn
	switch provider.Key { //nolint:exhaustive
	case "sipass":
		return NewSIPassResolver()
	default:
		return NewSAMLResolver(provider.Name, provider.samlAttributeMapping)
	}
}
