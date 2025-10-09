package charon

import (
	"encoding/xml"

	"github.com/beevik/etree"
	"gitlab.com/tozd/go/errors"
)

const (
	samlMetadataNS    = "urn:oasis:names:tc:SAML:2.0:metadata"
	attrNameFormatURI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	transientURN      = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	locAttrValue      = "https://sipasstest.peer.id/api/auth/provider/sipass"
	samlDsigNS        = "http://www.w3.org/2000/09/xmldsig#"
	cacheDuration     = "PT604800S"
	indentationSpaces = 4
)

type SAMLAttributeDefinition struct {
	Name         string
	NameFormat   string
	FriendlyName string
	IsRequired   bool
}

func getSIPASSAttributeDefinitions() []SAMLAttributeDefinition {
	return []SAMLAttributeDefinition{
		{
			Name:         "urn:oid:1.3.6.1.4.1.44044.1.1.1.2",
			NameFormat:   attrNameFormatURI,
			FriendlyName: "vatNumber",
			IsRequired:   true,
		},
		{
			Name:         "urn:oid:1.3.6.1.4.1.44044.1.1.2.2",
			NameFormat:   attrNameFormatURI,
			FriendlyName: "vatNumberMetadata",
			IsRequired:   true,
		},
		{
			Name:         "urn:oid:1.3.6.1.4.1.44044.1.1.1.6",
			NameFormat:   attrNameFormatURI,
			FriendlyName: "name",
			IsRequired:   true,
		},
		{
			Name:         "urn:oid:1.3.6.1.4.1.44044.1.1.2.6",
			NameFormat:   attrNameFormatURI,
			FriendlyName: "nameMetadata",
			IsRequired:   true,
		},
		{
			Name:         "urn:oid:1.3.6.1.4.1.44044.1.1.1.7",
			NameFormat:   attrNameFormatURI,
			FriendlyName: "surname",
			IsRequired:   true,
		},
		{
			Name:         "urn:oid:1.3.6.1.4.1.44044.1.1.2.7",
			NameFormat:   attrNameFormatURI,
			FriendlyName: "surnameMetadata",
			IsRequired:   true,
		},
		{
			Name:         "urn:oid:1.3.6.1.4.1.44044.1.1.1.11",
			NameFormat:   attrNameFormatURI,
			FriendlyName: "birthDate",
			IsRequired:   true,
		},
		{
			Name:         "urn:oid:1.3.6.1.4.1.44044.1.1.2.11",
			NameFormat:   attrNameFormatURI,
			FriendlyName: "birthDateMetadata",
			IsRequired:   true,
		},
		{
			Name:         "urn:oid:1.3.6.1.4.1.44044.1.1.1.14",
			NameFormat:   attrNameFormatURI,
			FriendlyName: "eMailAddress",
			IsRequired:   true,
		},
		{
			Name:         "urn:oid:1.3.6.1.4.1.44044.1.1.2.14",
			NameFormat:   attrNameFormatURI,
			FriendlyName: "eMailAddressMetadata",
			IsRequired:   true,
		},
		{
			Name:         "urn:oid:1.3.6.1.4.1.44044.1.1.3.2",
			NameFormat:   attrNameFormatURI,
			FriendlyName: "authId",
			IsRequired:   true,
		},
		{
			Name:         "urn:oid:1.3.6.1.4.1.44044.1.1.3.3",
			NameFormat:   attrNameFormatURI,
			FriendlyName: "authMechanism",
			IsRequired:   true,
		},
		{
			Name:         "urn:oid:1.3.6.1.4.1.44044.1.1.3.10",
			NameFormat:   attrNameFormatURI,
			FriendlyName: "language",
			IsRequired:   true,
		},
	}
}

func generateSAMLMetadata(provider samlProvider) ([]byte, errors.E) {
	entityDescriptor, err := provider.Provider.Metadata()
	if err != nil {
		return nil, withGosamlError(err)
	}
	if entityDescriptor.SPSSODescriptor == nil {
		return nil, errors.New("generated metadata missing SPSSODescriptor")
	}

	entityDescriptor.SPSSODescriptor.NameIDFormats = getNameIDFormatsForProvider(provider)

	metadataXML, err := xml.Marshal(entityDescriptor)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	doc := etree.NewDocument()
	if err = doc.ReadFromBytes(metadataXML); err != nil {
		return nil, errors.WithStack(err)
	}

	root := doc.Root()
	root.CreateAttr("xmlns:md", samlMetadataNS)
	root.CreateAttr("xmlns:ds", samlDsigNS)

	if provider.Key == "sipass" {
		enhanceSIPASSMetadata(doc)
	}
	addNamespacePrefixes(root)

	doc.Indent(indentationSpaces)
	metadataXML, err = doc.WriteToBytes()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	xmlWithDeclaration := append([]byte(xml.Header), metadataXML...)
	return xmlWithDeclaration, nil
}

// This is a heavily customized metadata for SIPASS IdP.
func enhanceSIPASSMetadata(doc *etree.Document) {
	root := doc.Root()
	root.CreateAttr("cacheDuration", cacheDuration)

	if kd := doc.FindElement("//KeyDescriptor"); kd != nil {
		kd.RemoveAttr("use")
	}

	for _, em := range doc.FindElements("//EncryptionMethod") {
		em.Parent().RemoveChild(em)
	}

	if acs := doc.FindElement("//AssertionConsumerService"); acs != nil {
		if indexAttr := acs.SelectAttr("index"); indexAttr != nil {
			indexAttr.Value = "0"
		}
		acs.CreateAttr("isDefault", "true")
		if locationAttr := acs.SelectAttr("Location"); locationAttr != nil {
			locationAttr.Value = locAttrValue
		}
	}

	doc.FindElement("//SPSSODescriptor").AddChild(createSipassACS(getSIPASSAttributeDefinitions()))
}

func addNamespacePrefixes(root *etree.Element) {
	metadataElements := map[string]bool{
		"EntityDescriptor":         true,
		"SPSSODescriptor":          true,
		"KeyDescriptor":            true,
		"NameIDFormat":             true,
		"AssertionConsumerService": true,
		"EncryptionMethod":         true,
	}

	signatureElements := map[string]bool{
		"KeyInfo":         true,
		"X509Data":        true,
		"X509Certificate": true,
	}

	for _, elem := range root.FindElements("//*") {
		if metadataElements[elem.Tag] {
			elem.Space = "md"
			elem.RemoveAttr("xmlns")
		}
		if signatureElements[elem.Tag] {
			elem.Space = "ds"
			elem.RemoveAttr("xmlns")
		}
	}
}

func createSipassACS(attributeDefinitions []SAMLAttributeDefinition) *etree.Element {
	acs := etree.NewElement("md:AttributeConsumingService")
	acs.CreateAttr("index", "0")
	acs.CreateAttr("isDefault", "true")

	sn := acs.CreateElement("md:ServiceName")
	sn.CreateAttr("xml:lang", "en")
	sn.SetText("PeerID")

	for _, attrDef := range attributeDefinitions {
		reqAttr := acs.CreateElement("md:RequestedAttribute")
		reqAttr.CreateAttr("Name", attrDef.Name)
		reqAttr.CreateAttr("NameFormat", attrDef.NameFormat)
		reqAttr.CreateAttr("FriendlyName", attrDef.FriendlyName)
		reqAttr.CreateAttr("isRequired", "true")
	}

	return acs
}

func getNameIDFormatsForProvider(provider samlProvider) []string {
	switch provider.Key { //nolint:exhaustive
	case "sipass":
		return []string{
			transientURN,
		}
	default:
		formats := make([]string, len(allowedNameIDFormats))
		copy(formats, allowedNameIDFormats)
		return formats
	}
}
