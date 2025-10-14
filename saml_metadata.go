package charon

import (
	"encoding/xml"

	"github.com/beevik/etree"
	"gitlab.com/tozd/go/errors"
)

const (
	samlMetadataNS    = "urn:oasis:names:tc:SAML:2.0:metadata"
	locAttrValue      = "https://sipasstest.peer.id/api/auth/provider/sipass"
	samlDsigNS        = "http://www.w3.org/2000/09/xmldsig#"
	cacheDuration     = "PT604800S"
	indentationSpaces = 4
)

func generateSAMLMetadata(provider samlProvider) ([]byte, errors.E) {
	entityDescriptor, err := provider.Provider.Metadata()
	if err != nil {
		return nil, withGosamlError(err)
	}

	if entityDescriptor.SPSSODescriptor == nil {
		return nil, errors.New("generated metadata missing SPSSODescriptor")
	}

	if provider.Mapping.CredentialIDAttributes == nil {
		entityDescriptor.SPSSODescriptor.NameIDFormats = allowedNameIDFormats
	}

	metadataXML, err := xml.Marshal(entityDescriptor)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	doc := etree.NewDocument()
	if err = doc.ReadFromBytes(metadataXML); err != nil {
		return nil, errors.WithStack(err)
	}

	root := doc.Root()
	root.CreateAttr("cacheDuration", cacheDuration)
	root.CreateAttr("xmlns:md", samlMetadataNS)
	root.CreateAttr("xmlns:ds", samlDsigNS)

	if len(provider.Mapping.Mapping) > 0 {
		doc.FindElement("//SPSSODescriptor").AddChild(createACS(provider.Mapping))
	}

	if kd := doc.FindElement("//KeyDescriptor"); kd != nil {
		kd.RemoveAttr("use")
	}

	for _, em := range doc.FindElements("//EncryptionMethod") {
		em.Parent().RemoveChild(em)
	}

	if provider.Key == "sipass" {
		if acs := doc.FindElement("//AssertionConsumerService"); acs != nil {
			if locationAttr := acs.SelectAttr("Location"); locationAttr != nil {
				locationAttr.Value = locAttrValue
			}
		}
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

func createACS(samlMapping SAMLAttributeMapping) *etree.Element {
	acs := etree.NewElement("md:AttributeConsumingService")
	acs.CreateAttr("index", "0")

	sn := acs.CreateElement("md:ServiceName")
	sn.CreateAttr("xml:lang", "en")
	sn.SetText("PeerID")

	for oid, friendlyName := range samlMapping.Mapping {
		reqAttr := acs.CreateElement("md:RequestedAttribute")
		reqAttr.CreateAttr("Name", oid)
		reqAttr.CreateAttr("FriendlyName", friendlyName)
		reqAttr.CreateAttr("isRequired", "true")
	}

	return acs
}
