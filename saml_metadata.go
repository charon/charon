package charon

import (
	"encoding/xml"
	"maps"
	"slices"

	"github.com/beevik/etree"
	"gitlab.com/tozd/go/errors"
)

const (
	samlMetadataNS    = "urn:oasis:names:tc:SAML:2.0:metadata"
	samlDsigNS        = "http://www.w3.org/2000/09/xmldsig#"
	indentationSpaces = 4
)

func generateSAMLMetadata(provider samlProvider, serviceName string) ([]byte, errors.E) {
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
	root.CreateAttr("xmlns:md", samlMetadataNS)
	root.CreateAttr("xmlns:ds", samlDsigNS)

	if len(provider.Mapping.Mapping) > 0 {
		doc.FindElement("//SPSSODescriptor").AddChild(createAttributeConsumingService(provider.Mapping, serviceName))
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
		"EntityDescriptor":          true,
		"SPSSODescriptor":           true,
		"KeyDescriptor":             true,
		"NameIDFormat":              true,
		"AssertionConsumerService":  true,
		"AttributeConsumingService": true,
		"ServiceName":               true,
		"RequestedAttribute":        true,
		"EncryptionMethod":          true,
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

func createAttributeConsumingService(samlMapping SAMLAttributeMapping, serviceName string) *etree.Element {
	acs := etree.NewElement("AttributeConsumingService")
	acs.CreateAttr("index", "1")

	for _, lang := range []string{"en", "sl"} {
		sn := acs.CreateElement("ServiceName")
		sn.CreateAttr("xml:lang", lang)
		sn.SetText(serviceName)
	}

	sortedKeys := slices.Sorted(maps.Keys(samlMapping.Mapping))

	for _, name := range sortedKeys {
		reqAttr := acs.CreateElement("RequestedAttribute")
		reqAttr.CreateAttr("Name", name)
		reqAttr.CreateAttr("FriendlyName", samlMapping.Mapping[name])
		reqAttr.CreateAttr("isRequired", "true")
	}

	return acs
}
