package charon

import (
	"encoding/base64"
	"encoding/xml"
	"regexp"
	"strconv"
	"strings"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
)

const (
	nameIDFormatWindowsDomainQualifiedName = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
	nameIDFormatKerberos                   = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
	nameIDFormatEntity                     = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
)

type SAMLAttributeMapping struct {
	// Empty CredentialIDAttributes means NameID.
	CredentialIDAttributes []string
	Mapping                map[string]string
}

func getSIPASSAttributeMapping() SAMLAttributeMapping {
	return SAMLAttributeMapping{
		// We use VAT number and birth date to construct an unique ID for this person.
		// VAT numbers can be recycled, but very unlikely for the person with the same birth date.
		CredentialIDAttributes: []string{"vatNumber", "birthDate"},
		Mapping: map[string]string{
			"urn:oid:1.3.6.1.4.1.44044.1.1.1.2":  "vatNumber",
			"urn:oid:1.3.6.1.4.1.44044.1.1.1.6":  "name",
			"urn:oid:1.3.6.1.4.1.44044.1.1.1.7":  "surname",
			"urn:oid:1.3.6.1.4.1.44044.1.1.1.11": "birthDate",
			"urn:oid:1.3.6.1.4.1.44044.1.1.1.14": "eMailAddress",
			"urn:oid:1.3.6.1.4.1.44044.1.1.3.2":  "authId",
			"urn:oid:1.3.6.1.4.1.44044.1.1.3.3":  "authMechanism",
			"urn:oid:1.3.6.1.4.1.44044.1.1.3.10": "language",
		},
	}
}

func getDefaultAttributeMapping() SAMLAttributeMapping {
	return SAMLAttributeMapping{
		CredentialIDAttributes: nil,
		Mapping:                nil,
	}
}

func getSAMLCredentialID(assertionInfo *saml2.AssertionInfo, attributes map[string][]any, credentialIDAttributes []string, rawResponse string) (string, errors.E) {
	credentialIDValues := []any{}
	decodedXML, err := base64.StdEncoding.DecodeString(rawResponse)
	if err != nil {
		return "", errors.WithMessage(err, "failed to decode SAMLResponse")
	}

	if len(credentialIDAttributes) == 0 {
		errE := validateNameIDFormat(decodedXML)
		if errE != nil {
			return "", errE
		}
		if assertionInfo.NameID != "" {
			credentialIDValues = append(credentialIDValues, assertionInfo.NameID)
		} else {
			return "", errors.New("empty NameID")
		}
	} else {
		for _, name := range credentialIDAttributes {
			values, ok := attributes[name]
			if !ok || len(values) == 0 {
				errE := errors.New("credential ID attribute not found or empty")
				errors.Details(errE)["attribute"] = name
				return "", errE
			}
			credentialIDValues = append(credentialIDValues, values...)
		}
	}

	// We use JSON representation of credential ID to support it being constructed from multiple values.
	credentialID, errE := x.MarshalWithoutEscapeHTML(credentialIDValues)
	if errE != nil {
		return "", errE
	}
	return string(credentialID), nil
}

var xmlTimeFormats = []string{ //nolint:gochecknoglobals
	"15:04:05.999999999Z07:00",
	"15:04:05.999999999",
}

var xmlDateTimeFormats = []string{ //nolint:gochecknoglobals
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02T15:04:05.999999999",
}

var xmlDateFormats = []string{ //nolint:gochecknoglobals
	"2006-01-02Z07:00",
	"2006-01-02",
}

var durationRe = regexp.MustCompile(`^(-)?P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$`)

// parseDuration parses only up to days because months and years are ambiguous in duration.
func parseDuration(s string) (time.Duration, errors.E) {
	matches := durationRe.FindStringSubmatch(s)
	if matches == nil {
		return 0, errors.New("invalid duration")
	}
	var d time.Duration
	if matches[2] != "" {
		days, err := strconv.Atoi(matches[2])
		if err != nil {
			return 0, errors.WithStack(err)
		}
		d += 24 * time.Hour * time.Duration(days) //nolint:mnd
	}
	if matches[3] != "" {
		hours, err := strconv.Atoi(matches[3])
		if err != nil {
			return 0, errors.WithStack(err)
		}
		d += time.Hour * time.Duration(hours)
	}
	if matches[4] != "" {
		minutes, err := strconv.Atoi(matches[4])
		if err != nil {
			return 0, errors.WithStack(err)
		}
		d += time.Minute * time.Duration(minutes)
	}
	if matches[5] != "" {
		seconds, err := strconv.ParseFloat(matches[5], 64)
		if err != nil {
			return 0, errors.WithStack(err)
		}
		d += time.Duration(float64(time.Second) * seconds)
	}
	if matches[1] == "-" {
		d = -d
	}
	return d, nil
}

func tryParseTime(layouts []string, s string) (time.Time, bool) {
	for _, layout := range layouts {
		// We assume UTC if timezone is not provided, but that is not really according to
		// the standard (where location is unspecified).
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func parseAttributeValue(value types.AttributeValue) (any, errors.E) {
	// Remove namespace prefix. We assume standard types, only that
	// the namespace prefix is maybe custom, but we simply ignore it.
	// Use the last colon to handle complex namespaces like "http://www.w3.org/2001/XMLSchema:int".
	lastColonIndex := strings.LastIndex(value.Type, ":")
	var valueType string
	if lastColonIndex == -1 {
		valueType = value.Type
	} else {
		valueType = value.Type[lastColonIndex+1:]
	}
	switch valueType {
	case "byte", "short", "int", "integer", "long", "negativeInteger", "nonNegativeInteger", "nonPositiveInteger", "positiveInteger",
		"unsignedByte", "unsignedShort", "unsignedInt", "unsignedLong":
		// We leave to ParseInt to fail if the value for unsignedLong is too large for int64.
		v, err := strconv.ParseInt(value.Value, 10, 64)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return v, nil
	case "float", "double", "decimal":
		v, err := strconv.ParseFloat(value.Value, 64)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return v, nil
	case "boolean":
		v, err := strconv.ParseBool(value.Value)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return v, nil
	case "string", "token", "normalizedString", "language", "anyURI", "":
		// If type is not provided, we assume string (the "" case).
		v := strings.TrimSpace(value.Value)
		if v != "" {
			return v, nil
		}
		return nil, nil //nolint:nilnil
	case "dateTime":
		v, ok := tryParseTime(xmlDateTimeFormats, value.Value)
		if !ok {
			return nil, errors.New("unable to parse dateTime")
		}
		return v, nil
	case "time":
		v, ok := tryParseTime(xmlTimeFormats, value.Value)
		if !ok {
			return nil, errors.New("unable to parse time")
		}
		return v, nil
	case "date":
		v, ok := tryParseTime(xmlDateFormats, value.Value)
		if !ok {
			return nil, errors.New("unable to parse date")
		}
		return v, nil
	case "duration":
		v, errE := parseDuration(value.Value)
		if errE != nil {
			return nil, errE
		}
		return v, nil
	default:
		return nil, errors.New("unsupported attribute type")
	}
}

func getSAMLAttributes(assertionInfo *saml2.AssertionInfo, mapping SAMLAttributeMapping) (map[string][]any, errors.E) {
	attributes := map[string][]any{}

	for name, attr := range assertionInfo.Values {
		attrName := name
		if mappedName, ok := mapping.Mapping[name]; ok {
			attrName = mappedName
		} else if attr.FriendlyName != "" {
			attrName = attr.FriendlyName
		}
		var values []any
		for _, value := range attr.Values {
			v, errE := parseAttributeValue(value)
			if errE != nil {
				errors.Details(errE)["value"] = value.Value
				errors.Details(errE)["type"] = value.Type
				errors.Details(errE)["attribute"] = name
				return nil, errE
			}
			if v != nil {
				values = append(values, v)
			}
		}
		if len(values) > 0 {
			attributes[attrName] = values
		}
	}

	return attributes, nil
}

func validateNameIDFormat(rawXML []byte) errors.E {
	format, value, errE := extractNameIDFormatFromXML(rawXML)
	if errE != nil {
		errors.Details(errE)["error"] = "extracting NameID format from SAMLResponse"
		return errE
	}

	if format == saml2.NameIdFormatEmailAddress ||
		format == saml2.NameIdFormatPersistent ||
		format == saml2.NameIdFormatX509SubjectName ||
		format == nameIDFormatWindowsDomainQualifiedName ||
		format == nameIDFormatKerberos ||
		format == nameIDFormatEntity {
		return nil
	}

	if format == saml2.NameIdFormatTransient ||
		format == saml2.NameIdFormatUnspecified {
		errE = errors.New("Transient or Unspecified NameID format cannot be used as credential ID")
		errors.Details(errE)["format"] = format
		errors.Details(errE)["nameID"] = value
		return errE
	}

	errE = errors.New("unsupported / unknown NameID format")
	errors.Details(errE)["format"] = format
	errors.Details(errE)["nameID"] = value
	return errE
}

func extractNameIDFormatFromXML(rawXML []byte) (string, string, errors.E) {
	type NameID struct {
		Format string `xml:"Format,attr"`
		Value  string `xml:",chardata"`
	}
	type Subject struct {
		NameID NameID `xml:"NameID"`
	}
	type Assertion struct {
		Subject Subject `xml:"Subject"`
	}
	type Response struct {
		Assertions []Assertion `xml:"Assertion"`
	}
	var resp Response
	if err := xml.Unmarshal(rawXML, &resp); err != nil {
		return "", "", errors.New("couldn't unmarshal SAMLResponse")
	}

	if len(resp.Assertions) == 0 {
		return "", "", errors.New("no assertions found in SAMLResponse")
	}

	format := resp.Assertions[0].Subject.NameID.Format
	value := resp.Assertions[0].Subject.NameID.Value

	if format == "" || value == "" {
		errE := errors.New("missing values NameID Format or NameID Value in SAMLResponse")
		errors.Details(errE)["format"] = format
		errors.Details(errE)["value"] = value
		return "", "", errE
	}
	return format, value, nil
}
