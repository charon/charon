package charon

import (
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	"gitlab.com/tozd/go/errors"
)

// samlBuildAuthURL is the same as saml2.BuildAuthURL, but correctly uses HTTP-Redirect binding.
// It also returns ID of the authn request.
//
// See: https://github.com/russellhaering/gosaml2/issues/89
func samlBuildAuthURL(sp *saml2.SAMLServiceProvider, relayState string) (string, string, errors.E) {
	doc, err := sp.BuildAuthRequestDocument()
	if err != nil {
		return "", "", errors.WithStack(err)
	}
	authURL, err := sp.BuildAuthURLRedirect(relayState, doc)
	if err != nil {
		return "", "", errors.WithStack(err)
	}
	el := doc.FindElement(".//samlp:AuthnRequest")
	if el == nil {
		return "", "", errors.New("AuthnRequest element not found")
	}
	id := el.SelectAttrValue("ID", "")
	if id == "" {
		return "", "", errors.New("ID attribute not found")
	}
	return authURL, id, nil
}

// retrieveAssertionInfoWithResponse is the same as saml2.RetrieveAssertionInfo, but
// returns the response as well. It also merges repeated same response attributes
// into one slice.
//
// See: https://github.com/russellhaering/gosaml2/issues/235
// See: https://github.com/russellhaering/gosaml2/pull/236
// See: https://github.com/russellhaering/gosaml2/issues/241
func retrieveAssertionInfoWithResponse(sp *saml2.SAMLServiceProvider, encodedResponse string) (*saml2.AssertionInfo, *types.Response, errors.E) {
	assertionInfo := &saml2.AssertionInfo{ //nolint:exhaustruct
		Values: make(saml2.Values),
	}

	response, err := sp.ValidateEncodedResponse(encodedResponse)
	if err != nil {
		return nil, nil, errors.WithStack(saml2.ErrVerification{Cause: err})
	}

	// TODO: Support multiple assertions.
	if len(response.Assertions) == 0 {
		return nil, nil, errors.WithStack(saml2.ErrMissingAssertion)
	}

	assertion := response.Assertions[0]
	assertionInfo.Assertions = response.Assertions
	assertionInfo.ResponseSignatureValidated = response.SignatureValidated

	warningInfo, err := sp.VerifyAssertionConditions(&assertion)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	// Get the NameID.
	subject := assertion.Subject
	if subject == nil {
		return nil, nil, errors.WithStack(saml2.ErrMissingElement{Tag: saml2.SubjectTag}) //nolint:exhaustruct
	}

	nameID := subject.NameID
	if nameID == nil {
		return nil, nil, errors.WithStack(saml2.ErrMissingElement{Tag: saml2.NameIdTag}) //nolint:exhaustruct
	}

	assertionInfo.NameID = nameID.Value

	// Get the actual assertion attributes.
	attributeStatement := assertion.AttributeStatement
	if attributeStatement == nil && !sp.AllowMissingAttributes {
		return nil, nil, errors.WithStack(saml2.ErrMissingElement{Tag: saml2.AttributeStatementTag}) //nolint:exhaustruct
	}

	if attributeStatement != nil {
		for _, attribute := range attributeStatement.Attributes {
			if v, ok := assertionInfo.Values[attribute.Name]; ok {
				v.Values = append(v.Values, attribute.Values...)
				assertionInfo.Values[attribute.Name] = v
			} else {
				assertionInfo.Values[attribute.Name] = attribute
			}
		}
	}

	if assertion.AuthnStatement != nil {
		if assertion.AuthnStatement.AuthnInstant != nil {
			assertionInfo.AuthnInstant = assertion.AuthnStatement.AuthnInstant
		}
		if assertion.AuthnStatement.SessionNotOnOrAfter != nil {
			assertionInfo.SessionNotOnOrAfter = assertion.AuthnStatement.SessionNotOnOrAfter
		}

		assertionInfo.SessionIndex = assertion.AuthnStatement.SessionIndex
	}

	assertionInfo.WarningInfo = warningInfo
	return assertionInfo, response, nil
}
