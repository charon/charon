package charon

import (
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	"gitlab.com/tozd/go/errors"
)

// retrieveAssertionInfoWithResponse is the same as saml2.RetrieveAssertionInfo, but
// returns the response as well.
//
// See: https://github.com/russellhaering/gosaml2/issues/235
// See: https://github.com/russellhaering/gosaml2/pull/236
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
			assertionInfo.Values[attribute.Name] = attribute
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
