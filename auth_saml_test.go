package charon_test

import (
	"bytes"
	"compress/flate"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

const (
	samlTestingEntityID = "samlTesting"
	samlTestingIssuer   = "https://saml.testing.local"
)

type SAMLTestStore struct {
	Subject                     string
	Attributes                  map[string][]string
	LastRequestID               string
	RelayState                  string
	PrivateKey                  *rsa.PrivateKey
	Certificate                 *x509.Certificate
	KeyStore                    dsig.X509KeyStore
	AssertionConsumerServiceURL string
}

type AuthnRequest struct {
	XMLName                     xml.Name `xml:"AuthnRequest"`
	AssertionConsumerServiceURL string   `xml:"AssertionConsumerServiceURL,attr"`
}

func startSAMLTestServer(t *testing.T) (*httptest.Server, *SAMLTestStore) {
	t.Helper()

	var ts *httptest.Server

	store := &SAMLTestStore{
		// We use one unique subject per instance for testing.
		Subject:    identifier.New().String(),
		Attributes: make(map[string][]string),
	}

	keyStore := dsig.RandomKeyStoreForTest()

	privateKey, certBytes, err := keyStore.GetKeyPair()
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	store.PrivateKey = privateKey
	store.Certificate = cert
	store.KeyStore = keyStore

	mux := http.NewServeMux()

	// Mock metadata endpoint.
	mux.HandleFunc("/saml/metadata", func(w http.ResponseWriter, req *http.Request) {
		certBase64 := base64.StdEncoding.EncodeToString(cert.Raw)
		scheme := "http"
		host := req.Host
		baseURL := fmt.Sprintf("%s://%s", scheme, host)
		metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>%s</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s/saml/auth"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, samlTestingIssuer, certBase64, baseURL)

		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(metadata))
	})

	mux.HandleFunc("/saml/auth", func(w http.ResponseWriter, req *http.Request) {
		samlRequest := req.URL.Query().Get("SAMLRequest")
		relayState := req.URL.Query().Get("RelayState")

		if samlRequest == "" {
			http.Error(w, "Missing SAMLRequest parameter", http.StatusBadRequest)
			return
		}

		store.RelayState = relayState

		xmlData, err := decodeSAMLRequest(t, samlRequest)
		if err != nil {
			http.Error(w, "samlTesting decodeSAMLRequest", http.StatusBadRequest)
			return
		}

		requestID := extractRequestID(t, xmlData)
		if requestID == "" {
			http.Error(w, "samlTesting missing request ID in SAML request", http.StatusBadRequest)
			return
		}
		store.LastRequestID = requestID

		callbackURL, errE := extractAssertionConsumerServiceURL(t, xmlData)
		if errE != nil || callbackURL == "" {
			http.Error(w, "samlTesting invalid assertion consumer service URL", http.StatusBadRequest)
			return
		}
		store.AssertionConsumerServiceURL = callbackURL

		response := generateSignedSAMLResponse(t, store, requestID, callbackURL)

		html := fmt.Sprintf(`
        <html>
            <body onload="document.forms[0].submit()">
                <form method="post" action="%s">
                    <input type="hidden" name="SAMLResponse" value="%s"/>
                    <input type="hidden" name="RelayState" value="%s"/>
                    <noscript>
                        <input type="submit" value="Submit"/>
                    </noscript>
                </form>
            </body>
        </html>`, callbackURL, response, relayState)

		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(html))
	})

	ts = httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts, store
}

func generateSignedSAMLResponse(t *testing.T, store *SAMLTestStore, requestID string, destination string) string {
	t.Helper()

	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.Add(5 * time.Minute)
	responseID := "response_" + identifier.New().String()

	if len(store.Attributes) == 0 {
		store.Attributes = map[string][]string{
			"email":     {store.Subject + "@example.com"},
			"username":  {store.Subject},
			"firstName": {"Test"},
			"lastName":  {"User"},
		}
	}

	responseXML := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="%s" Version="2.0" IssueInstant="%s" InResponseTo="%s" Destination="%s">
    <saml:Issuer>%s</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="assertion_%s" Version="2.0" IssueInstant="%s">
        <saml:Issuer>%s</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">%s</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData InResponseTo="%s" NotOnOrAfter="%s" Recipient="%s"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
            <saml:AudienceRestriction>
                <saml:Audience>%s</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="%s" SessionIndex="session_%s">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>%s
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`,
		responseID,                                 // response ID.
		now.Format(time.RFC3339),                   // issue instant.
		requestID,                                  // in response to.
		destination,                                // destination.
		samlTestingIssuer,                          // issuer.
		identifier.New().String(),                  // assertion ID.
		now.Format(time.RFC3339),                   // assertion issue instant.
		samlTestingIssuer,                          // assertion issuer.
		store.Subject,                              // name ID.
		requestID,                                  // subject confirmation in response to.
		notAfter.Format(time.RFC3339),              // subject confirmation not on or after.
		destination,                                // subject confirmation recipient.
		notBefore.Format(time.RFC3339),             // conditions not before.
		notAfter.Format(time.RFC3339),              // conditions not on or after.
		samlTestingEntityID,                        // audience.
		now.Format(time.RFC3339),                   // authn instant.
		identifier.New().String(),                  // session index.
		generateAttributesXML(t, store.Attributes), // attributes XML.
	)

	doc := etree.NewDocument()
	err := doc.ReadFromString(responseXML)
	require.NoError(t, err)

	signCtx := dsig.NewDefaultSigningContext(store.KeyStore)
	err = signCtx.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
	if err != nil {
		return ""
	}

	signedResponse, err := signCtx.SignEnveloped(doc.Root())
	require.NoError(t, err)

	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(signedResponse)

	xmlBytes, err := signedDoc.WriteToBytes()
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(xmlBytes)
}

func generateAttributesXML(t *testing.T, attributes map[string][]string) string {
	t.Helper()
	var sb strings.Builder

	for name, values := range attributes {
		sb.WriteString(fmt.Sprintf(`
            <saml:Attribute Name="%s" FriendlyName="%s">`, name, name))

		for _, value := range values {
			sb.WriteString(fmt.Sprintf(`
                <saml:AttributeValue xsi:type="xs:string">%s</saml:AttributeValue>`, value))
		}

		sb.WriteString(`
            </saml:Attribute>`)
	}

	return sb.String()
}

func samlSignin(t *testing.T, ts *httptest.Server, service *charon.Service, samlTS *httptest.Server, signinOrSignout charon.Completed) string {
	t.Helper()

	samlClient := samlTS.Client()

	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)

	authFlowThirdPartyProviderStart, errE := service.ReverseAPI("AuthFlowThirdPartyProviderStart", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Start SAML.
	resp, err := ts.Client().Post(ts.URL+authFlowThirdPartyProviderStart, "application/json", strings.NewReader(`{"provider":"samlTesting"}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authFlowResponse charon.AuthFlowResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, []charon.Provider{"samlTesting"}, authFlowResponse.Providers)
	require.NotNil(t, authFlowResponse.ThirdPartyProvider)
	require.True(t, strings.HasPrefix(authFlowResponse.ThirdPartyProvider.Location, samlTS.URL), authFlowResponse.ThirdPartyProvider.Location)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available, current provider is testing.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{}, []charon.Provider{"samlTesting"}, "", assertCharonDashboard)
	}

	// Redirect to our testing provider.
	resp, err = samlClient.Get(authFlowResponse.ThirdPartyProvider.Location) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	htmlStr := string(out)
	assert.Equal(t, http.StatusOK, resp.StatusCode, htmlStr)

	samlResponse := extractFormValue(t, htmlStr, "SAMLResponse")
	relayState := extractFormValue(t, htmlStr, "RelayState")
	actionURL := extractFormAction(t, htmlStr)

	require.NotEmpty(t, samlResponse)
	require.NotEmpty(t, relayState)
	require.NotEmpty(t, actionURL)

	formData := url.Values{
		"SAMLResponse": {samlResponse},
		"RelayState":   {relayState},
	}

	// Flow has not yet changed, current provider is testing.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{}, []charon.Provider{"samlTesting"}, "", assertCharonDashboard)
	}

	// Redirect to SAML callback.
	resp, err = ts.Client().Post(actionURL, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode())) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, string(out))
	location := resp.Header.Get("Location")

	route, errE := service.GetRoute(location, http.MethodGet)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, "AuthFlowGet", route.Name)

	// Flow is available and signinOrSignout is completed.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	require.NoError(t, err)
	oid := assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{signinOrSignout}, []charon.Provider{"samlTesting"}, "", assertCharonDashboard)

	chooseIdentity(t, ts, service, oid, flowID, "Charon", "Dashboard", signinOrSignout, []charon.Provider{"samlTesting"}, 1, "username")
	return doRedirectAndAccessToken(t, ts, service, oid, flowID, "Charon", "Dashboard", nonce, state, pkceVerifier, config, verifier, signinOrSignout, []charon.Provider{"samlTesting"})
}

func mockSAMLSignin(t *testing.T, ts *httptest.Server, service *charon.Service, signinOrSignout charon.Completed) string {
	t.Helper()

	mockSAMLClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	flowID, nonce, state, pkceVerifier, config, verifier := createAuthFlow(t, ts, service)

	authFlowThirdPartyProviderStart, errE := service.ReverseAPI("AuthFlowThirdPartyProviderStart", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Start MockSAML.
	resp, err := ts.Client().Post(ts.URL+authFlowThirdPartyProviderStart, "application/json", strings.NewReader(`{"provider":"mockSAML"}`)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var authFlowResponse charon.AuthFlowResponse
	errE = x.DecodeJSONWithoutUnknownFields(resp.Body, &authFlowResponse)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, []charon.Provider{"mockSAML"}, authFlowResponse.Providers)
	require.NotNil(t, authFlowResponse.ThirdPartyProvider)

	authFlowGet, errE := service.ReverseAPI("AuthFlowGet", waf.Params{"id": flowID.String()}, nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Flow is available, current provider is mockSAML.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{}, []charon.Provider{"mockSAML"}, "", assertCharonDashboard)
	}

	// Redirect to MockSAML login page.
	resp, err = mockSAMLClient.Get(authFlowResponse.ThirdPartyProvider.Location) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))

	location := resp.Header.Get("Location")
	require.NotEmpty(t, location, "Expected Location header in 302 response")
	locationURL, err := url.Parse(location)
	require.NoError(t, err)
	queryParams := locationURL.Query()

	authPayload := map[string]interface{}{
		"email": "jackson@example.com",
	}
	for key, values := range queryParams {
		if len(values) > 0 {
			authPayload[key] = values[0]
		}
	}
	jsonPayload, err := json.Marshal(authPayload)
	require.NoError(t, err)

	// Call MockSAML auth endpoint.
	resp, err = mockSAMLClient.Post("https://mocksaml.com/api/namespace/charon/saml/auth", "application/json", bytes.NewReader(jsonPayload)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	htmlStr := string(out)
	assert.Equal(t, http.StatusOK, resp.StatusCode, htmlStr)

	samlResponse := extractFormValue(t, htmlStr, "SAMLResponse")
	relayState := extractFormValue(t, htmlStr, "RelayState")
	actionURL := extractFormAction(t, htmlStr)

	require.NotEmpty(t, samlResponse)
	require.NotEmpty(t, relayState)
	require.NotEmpty(t, actionURL)

	formData := url.Values{
		"SAMLResponse": {samlResponse},
		"RelayState":   {relayState},
	}

	// Flow has not yet changed, current provider is testing.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{}, []charon.Provider{"mockSAML"}, "", assertCharonDashboard)
	}

	// Redirect to SAML callback.
	resp, err = ts.Client().Post(actionURL, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode())) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, string(out))
	location = resp.Header.Get("Location")
	assert.NotEmpty(t, location)

	route, errE := service.GetRoute(location, http.MethodGet)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, "AuthFlowGet", route.Name)

	// Flow is available and signinOrSignout is completed.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	require.NoError(t, err)
	oid := assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{signinOrSignout}, []charon.Provider{"mockSAML"}, "", assertCharonDashboard)

	chooseIdentity(t, ts, service, oid, flowID, "Charon", "Dashboard", signinOrSignout, []charon.Provider{"mockSAML"}, 1, "username")
	return doRedirectAndAccessToken(t, ts, service, oid, flowID, "Charon", "Dashboard", nonce, state, pkceVerifier, config, verifier, signinOrSignout, []charon.Provider{"mockSAML"})
}

func extractRequestID(t *testing.T, xmlData string) string {
	t.Helper()
	if idx := strings.Index(xmlData, `ID="`); idx != -1 {
		start := idx + 4
		if end := strings.Index(xmlData[start:], `"`); end != -1 {
			return xmlData[start : start+end]
		}
	}
	return ""
}

func extractAssertionConsumerServiceURL(t *testing.T, xmlData string) (string, error) {
	t.Helper()
	var req AuthnRequest
	if err := xml.Unmarshal([]byte(xmlData), &req); err != nil {
		return "", err
	}
	return req.AssertionConsumerServiceURL, nil
}

func decodeSAMLRequest(t *testing.T, encoded string) (string, error) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	reader := flate.NewReader(bytes.NewReader(raw))
	defer reader.Close()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("flate decompress: %w", err)
	}

	return string(decoded), nil
}

func extractFormValue(t *testing.T, html string, name string) string {
	t.Helper()
	searchStr := fmt.Sprintf(`name="%s" value="`, name)
	if idx := strings.Index(html, searchStr); idx != -1 {
		start := idx + len(searchStr)
		if end := strings.Index(html[start:], `"`); end != -1 {
			return html[start : start+end]
		}
	}
	return ""
}

func extractFormAction(t *testing.T, html string) string {
	t.Helper()
	searchStr := `action="`
	if idx := strings.Index(html, searchStr); idx != -1 {
		start := idx + len(searchStr)
		if end := strings.Index(html[start:], `"`); end != -1 {
			return html[start : start+end]
		}
	}
	return ""
}

func TestAuthFlowSAML(t *testing.T) { //nolint:dupl
	t.Parallel()

	ts, service, _, _, samlTS := startTestServer(t)

	// Signup with SAML.
	accessToken := samlSignin(t, ts, service, samlTS, charon.CompletedSignup)

	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{"samlTesting"}, 0, 1, 0, 1},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})

	signoutUser(t, ts, service, accessToken)

	// Signin with SAML.
	accessToken = samlSignin(t, ts, service, samlTS, charon.CompletedSignin)

	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{"samlTesting"}, 0, 1, 0, 1}, // Signin.
		{charon.ActivitySignOut, nil, nil, 0, 0, 0, 0},                             // Signout.
		{charon.ActivitySignIn, nil, []charon.Provider{"samlTesting"}, 0, 1, 0, 1},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})
}

func TestAuthFlowMockSAML(t *testing.T) {
	t.Parallel()

	ts, service, _, _, _ := startTestServer(t) //nolint:dogsled

	// Signup with MockSAML.
	accessToken := mockSAMLSignin(t, ts, service, charon.CompletedSignup)

	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{"mockSAML"}, 0, 1, 0, 1},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})

	signoutUser(t, ts, service, accessToken)

	// Signin with MockSAML.
	accessToken = mockSAMLSignin(t, ts, service, charon.CompletedSignin)

	verifyAllActivities(t, ts, service, accessToken, []ActivityExpectation{
		{charon.ActivitySignIn, nil, []charon.Provider{"mockSAML"}, 0, 1, 0, 1}, // Signin.
		{charon.ActivitySignOut, nil, nil, 0, 0, 0, 0},                          // Signout.
		{charon.ActivitySignIn, nil, []charon.Provider{"mockSAML"}, 0, 1, 0, 1},
		{charon.ActivityIdentityUpdate, []charon.ActivityChangeType{charon.ActivityChangeMembershipAdded}, nil, 1, 1, 0, 1},
		{charon.ActivityIdentityCreate, nil, nil, 1, 0, 0, 0},
	})
}
