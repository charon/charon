package charon_test

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
	"golang.org/x/net/html"

	"gitlab.com/charon/charon"
)

const (
	samlTestingEntityID = "samlTesting"
)

const (
	samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlProtocolNS  = "urn:oasis:names:tc:SAML:2.0:protocol"
)

type samlTestStore struct {
	Subject    string
	Attributes map[string][]string
	RelayState string
	KeyStore   dsig.X509KeyStore
}

type Response struct {
	XMLName      xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string            `xml:"ID,attr"`
	InResponseTo string            `xml:"InResponseTo,attr"`
	Destination  string            `xml:"Destination,attr"`
	Version      string            `xml:"Version,attr"`
	IssueInstant time.Time         `xml:"IssueInstant,attr"`
	Issuer       *types.Issuer     `xml:"Issuer"`
	Status       *types.Status     `xml:"Status"`
	Assertions   []types.Assertion `xml:"Assertion"`
}

type authnRequest struct {
	XMLName                     xml.Name `xml:"AuthnRequest"`
	AssertionConsumerServiceURL string   `xml:"AssertionConsumerServiceURL,attr"`
}

func samlPostFormTemplate() *template.Template {
	return template.Must(template.New("samlPostForm").Parse(`
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>SAML Response</title>
    </head>
    <body onload="document.forms[0].submit()">
        <form method="post" action="{{.CallbackURL}}">
            <input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}"/>
            <input type="hidden" name="RelayState" value="{{.RelayState}}"/>
            <noscript>
                <p>JavaScript is disabled. Please click the button below to continue:</p>
                <input type="submit" value="Submit"/>
            </noscript>
        </form>
    </body>
</html>`))
}

type samlResponseData struct {
	ResponseID   string
	AssertionID  string
	InResponseTo string
	Destination  string
	IssueInstant string
	NotBefore    string
	NotOnOrAfter string
	Issuer       string
	Audience     string
	Subject      string
	SessionIndex string
	Attributes   []types.Attribute
}

func samlResponseTemplate() *template.Template {
	return template.Must(template.New("samlResponse").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Destination="{{.Destination}}" ID="{{.ResponseID}}" InResponseTo="{{.InResponseTo}}" IssueInstant="{{.IssueInstant}}" Version="2.0">
    <saml:Issuer>{{.Issuer}}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="{{.AssertionID}}" IssueInstant="{{.IssueInstant}}" Version="2.0">
        <saml:Issuer>{{.Issuer}}</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{{.Subject}}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData InResponseTo="{{.InResponseTo}}" NotOnOrAfter="{{.NotOnOrAfter}}" Recipient="{{.Destination}}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{{.NotBefore}}" NotOnOrAfter="{{.NotOnOrAfter}}">
            <saml:AudienceRestriction>
                <saml:Audience>{{.Audience}}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="{{.IssueInstant}}" SessionIndex="{{.SessionIndex}}">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>{{range .Attributes}}
            <saml:Attribute FriendlyName="{{.Name}}" Name="{{.Name}}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">{{range .Values}}
                <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{{.Value}}</saml:AttributeValue>{{end}}
            </saml:Attribute>{{end}}
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`))
}

func generateMetadata(t *testing.T, certBase64 string, scheme string, host string) ([]byte, errors.E) {
	t.Helper()

	baseURL := scheme + "://" + host

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	root := doc.CreateElement("EntityDescriptor")
	root.CreateAttr("xmlns", "urn:oasis:names:tc:SAML:2.0:metadata")
	root.CreateAttr("entityID", samlTestingEntityID)

	idpSSO := root.CreateElement("IDPSSODescriptor")
	idpSSO.CreateAttr("protocolSupportEnumeration", samlProtocolNS)

	keyDescriptor := idpSSO.CreateElement("KeyDescriptor")
	keyDescriptor.CreateAttr("use", "signing")

	keyInfo := keyDescriptor.CreateElement("KeyInfo")
	keyInfo.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")

	x509Data := keyInfo.CreateElement("X509Data")
	x509Cert := x509Data.CreateElement("X509Certificate")
	x509Cert.SetText(certBase64)

	ssoService := idpSSO.CreateElement("SingleSignOnService")
	ssoService.CreateAttr("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
	ssoService.CreateAttr("Location", baseURL+"/saml/auth")

	nameIDFormat := idpSSO.CreateElement("NameIDFormat")
	nameIDFormat.SetText("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")

	doc.Indent(2)
	metadata, err := doc.WriteToBytes()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return metadata, nil
}

func buildAttributes(t *testing.T, store *samlTestStore) []types.Attribute {
	t.Helper()

	if len(store.Attributes) == 0 {
		store.Attributes = map[string][]string{
			"id":        {store.Subject},
			"email":     {store.Subject[:8] + "@example.com"},
			"firstName": {"Test"},
			"lastName":  {"User"},
		}
	}

	attributes := make([]types.Attribute, 0, len(store.Attributes))
	for name, values := range store.Attributes {
		attr := types.Attribute{
			XMLName:      xml.Name{Space: samlAssertionNS, Local: "Attribute"},
			FriendlyName: name,
			Name:         name,
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:       make([]types.AttributeValue, 0, len(values)),
		}
		for _, v := range values {
			attr.Values = append(attr.Values, types.AttributeValue{
				XMLName: xml.Name{Space: samlAssertionNS, Local: "AttributeValue"},
				Type:    "xs:string",
				Value:   v,
			})
		}
		attributes = append(attributes, attr)
	}

	return attributes
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

func extractAssertionConsumerServiceURL(t *testing.T, xmlData string) (string, errors.E) {
	t.Helper()

	var req authnRequest
	err := xml.Unmarshal([]byte(xmlData), &req)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return req.AssertionConsumerServiceURL, nil
}

func decodeSAMLRequest(t *testing.T, encoded string) (string, errors.E) {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.WithStack(err)
	}

	reader := flate.NewReader(bytes.NewReader(raw))
	defer reader.Close()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return string(decoded), nil
}

func generateSignedSAMLResponse(t *testing.T, store *samlTestStore, requestID string, destination string) string {
	t.Helper()

	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.Add(5 * time.Minute)

	attributes := buildAttributes(t, store)

	samlRData := samlResponseData{
		ResponseID:   "_" + identifier.New().String(),
		AssertionID:  "_" + identifier.New().String(),
		InResponseTo: requestID,
		Destination:  destination,
		IssueInstant: now.Format(time.RFC3339Nano),
		NotBefore:    notBefore.Format(time.RFC3339),
		NotOnOrAfter: notAfter.Format(time.RFC3339),
		Issuer:       samlTestingEntityID,
		Audience:     samlTestingEntityID,
		Subject:      store.Subject,
		SessionIndex: "_" + identifier.New().String(),
		Attributes:   attributes,
	}

	samlRTemplate := samlResponseTemplate()
	var buf bytes.Buffer
	err := samlRTemplate.Execute(&buf, samlRData)
	require.NoError(t, err)

	doc := etree.NewDocument()
	err = doc.ReadFromBytes(buf.Bytes())
	require.NoError(t, err)

	signCtx := dsig.NewDefaultSigningContext(store.KeyStore)
	signCtx.Canonicalizer = dsig.MakeC14N10RecCanonicalizer()
	err = signCtx.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
	require.NoError(t, err)
	signedResponse, err := signCtx.SignEnveloped(doc.Root())
	require.NoError(t, err)

	signatureElement := signedResponse.FindElement("ds:Signature")
	signedResponse.InsertChildAt(2, signatureElement)
	signedResponse.RemoveChild(signatureElement)

	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(signedResponse)

	xmlBytes, err := signedDoc.WriteToBytes()
	xmlBytes = []byte(xml.Header + string(xmlBytes))
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(xmlBytes)
}

func startSAMLTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	store := &samlTestStore{
		// We use one unique subject per instance for testing.
		Subject:    identifier.New().String()[:8],
		Attributes: make(map[string][]string),
	}

	keyStore := dsig.RandomKeyStoreForTest()

	_, certBytes, err := keyStore.GetKeyPair()
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	store.KeyStore = keyStore

	mux := http.NewServeMux()

	// Mock metadata endpoint.
	mux.HandleFunc("/saml/metadata", func(w http.ResponseWriter, req *http.Request) {
		certBase64 := base64.StdEncoding.EncodeToString(cert.Raw)
		scheme := "http"
		host := req.Host
		metadata, errE := generateMetadata(t, certBase64, scheme, host)
		if errE != nil {
			http.Error(w, "samlTesting error in generating metadata", http.StatusInternalServerError)
		}

		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(metadata)
	})

	mux.HandleFunc("/saml/auth", func(w http.ResponseWriter, req *http.Request) {
		samlRequest := req.URL.Query().Get("SAMLRequest")
		relayState := req.URL.Query().Get("RelayState")

		if samlRequest == "" {
			http.Error(w, "samlTesting missing SAMLRequest parameter", http.StatusBadRequest)
			return
		}

		store.RelayState = relayState

		xmlData, err := decodeSAMLRequest(t, samlRequest)
		if err != nil {
			http.Error(w, "samlTesting error in decoding SAML request", http.StatusBadRequest)
			return
		}

		requestID := extractRequestID(t, xmlData)
		if requestID == "" {
			http.Error(w, "samlTesting missing request ID in SAML request", http.StatusBadRequest)
			return
		}

		callbackURL, errE := extractAssertionConsumerServiceURL(t, xmlData)
		if errE != nil || callbackURL == "" {
			http.Error(w, "samlTesting invalid assertion consumer service URL", http.StatusBadRequest)
			return
		}

		response := generateSignedSAMLResponse(t, store, requestID, callbackURL)

		htmlResponse := struct {
			CallbackURL  string
			SAMLResponse string
			RelayState   string
		}{
			CallbackURL:  callbackURL,
			SAMLResponse: response,
			RelayState:   relayState,
		}

		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		samlPostFormHTMLTemplate := samlPostFormTemplate()
		if err := samlPostFormHTMLTemplate.Execute(w, htmlResponse); err != nil {
			http.Error(w, "samlTesting failed to generate HTML response form", http.StatusInternalServerError)
			return
		}
	})

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts
}

func extractFormValues(t *testing.T, htmlStr string) (url.Values, string, errors.E) {
	t.Helper()

	values := url.Values{}

	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return nil, "", errors.WithStack(err)
	}

	var action string
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "form":
				for _, attr := range n.Attr {
					if attr.Key == "action" {
						action = attr.Val
					}
				}
			case "input":
				var name, value string
				var disabled bool
				for _, attr := range n.Attr {
					switch attr.Key {
					case "name":
						name = attr.Val
					case "value":
						value = attr.Val
					case "disabled":
						disabled = true
					}
				}
				if name != "" && !disabled {
					values.Add(name, value)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)

	return values, action, nil
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

	values, action, errE := extractFormValues(t, htmlStr)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.NotEmpty(t, values)
	require.NotEmpty(t, action)
	require.True(t, strings.HasPrefix(action, ts.URL), action)

	// Flow has not yet changed, current provider is testing.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{}, []charon.Provider{"samlTesting"}, "", assertCharonDashboard)
	}

	// Redirect to SAML callback.
	resp, err = ts.Client().Post(action, "application/x-www-form-urlencoded", strings.NewReader(values.Encode())) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, string(out))
	location := resp.Header.Get("Location")
	assert.NotEmpty(t, location)

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

func createMockSAMLClient(t *testing.T) *http.Client {
	t.Helper()

	client := cleanhttp.DefaultClient()

	// We do not follow redirects automatically.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return client
}

func mockSAMLSignin(t *testing.T, ts *httptest.Server, service *charon.Service, signinOrSignout charon.Completed) string {
	t.Helper()

	mockSAMLClient := createMockSAMLClient(t)

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
	require.True(t, strings.HasPrefix(authFlowResponse.ThirdPartyProvider.Location, "https://mocksaml.com/"), authFlowResponse.ThirdPartyProvider.Location)

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
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))

	location := resp.Header.Get("Location")
	require.NotEmpty(t, location, "Expected Location header in 302 response")
	locationURL, err := url.Parse(location)
	require.NoError(t, err)

	// MockSAML requires an email for authentication, which is not included in location.
	authPayload := map[string]interface{}{
		"email": "jackson@example.com",
	}
	for key, values := range locationURL.Query() {
		if len(values) > 0 {
			authPayload[key] = values[0]
		}
	}

	jsonPayload, errE := x.Marshal(authPayload)
	require.NoError(t, errE, "% -+#.1v", errE)

	// Call MockSAML auth endpoint.
	resp, err = mockSAMLClient.Post("https://mocksaml.com/api/namespace/charon/saml/auth", "application/json", bytes.NewReader(jsonPayload)) //nolint:noctx,bodyclose
	require.NoError(t, err)
	t.Cleanup(func(r *http.Response) func() { return func() { r.Body.Close() } }(resp))
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	htmlStr := string(out)
	assert.Equal(t, http.StatusOK, resp.StatusCode, htmlStr)

	values, action, errE := extractFormValues(t, htmlStr)
	require.NoError(t, errE, "% -+#.1v", errE)
	require.NotEmpty(t, values)
	require.NotEmpty(t, action)
	require.True(t, strings.HasPrefix(action, ts.URL), action)

	// Flow has not yet changed, current provider is mockSAML.
	resp, err = ts.Client().Get(ts.URL + authFlowGet) //nolint:noctx,bodyclose
	if assert.NoError(t, err) {
		assertFlowResponse(t, ts, service, resp, nil, []charon.Completed{}, []charon.Provider{"mockSAML"}, "", assertCharonDashboard)
	}

	// Redirect to SAML callback.
	resp, err = ts.Client().Post(action, "application/x-www-form-urlencoded", strings.NewReader(values.Encode())) //nolint:noctx,bodyclose
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
