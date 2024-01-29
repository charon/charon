package charon

import (
	"net/http"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"gitlab.com/tozd/waf"
)

// TODO: Implement using fosite.
//       See: https://github.com/ory/fosite/issues/405

//nolint:tagliatelle
type wellKnown struct {
	// REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts as its
	// Issuer Identifier. If Issuer discovery is supported, this value MUST be identical to the issuer value
	// returned by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.
	Issuer string `json:"issuer"`

	// REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint.
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// URL of the OP's OAuth 2.0 Token Endpoint. This is REQUIRED unless only the Implicit Flow is used.
	TokenEndpoint string `json:"token_endpoint"`

	// RECOMMENDED. URL of the OP's UserInfo Endpoint. This URL MUST use the https scheme and MAY contain
	// port, path, and query parameter components.
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`

	// REQUIRED. URL of the OP's JSON Web Key Set document. This contains the signing key(s) the RP uses to
	// validate signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s), which are
	// used by RPs to encrypt requests to the Server. When both signing and encryption keys are made available,
	// a use (Key Use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's
	// intended usage. Although some algorithms allow the same key to be used for both signatures and encryption,
	// doing so is NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509
	// representations of keys provided. When used, the bare key values MUST still be present and MUST match
	// those in the certificate.
	JWKSURI string `json:"jwks_uri"`

	// RECOMMENDED. URL of the OP's Dynamic Client Registration Endpoint.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// RECOMMENDED. JSON array containing a list of the OAuth 2.0 scope values that this server supports.
	// The server MUST support the openid scope value. Servers MAY choose not to advertise some supported
	// scope values even when this parameter is used, although those defined SHOULD be listed, if supported.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports.
	// Dynamic OpenID Providers MUST support the code, id_token, and the token id_token Response Type values.
	ResponseTypesSupported []string `json:"response_types_supported"`

	// OPTIONAL. JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports,
	// as specified in OAuth 2.0 Multiple Response Type Encoding Practices. If omitted, the default for
	// Dynamic OpenID Providers is ["query", "fragment"].
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports. Dynamic
	// OpenID Providers MUST support the authorization_code and implicit Grant Type values and MAY support other
	// Grant Types. If omitted, the default value is ["authorization_code", "implicit"].
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the Authentication Context Class References that this OP supports.
	AcrValuesSupported []string `json:"acr_values_supported,omitempty"`

	// REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports.
	// Valid types include pairwise and public.
	SubjectTypesSupported []string `json:"subject_types_supported"`

	// REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the
	// ID Token to encode the Claims in a JWT. The algorithm RS256 MUST be included. The value none MAY be
	// supported, but MUST NOT be used unless the Response Type used returns no ID Token from the Authorization
	// Endpoint (such as when using the Authorization Code Flow).
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for
	// the ID Token to encode the Claims in a JWT.
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for
	// the ID Token to encode the Claims in a JWT.
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by
	// the UserInfo Endpoint to encode the Claims in a JWT. The value none MAY be included.
	UserinfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values)
	// supported by the UserInfo Endpoint to encode the Claims in a JWT.
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported
	// by the UserInfo Endpoint to encode the Claims in a JWT.
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP
	// for Request Objects, which are described in Section 6.1 of OpenID Connect Core 1.0.
	// These algorithms are used both when the Request Object is passed by value (using the request parameter)
	// and when it is passed by reference (using the request_uri parameter). Servers SHOULD support none and RS256.
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP
	// for Request Objects. These algorithms are used both when the Request Object is passed by value and when
	// it is passed by reference.
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for
	// Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of Client Authentication methods supported by this Token Endpoint.
	// The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described
	// in Section 9 of OpenID Connect Core 1.0. Other authentication methods MAY be defined by extensions.
	// If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Token
	// Endpoint for the signature on the JWT used to authenticate the Client at the Token Endpoint for the
	// private_key_jwt and client_secret_jwt authentication methods. Servers SHOULD support RS256. The value none MUST NOT be used.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports. These
	// values are described in Section 3.1.2.1 of OpenID Connect Core 1.0.
	DisplayValuesSupported []string `json:"display_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports. These Claim Types
	// are described in Section 5.6 of OpenID Connect Core 1.0. Values defined by this specification are
	// normal, aggregated, and distributed. If omitted, the implementation supports only normal Claims.
	ClaimTypesSupported []string `json:"claim_types_supported,omitempty"`

	// RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able
	// to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list.
	ClaimsSupported []string `json:"claims_supported,omitempty"`

	// OPTIONAL. URL of a page containing human-readable information that developers might want or need to know when
	// using the OpenID Provider. In particular, if the OpenID Provider does not support Dynamic Client Registration,
	// then information on how to register Clients needs to be provided in this documentation.
	ServiceDocumentation string `json:"service_documentation,omitempty"`

	// OPTIONAL. Languages and scripts supported for values in Claims being returned, represented as a JSON array of
	// BCP47 language tag values. Not all languages and scripts are necessarily supported for all Claim values.
	ClaimsLocalesSupported []string `json:"claims_locales_supported,omitempty"`

	// OPTIONAL. Languages and scripts supported for the user interface, represented as a JSON array of BCP47 language tag values.
	UILocalesSupported []string `json:"ui_locales_supported,omitempty"`

	// OPTIONAL. Boolean value specifying whether the OP supports use of the claims parameter, with true indicating support.
	// If omitted, the default value is false.
	ClaimsParameterSupported bool `json:"claims_parameter_supported"`

	// OPTIONAL. Boolean value specifying whether the OP supports use of the request parameter, with true indicating
	// support. If omitted, the default value is false.
	RequestParameterSupported bool `json:"request_parameter_supported"`

	// OPTIONAL. Boolean value specifying whether the OP supports use of the request_uri parameter, with true
	// indicating support. If omitted, the default value is true.
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`

	// OPTIONAL. Boolean value specifying whether the OP requires any request_uri values used to be pre-registered
	// using the request_uris registration parameter. Pre-registration is REQUIRED when the value is true. If
	// omitted, the default value is false.
	RequireRequestURIRegistration bool `json:"require_request_uri_registration"`

	// OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about the OP's
	// requirements on how the Relying Party can use the data provided by the OP. The registration process SHOULD
	// display this URL to the person registering the Client if it is given.
	OpPolicyURI string `json:"op_policy_uri,omitempty"`

	// OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about OpenID
	// Provider's terms of service. The registration process SHOULD display this URL to the person registering the Client if it is given.
	OpTosURI string `json:"op_tos_uri,omitempty"`

	// OPTIONAL. URL of the authorization server's OAuth 2.0 revocation endpoint.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// OPTIONAL. JSON array containing a list of client authentication methods supported by this revocation endpoint.
	// The valid client authentication method values are those registered in the IANA
	// "OAuth Token Endpoint Authentication Methods" registry. If omitted, the default is "client_secret_basic"
	// -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0.
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWS signing algorithms ("alg" values) supported by the
	// revocation endpoint for the signature on the JWT used to authenticate the client at
	// the revocation endpoint for the "private_key_jwt" and "client_secret_jwt" authentication methods.
	// This metadata entry MUST be present if either of these authentication methods are
	// specified in the "revocation_endpoint_auth_methods_supported" entry. No default algorithms are implied
	// if this entry is omitted. The value "none" MUST NOT be used.
	RevocationEndpointAuthSigningAlgValuesSupported []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`

	// OPTIONAL. URL of the authorization server's OAuth 2.0 introspection endpoint.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// OPTIONAL. JSON array containing a list of client authentication methods supported by this introspection endpoint.
	// The valid client authentication method values are those registered in the IANA "OAuth Token Endpoint
	// Authentication Methods" registry or those registered in the IANA "OAuth
	// Access Token Types" registry. (These values are and will remain distinct, due to
	// Section 7.2.) If omitted, the set of supported authentication methods MUST be determined by other means.
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWS signing algorithms ("alg" values) supported by the introspection
	// endpoint for the signature on the JWT used to authenticate the client at the introspection endpoint for
	// the "private_key_jwt" and "client_secret_jwt" authentication methods. This metadata entry
	// MUST be present if either of these authentication methods are specified in the "introspection_endpoint_auth_methods_supported"
	// entry. No default algorithms are implied if this entry is omitted. The value "none" MUST NOT be used.
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of Proof Key for Code Exchange (PKCE) code challenge methods
	// supported by this authorization server. Code challenge method values are used in the "code_challenge_method"
	// parameter defined in Section 4.3. The valid code challenge method values are those
	// registered in the IANA "PKCE Code Challenge Methods" registry. If omitted, the
	// authorization server does not support PKCE.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`

	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`
}

//nolint:gochecknoglobals
var (
	responseModesSupported        = []fosite.ResponseModeType{fosite.ResponseModeQuery, fosite.ResponseModeFragment, fosite.ResponseModeFormPost}
	responseModesSupportedStrings = []string{string(fosite.ResponseModeQuery), string(fosite.ResponseModeFragment), string(fosite.ResponseModeFormPost)}
	signingAlgValuesSupported     = []string{
		string(jose.RS256), string(jose.RS384), string(jose.RS512),
		string(jose.ES256), string(jose.ES384), string(jose.ES512),
		string(jose.PS256), string(jose.PS384), string(jose.PS512),
	}
)

// TODO: This JSON could be generated once and stored as []byte.

// oidcConfiguration provides discovery configuration.
func (s *Service) oidcConfiguration(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	oidc := s.oidc()
	issuer := oidc.Config.GetAccessTokenIssuer(ctx)

	authorizenPath, errE := s.Reverse("OIDCAuthorize", nil, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	tokenPath, errE := s.ReverseAPI("OIDCToken", nil, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	userinfoPath, errE := s.ReverseAPI("OIDCUserInfo", nil, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	keysPath, errE := s.Reverse("OIDCKeys", nil, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	revokePath, errE := s.ReverseAPI("OIDCRevoke", nil, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	introspectPath, errE := s.ReverseAPI("OIDCIntrospect", nil, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// TODO: Add OpPolicyURI.
	// TODO: Add OpTosURI.
	// TODO: Add EndSessionEndpoint.
	// TODO: Add ServiceDocumentation.
	// TODO: Can we support RegistrationEndpoint?
	response := wellKnown{ //nolint:exhaustruct
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + authorizenPath,
		TokenEndpoint:         issuer + tokenPath,
		UserinfoEndpoint:      issuer + userinfoPath,
		JWKSURI:               issuer + keysPath,
		// TODO: Extend ScopesSupported with common scopes across all apps.
		ScopesSupported:        []string{"openid", "offline_access"},
		ResponseTypesSupported: []string{"id_token", "code", "code id_token"},
		ResponseModesSupported: responseModesSupportedStrings,
		GrantTypesSupported:    []string{"client_credentials", "authorization_code", "refresh_token"},
		// We do not use pairwise type because we use unique subject identifiers per organization, not per app/client,
		// so we list "public" here instead of "pairwise".
		SubjectTypesSupported: []string{"public"},
		// TODO: Implement support and add all from signingAlgValuesSupported.
		//       See: https://github.com/ory/fosite/issues/788
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		// TODO: Implement support and add all from signingAlgValuesSupported.
		UserinfoSigningAlgValuesSupported: []string{"none"},
		// We do not really care how the request object is signed, so we support anything fosite does.
		RequestObjectSigningAlgValuesSupported:     append([]string{"none"}, signingAlgValuesSupported...),
		TokenEndpointAuthMethodsSupported:          []string{"none", "client_secret_post", "client_secret_basic", "private_key_jwt"},
		TokenEndpointAuthSigningAlgValuesSupported: signingAlgValuesSupported,
		DisplayValuesSupported:                     []string{"page"},
		ClaimTypesSupported:                        []string{"normal"},
		// TODO: Extend ClaimsSupported with common scopes across all apps.
		ClaimsSupported:           []string{},
		ClaimsParameterSupported:  false,
		RequestParameterSupported: true,
		// Fosite supports request URIs by allowlisting them, but we currently do not support allowlisting
		// URIs for clients thus effectively disabling request URIs.
		RequestURIParameterSupported: false,
		// We require allowlisted request URIs (but we do not provide any means to register them,
		// nor we have a registration endpoint).
		RequireRequestURIRegistration:                   true,
		RevocationEndpoint:                              issuer + revokePath,
		RevocationEndpointAuthMethodsSupported:          []string{"none", "client_secret_post", "client_secret_basic", "private_key_jwt"},
		RevocationEndpointAuthSigningAlgValuesSupported: signingAlgValuesSupported,
		IntrospectionEndpoint:                           issuer + introspectPath,
		// TODO: Add "private_key_jwt" and "client_secret_post" once supported.
		//       See: https://github.com/ory/fosite/issues/447
		IntrospectionEndpointAuthMethodsSupported: []string{"bearer", "client_secret_basic"},
		// TODO: Use signingAlgValuesSupported once "private_key_jwt" is supported.
		IntrospectionEndpointAuthSigningAlgValuesSupported: []string{},
		CodeChallengeMethodsSupported:                      []string{"S256"},
	}

	s.WriteJSON(w, req, response, nil)
}

func (s *Service) OIDCConfiguration1(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	s.oidcConfiguration(w, req)
}

func (s *Service) OIDCConfiguration2(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	s.oidcConfiguration(w, req)
}
