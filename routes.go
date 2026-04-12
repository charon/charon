package charon

import (
	"net/http"

	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

const corsMaxAge = 600

func (s *Service) setRoutes() { //nolint:maintidx
	s.Routes = map[string]waf.Route{
		"Home": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.HomeGet,
				},
			},
			Path: "/",
		},
		"License": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.LicenseGet,
				},
			},
			Path: "/LICENSE",
		},
		"Notice": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.NoticeGet,
				},
			},
			Path: "/NOTICE",
		},
		"Context": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.ContextGet,
				},
			},
			Path: "/context.json",
		},
		"OIDCAuthorize": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OIDCAuthorizeGet,
				},
			},
			Path: "/auth/oidc/authorize",
		},
		"OIDCToken": {
			Path: "/auth/oidc/token",
			API: waf.RouteOptions{
				CORS: &waf.CORSOptions{
					AllowedOrigins: []string{"*"},
					AllowedMethods: []string{"POST"},
					AllowedHeaders: []string{"Authorization"},
					MaxAge:         corsMaxAge,
				},
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.OIDCTokenPostAPI,
				},
			},
		},
		"OIDCRevoke": {
			Path: "/auth/oidc/revoke",
			API: waf.RouteOptions{
				CORS: &waf.CORSOptions{
					AllowedOrigins: []string{"*"},
					AllowedMethods: []string{"POST"},
					AllowedHeaders: []string{"Authorization"},
					MaxAge:         corsMaxAge,
				},
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.OIDCRevokePostAPI,
				},
			},
		},
		"OIDCIntrospect": {
			Path: "/auth/oidc/introspect",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.OIDCIntrospectPostAPI,
				},
			},
		},
		"OIDCUserInfo": {
			Path: "/auth/oidc/userinfo",
			API: waf.RouteOptions{
				CORS: &waf.CORSOptions{
					AllowedOrigins: []string{"*"},
					AllowedMethods: []string{"GET", "HEAD", "POST"},
					AllowedHeaders: []string{"Authorization"},
					MaxAge:         corsMaxAge,
				},
				Handlers: map[string]waf.Handler{
					http.MethodGet:  s.OIDCUserInfoGetAPI,
					http.MethodPost: s.OIDCUserInfoPostAPI,
				},
			},
		},
		"OIDCKeys": {
			RouteOptions: waf.RouteOptions{
				CORS: &waf.CORSOptions{
					AllowedOrigins: []string{"*"},
					AllowedMethods: []string{"GET", "HEAD"},
					MaxAge:         corsMaxAge,
				},
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OIDCKeysGet,
				},
			},
			Path: "/.well-known/jwks.json",
		},
		"OIDCDiscovery1": {
			RouteOptions: waf.RouteOptions{
				CORS: &waf.CORSOptions{
					AllowedOrigins: []string{"*"},
					AllowedMethods: []string{"GET", "HEAD"},
					MaxAge:         corsMaxAge,
				},
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OIDCDiscovery1Get,
				},
			},
			Path: "/.well-known/oauth-authorization-server",
		},
		"OIDCDiscovery2": {
			RouteOptions: waf.RouteOptions{
				CORS: &waf.CORSOptions{
					AllowedOrigins: []string{"*"},
					AllowedMethods: []string{"GET", "HEAD"},
					MaxAge:         corsMaxAge,
				},
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OIDCDiscovery2Get,
				},
			},
			Path: "/.well-known/openid-configuration",
		},
		"AuthSignout": {
			Path: "/auth/signout",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthSignoutPostAPI,
				},
			},
		},
		"AuthThirdPartyProvider": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.AuthThirdPartyProviderGet,
					// This is an exception. SAML makes a POST to user-facing URL so we do not want to use /api here.
					http.MethodPost: s.AuthThirdPartyProviderPost,
				},
			},
			Path: "/auth/provider/:provider",
		},
		"AuthFlowThirdPartyProviderStart": {
			Path: "/auth/providerStart/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthFlowThirdPartyProviderStartPostAPI,
				},
			},
		},
		"AuthFlowPasskeyGetStart": {
			Path: "/auth/passkeyGetStart/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthFlowPasskeyGetStartPostAPI,
				},
			},
		},
		"AuthFlowPasskeyGetComplete": {
			Path: "/auth/passkeyGetComplete/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthFlowPasskeyGetCompletePostAPI,
				},
			},
		},
		"AuthFlowPasskeyCreateStart": {
			Path: "/auth/passkeyCreateStart/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthFlowPasskeyCreateStartPostAPI,
				},
			},
		},
		"AuthFlowPasskeyCreateComplete": {
			Path: "/auth/passkeyCreateComplete/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthFlowPasskeyCreateCompletePostAPI,
				},
			},
		},
		"AuthFlowPasswordStart": {
			Path: "/auth/passwordStart/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthFlowPasswordStartPostAPI,
				},
			},
		},
		"AuthFlowPasswordComplete": {
			Path: "/auth/passwordComplete/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthFlowPasswordCompletePostAPI,
				},
			},
		},
		"AuthFlowCodeStart": {
			Path: "/auth/codeStart/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthFlowCodeStartPostAPI,
				},
			},
		},
		"AuthFlowCodeComplete": {
			Path: "/auth/codeComplete/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthFlowCodeCompletePostAPI,
				},
			},
		},
		"AuthFlowRestartAuth": {
			Path: "/auth/restartAuth/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthFlowRestartAuthPostAPI,
				},
			},
		},
		"AuthFlowDecline": {
			Path: "/auth/decline/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthFlowDeclinePostAPI,
				},
			},
		},
		"AuthFlowChooseIdentity": {
			Path: "/auth/chooseIdentity/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthFlowChooseIdentityPostAPI,
				},
			},
		},
		"AuthFlowRedirect": {
			Path: "/auth/redirect/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.AuthFlowRedirectPostAPI,
				},
			},
		},
		"AuthFlowGet": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.AuthFlowGetGet,
				},
			},
			Path: "/auth/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.AuthFlowGetGetAPI,
				},
			},
		},
		"ApplicationTemplateList": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.ApplicationTemplateListGet,
				},
			},
			Path: "/a",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.ApplicationTemplateListGetAPI,
				},
			},
		},
		"ApplicationTemplateCreate": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.ApplicationTemplateCreateGet,
				},
			},
			Path: "/a/create",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.ApplicationTemplateCreatePostAPI,
				},
			},
		},
		"ApplicationTemplateGet": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.ApplicationTemplateGet,
				},
			},
			Path: "/a/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.ApplicationTemplateGetGetAPI,
				},
			},
		},
		"ApplicationTemplateUpdate": {
			Path: "/a/update/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.ApplicationTemplateUpdatePostAPI,
				},
			},
		},
		"OrganizationList": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationListGet,
				},
			},
			Path: "/o",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationListGetAPI,
				},
			},
		},
		"OrganizationCreate": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationCreateGet,
				},
			},
			Path: "/o/create",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.OrganizationCreatePostAPI,
				},
			},
		},
		"OrganizationGet": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationGetGet,
				},
			},
			Path: "/o/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationGetGetAPI,
				},
			},
		},
		"OrganizationUpdate": {
			Path: "/o/update/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.OrganizationUpdatePostAPI,
				},
			},
		},
		"OrganizationApp": {
			Path: "/o/app/:id/:appId",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationAppGetAPI,
				},
			},
		},
		"OrganizationIdentity": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationIdentityGet,
				},
			},
			Path: "/o/identity/:id/:identityId",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationIdentityGetAPI,
				},
			},
		},
		"OrganizationUsers": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationUsersGet,
				},
			},
			Path: "/o/users/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationUsersGetAPI,
				},
			},
		},
		"OrganizationBlockUser": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationBlockUserGet,
				},
			},
			Path: "/o/block/:id/:identityId",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.OrganizationBlockUserPostAPI,
				},
			},
		},
		"OrganizationBlockedStatus": {
			Path: "/o/blocked/:id/:identityId",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationBlockedStatusGetAPI,
				},
			},
		},
		"OrganizationActivity": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationActivityGet,
				},
			},
			Path: "/o/activity/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationActivityGetAPI,
				},
			},
		},
		"OrganizationActivityGet": {
			Path: "/o/activity/:id/:activityId",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.OrganizationActivityGetGetAPI,
				},
			},
		},
		"ActivityList": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.ActivityListGet,
				},
			},
			Path: "/activity",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.ActivityListGetAPI,
				},
			},
		},
		"ActivityGet": {
			Path: "/activity/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.ActivityGetGetAPI,
				},
			},
		},
		"IdentityList": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.IdentityListGet,
				},
			},
			Path: "/i",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.IdentityListGetAPI,
				},
			},
		},
		"IdentityCreate": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.IdentityCreateGet,
				},
			},
			Path: "/i/create",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.IdentityCreatePostAPI,
				},
			},
		},
		"IdentityGet": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.IdentityGetGet,
				},
			},
			Path: "/i/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.IdentityGetGetAPI,
				},
			},
		},
		"IdentityUpdate": {
			Path: "/i/update/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.IdentityUpdatePostAPI,
				},
			},
		},
		"SAMLMetadata": {
			Path: "/samlMetadata/:provider",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.SAMLMetadataGetAPI,
				},
			},
		},
		"CredentialList": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.CredentialListGet,
				},
			},
			Path: "/authentication",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.CredentialListGetAPI,
				},
			},
		},
		"CredentialAdd": {
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.CredentialAddGet,
				},
			},
			Path: "/authentication/add",
		},
		"CredentialAddEmail": {
			Path: "/authentication/emailAdd",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.CredentialAddEmailPostAPI,
				},
			},
		},
		"CredentialAddUsername": {
			Path: "/authentication/usernameAdd",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.CredentialAddUsernamePostAPI,
				},
			},
		},
		"CredentialAddPasswordStart": {
			Path: "/authentication/passwordAddStart",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.CredentialAddPasswordStartPostAPI,
				},
			},
		},
		"CredentialAddPasswordComplete": {
			Path: "/authentication/passwordAddComplete",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.CredentialAddPasswordCompletePostAPI,
				},
			},
		},
		"CredentialAddPasskeyStart": {
			Path: "/authentication/passkeyAddStart",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.CredentialAddPasskeyStartPostAPI,
				},
			},
		},
		"CredentialAddPasskeyComplete": {
			Path: "/authentication/passkeyAddComplete",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.CredentialAddPasskeyCompletePostAPI,
				},
			},
		},
		"CredentialRemove": {
			Path: "/authentication/remove/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.CredentialRemovePostAPI,
				},
			},
		},
		"CredentialRename": {
			Path: "/authentication/rename/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodPost: s.CredentialRenamePostAPI,
				},
			},
		},
		"CredentialGet": {
			Path: "/authentication/:id",
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.CredentialGetGetAPI,
				},
			},
		},
	}

	if s.termsOfService != nil {
		// TODO: This is just temporary. Once we have PeerDB as backend we should just create PeerDB documents with these during populate.
		termsOfServicePageID := identifier.From(s.domain, "PAGE", "TERMS_OF_SERVICE")

		s.Routes["TermsOfService"] = waf.Route{
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.TermsOfServiceGet,
				},
			},
			Path: "/d/" + termsOfServicePageID.String(),
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.TermsOfServiceGetAPI,
				},
			},
		}
	}

	if s.privacyPolicy != nil {
		// TODO: This is just temporary. Once we have PeerDB as backend we should just create PeerDB documents with these during populate.
		privacyPolicyPageID := identifier.From(s.domain, "PAGE", "PRIVACY_POLICY")

		s.Routes["PrivacyPolicy"] = waf.Route{
			RouteOptions: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.PrivacyPolicyGet,
				},
			},
			Path: "/d/" + privacyPolicyPageID.String(),
			API: waf.RouteOptions{
				Handlers: map[string]waf.Handler{
					http.MethodGet: s.PrivacyPolicyGetAPI,
				},
			},
		}
	}
}
