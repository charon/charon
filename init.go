package charon

import (
	"context"
	"time"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

type charonOrganization struct {
	ID                                identifier.Identifier
	AppID                             identifier.Identifier
	ClientID                          identifier.Identifier
	ApplicationTemplateID             identifier.Identifier
	ApplicationTemplateClientPublicID identifier.Identifier
	RedirectURI                       string
}

func initCharonOrganization(config *Config, service *Service, domain string) (func() charonOrganization, errors.E) {
	return initWithHost(config, domain, func(host string) charonOrganization {
		charonOrganizationID := identifier.New()
		charonAppID := identifier.New()
		charonClientID := identifier.New()
		charonApplicationTemplateID := identifier.New()
		charonApplicationTemplateClientPublicID := identifier.New()

		// In browsers, trailing slash is always added at the beginning of pathname, so we
		// do the same here to make sure redirect URIs match window.location.href in browsers.
		uri := "https://" + host + "/"

		refreshTokenLifespan := x.Duration(time.Hour * 24 * 30) //nolint:mnd

		organization := Organization{
			OrganizationPublic: OrganizationPublic{
				ID:          &charonOrganizationID,
				Name:        "Charon",
				Description: "",
			},
			Admins: []IdentityRef{},
			Applications: []OrganizationApplication{
				{
					OrganizationApplicationPublic: OrganizationApplicationPublic{
						ID:     &charonAppID,
						Active: true,
						ApplicationTemplate: ApplicationTemplatePublic{
							ID:               &charonApplicationTemplateID,
							Name:             "Dashboard",
							Description:      "",
							HomepageTemplate: uri,
							IDScopes:         []string{"openid", "profile", "email"},
							Variables:        []Variable{},
							ClientsPublic: []ApplicationTemplateClientPublic{
								{
									ID:                   &charonApplicationTemplateClientPublicID,
									Description:          "",
									AdditionalScopes:     []string{},
									RedirectURITemplates: []string{uri},
									AccessTokenType:      AccessTokenHMAC,

									// TODO: Configure lifespans based on what frontend expects.
									AccessTokenLifespan:  x.Duration(time.Hour),
									IDTokenLifespan:      x.Duration(time.Hour),
									RefreshTokenLifespan: &refreshTokenLifespan,
								},
							},
							ClientsBackend: []ApplicationTemplateClientBackend{},
							ClientsService: []ApplicationTemplateClientService{},
						},
						Values: []Value{},
					},
					ClientsPublic: []OrganizationApplicationClientPublic{
						{
							ID: &charonClientID,
							Client: ClientRef{
								ID: charonApplicationTemplateClientPublicID,
							},
						},
					},
					ClientsBackend: []OrganizationApplicationClientBackend{},
					ClientsService: []OrganizationApplicationClientService{},
				},
			},
		}

		errE := organization.validate(context.Background(), &organization, service)
		if errE != nil {
			// Internal error: this should never happen.
			panic(errE)
		}

		data, errE := x.MarshalWithoutEscapeHTML(organization)
		if errE != nil {
			// Internal error: this should never happen.
			panic(errE)
		}

		service.organizationsMu.Lock()
		defer service.organizationsMu.Unlock()

		service.organizations[charonOrganizationID] = data

		return charonOrganization{
			ID:                                charonOrganizationID,
			AppID:                             charonAppID,
			ClientID:                          charonClientID,
			ApplicationTemplateID:             charonApplicationTemplateID,
			ApplicationTemplateClientPublicID: charonApplicationTemplateClientPublicID,
			RedirectURI:                       uri,
		}
	})
}
