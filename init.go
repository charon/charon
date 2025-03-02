package charon

import (
	"context"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

type charonOrganization struct {
	ID                                identifier.Identifier
	ApplicationID                     identifier.Identifier
	ClientID                          identifier.Identifier
	ApplicationTemplateID             identifier.Identifier
	ApplicationTemplateClientPublicID identifier.Identifier
}

func initCharonOrganization(config *Config, service *Service, domain string) (func() charonOrganization, errors.E) {
	return initWithHost(config, domain, func(host string) charonOrganization {
		charonOrganizationID := identifier.New()
		charonApplicationID := identifier.New()
		charonClientID := identifier.New()
		charonApplicationTemplateID := identifier.New()
		charonApplicationTemplateClientPublicID := identifier.New()

		url := "https://" + host

		organization := Organization{
			OrganizationPublic: OrganizationPublic{
				ID:          &charonOrganizationID,
				Name:        "Charon",
				Description: "",
			},
			Admins: []IdentityRef{},
			Applications: []OrganizationApplication{
				{
					ID:     &charonApplicationID,
					Active: true,
					ApplicationTemplate: ApplicationTemplatePublic{
						ID:               &charonApplicationTemplateID,
						Name:             "Dashboard",
						Description:      "",
						HomepageTemplate: url,
						IDScopes:         []string{"openid", "profile", "email"},
						Variables:        []Variable{},
						ClientsPublic: []ApplicationTemplateClientPublic{
							{
								ID:                   &charonApplicationTemplateClientPublicID,
								Description:          "",
								AdditionalScopes:     []string{},
								RedirectURITemplates: []string{url},
							},
						},
						ClientsBackend: []ApplicationTemplateClientBackend{},
						ClientsService: []ApplicationTemplateClientService{},
					},
					Values: []Value{},
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

		errE := organization.Validate(context.Background(), &organization)
		if errE != nil {
			// This should never happen.
			panic(errE)
		}

		data, errE := x.MarshalWithoutEscapeHTML(organization)
		if errE != nil {
			// This should never happen.
			panic(errE)
		}

		service.organizationsMu.Lock()
		defer service.organizationsMu.Unlock()

		service.organizations[charonOrganizationID] = data

		return charonOrganization{
			ID:                                charonOrganizationID,
			ApplicationID:                     charonApplicationID,
			ClientID:                          charonClientID,
			ApplicationTemplateID:             charonApplicationTemplateID,
			ApplicationTemplateClientPublicID: charonApplicationTemplateClientPublicID,
		}
	})
}
