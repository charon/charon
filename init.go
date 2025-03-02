package charon

import (
	"context"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

//nolint:gochecknoglobals
var (
	// TODO: Generate random ones at initial run of Charon so that each Charon instance has different IDs.
	charonOrganizationID                    = identifier.MustFromString("TCD1UhKfBDewGv2TgPnFsX")
	charonAppID                             = identifier.MustFromString("8sWLA74HFfjdaeQPHJ5GS8")
	charonClientID                          = identifier.MustFromString("MWsRw9LcyggooUPHTpp5Jd")
	charonApplicationTemplateID             = identifier.MustFromString("P9s5Ybwb7K6wMJAdzta5wq")
	charonApplicationTemplateClientPublicID = identifier.MustFromString("Y6FAGc9DHiECGRJb4ML8zN")
)

// TODO: Return random IDs instead of an empty struct and expose them to the frontend.
func initCharonOrganization(config *Config, domain string) (func() struct{}, errors.E) {
	return initWithHost(config, domain, func(host string) struct{} {
		organization := Organization{
			OrganizationPublic: OrganizationPublic{
				ID:          &charonOrganizationID,
				Name:        "Charon",
				Description: "",
			},
			Admins: []IdentityRef{},
			Applications: []OrganizationApplication{
				{
					ID:     &charonAppID,
					Active: true,
					ApplicationTemplate: ApplicationTemplatePublic{
						ID:               &charonApplicationTemplateID,
						Name:             "Dashboard",
						Description:      "",
						HomepageTemplate: "https://gitlab.com/charon/charon",
						IDScopes:         []string{"openid", "profile", "email"},
						Variables:        []Variable{},
						ClientsPublic: []ApplicationTemplateClientPublic{
							{
								ID:                   &charonApplicationTemplateClientPublicID,
								Description:          "",
								AdditionalScopes:     []string{},
								RedirectURITemplates: []string{host},
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

		organizationsMu.Lock()
		defer organizationsMu.Unlock()

		organizations[charonOrganizationID] = data

		return struct{}{}
	})
}
