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

// Ref returns a reference to the Charon organization.
func (c charonOrganization) Ref() OrganizationRef {
	return OrganizationRef{ID: c.ID}
}

func initCharonOrganization(ctx context.Context, config *Config, service *Service) (func() charonOrganization, errors.E) {
	return initWithHost(config, service.domain, func(host string) charonOrganization {
		// The base contains the service title so that the organization ID is deterministic: when state is persisted, a restart reuses
		// the existing organization instead of creating a new one, and persisted references to the organization stay valid across
		// restarts. Changing the title switches to a new organization.
		charonOrganizationBase := []string{service.domain, "ORGANIZATION", service.title}
		charonOrganizationID := identifier.From(charonOrganizationBase...)

		// In browsers, trailing slash is always added at the beginning of pathname, so we
		// do the same here to make sure redirect URIs match window.location.href in browsers.
		uri := "https://" + host + "/"

		// We populate the organization only if it does not already exist so that changes made to the stored organization are preserved.
		// All writers of the organizations store first wait for this initialization to complete, so checking outside of the write lock is safe.
		//
		// TODO: Update host-dependent fields in the stored organization when the host changes.
		//       The homepage and redirect URI templates contain the host, so when the domain or external port changes, a persisted organization
		//       keeps stale URIs and signing into the dashboard fails until the stored organization is updated or deleted.
		service.organizations.RLock()
		data, ok := service.organizations.Get(charonOrganizationID)
		service.organizations.RUnlock()
		if ok {
			var organization Organization
			errE := x.UnmarshalWithoutUnknownFields(data, &organization)
			if errE != nil {
				// Internal error: this should never happen.
				panic(errE)
			}
			app := organization.Applications[0]
			return charonOrganization{
				ID:                                charonOrganizationID,
				AppID:                             *app.ID,
				ClientID:                          *app.ClientsPublic[0].ID,
				ApplicationTemplateID:             *app.ApplicationTemplate.ID,
				ApplicationTemplateClientPublicID: *app.ApplicationTemplate.ClientsPublic[0].ID,
				RedirectURI:                       uri,
			}
		}

		charonAppBase := newChildBase(charonOrganizationBase, "ORGANIZATION_APPLICATION")()
		charonAppID := identifier.From(charonAppBase...)
		charonClientBase := newChildBase(charonAppBase, "ORGANIZATION_APPLICATION_CLIENT_PUBLIC")()
		charonClientID := identifier.From(charonClientBase...)
		charonApplicationTemplateBase := service.newBase("APPLICATION_TEMPLATE")()
		charonApplicationTemplateID := identifier.From(charonApplicationTemplateBase...)
		charonApplicationTemplateClientPublicBase := newChildBase(charonApplicationTemplateBase, "APPLICATION_TEMPLATE_CLIENT_PUBLIC")()
		charonApplicationTemplateClientPublicID := identifier.From(charonApplicationTemplateClientPublicBase...)

		refreshTokenLifespan := x.Duration(time.Hour * 24 * 30) //nolint:mnd

		organization := Organization{
			OrganizationPublic: OrganizationPublic{
				ID:          &charonOrganizationID,
				Base:        charonOrganizationBase,
				Name:        service.title,
				Description: "",
			},
			Admins: []IdentityRef{},
			Applications: []OrganizationApplication{
				{
					OrganizationApplicationPublic: OrganizationApplicationPublic{
						ID:     &charonAppID,
						Base:   charonAppBase,
						Active: true,
						ApplicationTemplate: ApplicationTemplatePublic{
							ID:               &charonApplicationTemplateID,
							Base:             charonApplicationTemplateBase,
							Name:             "Dashboard",
							Description:      "",
							HomepageTemplate: uri,
							IDScopes:         []string{"openid", "profile", "email"},
							Roles:            []Role{},
							Variables:        []Variable{},
							ClientsPublic: []ApplicationTemplateClientPublic{
								{
									ID:                   &charonApplicationTemplateClientPublicID,
									Base:                 charonApplicationTemplateClientPublicBase,
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
							ID:   &charonClientID,
							Base: charonClientBase,
							Client: ClientRef{
								ID: charonApplicationTemplateClientPublicID,
							},
						},
					},
					ClientsBackend: []OrganizationApplicationClientBackend{},
					ClientsService: []OrganizationApplicationClientService{},
				},
			},
			Roles:            nil,
			AllowedProviders: nil,
		}

		errE := organization.validate(ctx, &organization, service)
		if errE != nil {
			// Internal error: this should never happen.
			panic(errE)
		}

		data, errE = x.MarshalWithoutEscapeHTML(organization)
		if errE != nil {
			// Internal error: this should never happen.
			panic(errE)
		}

		service.organizations.Lock()
		defer service.organizations.Unlock()

		errE = service.organizations.Set(charonOrganizationID, data)
		if errE != nil {
			// We cannot do much about this error.
			panic(errE)
		}

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
