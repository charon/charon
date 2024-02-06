package charon

import (
	"context"
	"slices"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

var ErrClientNotFound = errors.Base("client not found")

type OIDCStore struct {
	storage.MemoryStore
}

func NewOIDCStore() *OIDCStore {
	return &OIDCStore{
		MemoryStore: *storage.NewMemoryStore(),
	}
}

func (s *OIDCStore) GetClient(_ context.Context, strID string) (fosite.Client, error) { //nolint:ireturn
	id, errE := identifier.FromString(strID)
	if errE != nil {
		return nil, errE
	}

	organizationsMu.RLock()
	defer organizationsMu.RUnlock()

	for orgID, data := range organizations {
		var organization Organization
		errE := x.UnmarshalWithoutUnknownFields(data, &organization)
		if errE != nil {
			errors.Details(errE)["id"] = orgID
			return nil, errE
		}

		for _, app := range organization.Applications {
			if !app.Active {
				continue
			}

			clientPublic := app.GetClientPublic(id)
			if clientPublic != nil {
				// We should always find template client because we check for this during validation.
				templateClientPublic := app.ApplicationTemplate.GetClientPublic(id)

				scopes := slices.Clone(app.ApplicationTemplate.IDScopes)
				scopes = append(scopes, templateClientPublic.AdditionalScopes...)
				slices.Sort(scopes)
				slices.Compact(scopes)

				values := map[string]string{}
				for _, value := range app.Values {
					values[value.Name] = value.Value
				}

				redirectURIs := []string{}
				for _, template := range templateClientPublic.RedirectURITemplates {
					redirectURI, errE := interpolateVariables(template, values)
					if errE != nil {
						// This should not happen. We have validated it.
						errors.Details(errE)["template"] = template
						return nil, errE
					}
					redirectURIs = append(redirectURIs, redirectURI)
				}

				slices.Sort(redirectURIs)
				slices.Compact(redirectURIs)

				return &OIDCClient{
					ID:                      id,
					AppID:                   *app.ID,
					Type:                    ClientPublic,
					TokenEndpointAuthMethod: "none",
					Scopes:                  scopes,
					RedirectURIs:            redirectURIs,
					Secret:                  nil,
				}, nil
			}

			clientBackend := app.GetClientBackend(id)
			if clientBackend != nil {
				// We should always find template client because we check for this during validation.
				templateClientBackend := app.ApplicationTemplate.GetClientBackend(id)

				scopes := slices.Clone(app.ApplicationTemplate.IDScopes)
				scopes = append(scopes, templateClientBackend.AdditionalScopes...)
				slices.Sort(scopes)
				slices.Compact(scopes)

				values := map[string]string{}
				for _, value := range app.Values {
					values[value.Name] = value.Value
				}

				redirectURIs := []string{}
				for _, template := range templateClientBackend.RedirectURITemplates {
					redirectURI, errE := interpolateVariables(template, values)
					if errE != nil {
						// This should not happen. We have validated it.
						errors.Details(errE)["template"] = template
						return nil, errE
					}
					redirectURIs = append(redirectURIs, redirectURI)
				}

				slices.Sort(redirectURIs)
				slices.Compact(redirectURIs)

				return &OIDCClient{
					ID:                      id,
					AppID:                   *app.ID,
					Type:                    ClientBackend,
					TokenEndpointAuthMethod: templateClientBackend.TokenEndpointAuthMethod,
					Scopes:                  scopes,
					RedirectURIs:            redirectURIs,
					Secret:                  []byte(clientBackend.Secret),
				}, nil
			}

			clientService := app.GetClientService(id)
			if clientService != nil {
				// We should always find template client because we check for this during validation.
				templateClientService := app.ApplicationTemplate.GetClientService(id)

				scopes := slices.Clone(app.ApplicationTemplate.IDScopes)
				scopes = append(scopes, templateClientService.AdditionalScopes...)
				slices.Sort(scopes)
				slices.Compact(scopes)

				values := map[string]string{}
				for _, value := range app.Values {
					values[value.Name] = value.Value
				}

				return &OIDCClient{
					ID:                      id,
					AppID:                   *app.ID,
					Type:                    ClientService,
					TokenEndpointAuthMethod: templateClientService.TokenEndpointAuthMethod,
					Scopes:                  scopes,
					RedirectURIs:            nil,
					Secret:                  []byte(clientService.Secret),
				}, nil
			}
		}
	}

	return nil, errors.WithDetails(ErrClientNotFound, "id", id)
}
