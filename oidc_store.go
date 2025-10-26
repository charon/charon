package charon

import (
	"context"
	"slices"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

var ErrClientNotFound = errors.Base("client not found")

type oidcMemoryStore struct {
	storage.MemoryStore
}

func newOIDCStore() *oidcMemoryStore {
	return &oidcMemoryStore{
		MemoryStore: *storage.NewMemoryStore(),
	}
}

// GetClient requires ctx with serviceContextKey set.
func (s *oidcMemoryStore) GetClient(ctx context.Context, strID string) (fosite.Client, error) { //nolint:ireturn
	id, errE := identifier.MaybeString(strID)
	if errE != nil {
		return nil, errE
	}

	service := ctx.Value(serviceContextKey).(*Service) //nolint:forcetypeassert,errcheck

	service.organizationsMu.RLock()
	defer service.organizationsMu.RUnlock()

	for orgID, data := range service.organizations {
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

			clientPublic := app.GetClientPublic(&id)
			if clientPublic != nil {
				// We should always find template client because we check for this during validation.
				templateClientPublic := app.ApplicationTemplate.GetClientPublic(&clientPublic.Client.ID)

				scopes := slices.Clone(app.ApplicationTemplate.IDScopes)
				scopes = append(scopes, templateClientPublic.AdditionalScopes...)
				slices.Sort(scopes)
				scopes = slices.Compact(scopes)

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
				redirectURIs = slices.Compact(redirectURIs)

				return &OIDCClient{
					ID:                      id,
					OrganizationID:          *organization.ID,
					AppID:                   *app.ID,
					Type:                    ClientPublic,
					AccessTokenType:         templateClientPublic.AccessTokenType,
					TokenEndpointAuthMethod: "none",
					Scopes:                  scopes,
					RedirectURIs:            redirectURIs,
					Secret:                  nil,
					AccessTokenLifespan:     templateClientPublic.AccessTokenLifespan,
					IDTokenLifespan:         templateClientPublic.IDTokenLifespan,
					RefreshTokenLifespan:    templateClientPublic.RefreshTokenLifespan,
				}, nil
			}

			clientBackend := app.GetClientBackend(&id)
			if clientBackend != nil {
				// We should always find template client because we check for this during validation.
				templateClientBackend := app.ApplicationTemplate.GetClientBackend(&clientBackend.Client.ID)

				scopes := slices.Clone(app.ApplicationTemplate.IDScopes)
				scopes = append(scopes, templateClientBackend.AdditionalScopes...)
				slices.Sort(scopes)
				scopes = slices.Compact(scopes)

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
				redirectURIs = slices.Compact(redirectURIs)

				return &OIDCClient{
					ID:                      id,
					OrganizationID:          *organization.ID,
					AppID:                   *app.ID,
					Type:                    ClientBackend,
					AccessTokenType:         templateClientBackend.AccessTokenType,
					TokenEndpointAuthMethod: templateClientBackend.TokenEndpointAuthMethod,
					Scopes:                  scopes,
					RedirectURIs:            redirectURIs,
					Secret:                  []byte(clientBackend.Secret),
					AccessTokenLifespan:     templateClientBackend.AccessTokenLifespan,
					IDTokenLifespan:         templateClientBackend.IDTokenLifespan,
					RefreshTokenLifespan:    templateClientBackend.RefreshTokenLifespan,
				}, nil
			}

			clientService := app.GetClientService(&id)
			if clientService != nil {
				// We should always find template client because we check for this during validation.
				templateClientService := app.ApplicationTemplate.GetClientService(&clientService.Client.ID)

				scopes := slices.Clone(app.ApplicationTemplate.IDScopes)
				scopes = append(scopes, templateClientService.AdditionalScopes...)
				slices.Sort(scopes)
				scopes = slices.Compact(scopes)

				return &OIDCClient{
					ID:                      id,
					OrganizationID:          *organization.ID,
					AppID:                   *app.ID,
					Type:                    ClientService,
					AccessTokenType:         templateClientService.AccessTokenType,
					TokenEndpointAuthMethod: templateClientService.TokenEndpointAuthMethod,
					Scopes:                  scopes,
					RedirectURIs:            nil,
					Secret:                  []byte(clientService.Secret),
					AccessTokenLifespan:     templateClientService.AccessTokenLifespan,
					IDTokenLifespan:         templateClientService.IDTokenLifespan,
					RefreshTokenLifespan:    templateClientService.RefreshTokenLifespan,
				}, nil
			}
		}
	}

	return nil, errors.WithDetails(ErrClientNotFound, "id", id)
}

func (s *oidcMemoryStore) CreateOpenIDConnectSession(ctx context.Context, code string, req fosite.Requester) error {
	// Use our identifiers if ID is the default is UUID ID (which contains "-" in its string representation).
	// Here we check that we successfully set ID to our own ID generation and panic if not.
	// TODO: Find a better way to override ID generator in accessRequest.GetID.
	if strings.Contains(req.GetID(), "-") {
		panic(errors.New("default ID generation has been used"))
	}
	return s.MemoryStore.CreateOpenIDConnectSession(ctx, code, req) //nolint:wrapcheck
}

func (s *oidcMemoryStore) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	// Use our identifiers if ID is the default is UUID ID (which contains "-" in its string representation).
	// Here we check that we successfully set ID to our own ID generation and panic if not.
	// TODO: Find a better way to override ID generator in accessRequest.GetID.
	if strings.Contains(req.GetID(), "-") {
		panic(errors.New("default ID generation has been used"))
	}
	return s.MemoryStore.CreateAuthorizeCodeSession(ctx, code, req) //nolint:wrapcheck
}

func (s *oidcMemoryStore) CreatePKCERequestSession(ctx context.Context, code string, req fosite.Requester) error {
	// Use our identifiers if ID is the default is UUID ID (which contains "-" in its string representation).
	// Here we check that we successfully set ID to our own ID generation and panic if not.
	// TODO: Find a better way to override ID generator in accessRequest.GetID.
	if strings.Contains(req.GetID(), "-") {
		panic(errors.New("default ID generation has been used"))
	}
	return s.MemoryStore.CreatePKCERequestSession(ctx, code, req) //nolint:wrapcheck
}

func (s *oidcMemoryStore) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	// Use our identifiers if ID is the default is UUID ID (which contains "-" in its string representation).
	// Here we check that we successfully set ID to our own ID generation and panic if not.
	// TODO: Find a better way to override ID generator in accessRequest.GetID.
	if strings.Contains(req.GetID(), "-") {
		panic(errors.New("default ID generation has been used"))
	}
	return s.MemoryStore.CreateAccessTokenSession(ctx, signature, req) //nolint:wrapcheck
}

func (s *oidcMemoryStore) CreateRefreshTokenSession(ctx context.Context, signature, accessTokenSignature string, req fosite.Requester) error {
	// Use our identifiers if ID is the default is UUID ID (which contains "-" in its string representation).
	// Here we check that we successfully set ID to our own ID generation and panic if not.
	// TODO: Find a better way to override ID generator in accessRequest.GetID.
	if strings.Contains(req.GetID(), "-") {
		panic(errors.New("default ID generation has been used"))
	}
	return s.MemoryStore.CreateRefreshTokenSession(ctx, signature, accessTokenSignature, req) //nolint:wrapcheck
}
