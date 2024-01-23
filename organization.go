package charon

import (
	"context"
	"io"
	"net/http"
	"slices"
	"sync"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

var (
	ErrOrganizationNotFound     = errors.Base("organization not found")
	ErrOrganizationUnauthorized = errors.Base("organization change unauthorized")
)

var (
	organizations   = make(map[identifier.Identifier][]byte) //nolint:gochecknoglobals
	organizationsMu = sync.RWMutex{}                         //nolint:gochecknoglobals
)

type Organization struct {
	ID identifier.Identifier

	Admins []identifier.Identifier

	Name    string
	Members []identifier.Identifier
}

func GetOrganization(ctx context.Context, id identifier.Identifier) (*Organization, errors.E) { //nolint:revive
	organizationsMu.RLock()
	defer organizationsMu.RUnlock()

	data, ok := organizations[id]
	if !ok {
		return nil, errors.WithDetails(ErrOrganizationNotFound, "id", id)
	}
	var organization Organization
	errE := x.UnmarshalWithoutUnknownFields(data, &organization)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, errE
	}
	return &organization, nil
}

func SetOrganization(ctx context.Context, organization *Organization) errors.E { //nolint:revive
	data, errE := x.MarshalWithoutEscapeHTML(organization)
	if errE != nil {
		errors.Details(errE)["id"] = organization.ID
		return errE
	}

	organizationsMu.Lock()
	defer organizationsMu.Unlock()

	organizations[organization.ID] = data
	return nil
}

func UpsertOrganization(ctx context.Context, organization *Organization) errors.E { 
	data, errE := x.MarshalWithoutEscapeHTML(organization)
	if errE != nil {
		errors.Details(errE)["id"] = organization.ID
		return errE
	}

	organizationsMu.Lock()
	defer organizationsMu.Unlock()

	existingData, ok := organizations[organization.ID]
	if !ok {
		organizations[organization.ID] = data
		return nil
	}

	var existingOrganization Organization
	errE = x.UnmarshalWithoutUnknownFields(existingData, &existingOrganization)
	if errE != nil {
		errors.Details(errE)["id"] = organization.ID
		return errE
	}

	account := mustGetAccount(ctx)
	if !slices.Contains(existingOrganization.Admins, account) {
		return errors.WithDetails(ErrOrganizationUnauthorized, "id", organization.ID)
	}

	organizations[organization.ID] = data
	return nil
}

func (s *Service) Organization(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false, "Charon Dashboard") == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) Organizations(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false, "Charon Dashboard") == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func getOrganizationFromID(ctx context.Context, value string) (*Organization, errors.E) {
	if value == "" {
		return nil, errors.WithStack(ErrOrganizationNotFound)
	}

	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrOrganizationNotFound)
	}

	return GetOrganization(ctx, id)
}

func (s *Service) OrganizationGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	organization, errE := getOrganizationFromID(ctx, params["id"])
	if errors.Is(errE, ErrOrganizationNotFound) {
		s.NotFound(w, req)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, organization, nil)
}

func (s *Service) OrganizationsGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	result := []map[string]identifier.Identifier{}

	organizationsMu.RLock()
	defer organizationsMu.RUnlock()

	for id := range organizations {
		result = append(result, map[string]identifier.Identifier{
			"id": id,
		})
	}

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) OrganizationsPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	var organization Organization
	errE := x.DecodeJSON(req.Body, &organization)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = UpsertOrganization(ctx, &organization)
	if errors.Is(errE, ErrOrganizationUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	waf.Error(w, req, http.StatusOK)
}
