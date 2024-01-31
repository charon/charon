package charon

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"slices"
	"sync"

	"github.com/alexedwards/argon2id"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

var (
	ErrOrganizationNotFound      = errors.Base("organization not found")
	ErrOrganizationAlreadyExists = errors.Base("organization already exists")
	ErrOrganizationUnauthorized  = errors.Base("organization change unauthorized")
)

var (
	organizations   = make(map[identifier.Identifier][]byte) //nolint:gochecknoglobals
	organizationsMu = sync.RWMutex{}                         //nolint:gochecknoglobals
)

type OrganizationApplication struct {
	ID          *identifier.Identifier `json:"id"`
	Application ApplicationRef         `json:"application"`

	// TODO: This should really be a []byte, but should not be base64 encoded when in JSON. Go JSONv2 might support that.
	Secret string `json:"secret"`

	URLBase string `json:"urlBase"`
}

type Organization struct {
	ID *identifier.Identifier `json:"id"`

	Admins []AccountRef `json:"admins"`

	Name         string                    `json:"name"`
	Applications []OrganizationApplication `json:"applications"`
}

type OrganizationRef struct {
	ID identifier.Identifier `json:"id"`
}

func (o *Organization) Validate(ctx context.Context) errors.E {
	if o.ID == nil {
		id := identifier.New()
		o.ID = &id
	}

	account := mustGetAccount(ctx)
	accountRef := AccountRef{account}
	if !slices.Contains(o.Admins, accountRef) {
		o.Admins = append(o.Admins, accountRef)
	}

	// We sort and remove duplicates.
	slices.SortFunc(o.Admins, func(a AccountRef, b AccountRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	o.Admins = slices.Compact(o.Admins)

	if o.Name == "" {
		return errors.New("name is required")
	}

	appsSet := mapset.NewThreadUnsafeSet[identifier.Identifier]()
	for i, orgApp := range o.Applications {
		// IDs can be deterministic here.
		// TODO: Make them be generated randomly. But update should the operate on JSON patches.
		id := identifier.FromUUID(uuid.NewSHA1(uuid.UUID(*o.ID), orgApp.Application.ID[:]))
		if orgApp.ID == nil {
			orgApp.ID = &id
		} else if *orgApp.ID != id {
			errE := errors.New("invalid app ID")
			errors.Details(errE)["id"] = *orgApp.ID
			errors.Details(errE)["application"] = orgApp.Application.ID
			return errE
		}

		if appsSet.Contains(orgApp.Application.ID) {
			errE := errors.New("duplicate app")
			errors.Details(errE)["id"] = *orgApp.ID
			errors.Details(errE)["application"] = orgApp.Application.ID
			return errE
		}
		appsSet.Add(orgApp.Application.ID)

		params, _, _, err := argon2id.DecodeHash(orgApp.Secret)
		// TODO: What is a workflow to make these params stricter in the future?
		//       API calls will start failing with existing secrets on unrelated updates.
		if err != nil ||
			params.Memory < argon2idParams.Memory ||
			params.Iterations < argon2idParams.Iterations ||
			params.Parallelism < argon2idParams.Parallelism ||
			params.SaltLength < argon2idParams.SaltLength ||
			params.KeyLength < argon2idParams.KeyLength {
			errE := errors.WithMessage(err, "invalid app secret")
			errors.Details(errE)["id"] = *orgApp.ID
			errors.Details(errE)["application"] = orgApp.Application.ID
			return errE
		}

		o.Applications[i] = orgApp
	}

	return nil
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

func CreateOrganization(ctx context.Context, organization *Organization) errors.E {
	errE := organization.Validate(ctx)
	if errE != nil {
		return errE
	}

	data, errE := x.MarshalWithoutEscapeHTML(organization)
	if errE != nil {
		return errE
	}

	organizationsMu.Lock()
	defer organizationsMu.Unlock()

	organizations[*organization.ID] = data
	return nil
}

func UpdateOrganization(ctx context.Context, organization *Organization) errors.E {
	errE := organization.Validate(ctx)
	if errE != nil {
		return errE
	}

	data, errE := x.MarshalWithoutEscapeHTML(organization)
	if errE != nil {
		errors.Details(errE)["id"] = *organization.ID
		return errE
	}

	organizationsMu.Lock()
	defer organizationsMu.Unlock()

	existingData, ok := organizations[*organization.ID]
	if !ok {
		return errors.WithDetails(ErrOrganizationNotFound, "id", *organization.ID)
	}

	var existingOrganization Organization
	errE = x.UnmarshalWithoutUnknownFields(existingData, &existingOrganization)
	if errE != nil {
		errors.Details(errE)["id"] = *organization.ID
		return errE
	}

	account := mustGetAccount(ctx)
	if !slices.Contains(existingOrganization.Admins, AccountRef{account}) {
		return errors.WithDetails(ErrOrganizationUnauthorized, "id", organization.ID)
	}

	organizations[*organization.ID] = data
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

func (s *Service) OrganizationCreate(w http.ResponseWriter, req *http.Request, _ waf.Params) {
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
	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrOrganizationNotFound)
	}

	return GetOrganization(ctx, id)
}

func (s *Service) returnOrganization(ctx context.Context, w http.ResponseWriter, req *http.Request, organization *Organization) {
	account := mustGetAccount(ctx)

	s.WriteJSON(w, req, organization, map[string]interface{}{
		"can_update": slices.Contains(organization.Admins, AccountRef{account}),
	})
}

func (s *Service) returnOrganizationRef(_ context.Context, w http.ResponseWriter, req *http.Request, organization *Organization) {
	s.WriteJSON(w, req, OrganizationRef{ID: *organization.ID}, nil)
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

	s.returnOrganization(ctx, w, req, organization)
}

func (s *Service) OrganizationsGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	result := []OrganizationRef{}

	organizationsMu.RLock()
	defer organizationsMu.RUnlock()

	for id := range organizations {
		result = append(result, OrganizationRef{ID: id})
	}

	slices.SortFunc(result, func(a OrganizationRef, b OrganizationRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) OrganizationUpdatePost(w http.ResponseWriter, req *http.Request, params waf.Params) { //nolint:dupl
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	var organization Organization
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &organization)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if organization.ID == nil {
		id, errE := identifier.FromString(params["id"]) //nolint:govet
		if errE != nil {
			s.BadRequestWithError(w, req, errE)
		}
		organization.ID = &id
	} else if params["id"] != organization.ID.String() {
		errE = errors.New("params ID does not match payload ID")
		errors.Details(errE)["params"] = params["id"]
		errors.Details(errE)["payload"] = *organization.ID
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = UpdateOrganization(ctx, &organization)
	if errors.Is(errE, ErrOrganizationUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errors.Is(errE, ErrOrganizationNotFound) {
		waf.Error(w, req, http.StatusNotFound)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnOrganization(ctx, w, req, &organization)
}

func (s *Service) OrganizationCreatePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	var organization Organization
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &organization)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if organization.ID != nil {
		s.BadRequestWithError(w, req, errors.New("payload contains ID"))
		return
	}

	errE = CreateOrganization(ctx, &organization)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnOrganizationRef(ctx, w, req, &organization)
}
