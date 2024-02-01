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

type Value struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (v *Value) Validate(ctx context.Context) errors.E {
	if v.Name == "" {
		return errors.New("name is required")
	}

	if v.Value == "" {
		return errors.New("value is required")
	}

	return nil
}

type OrganizationApplicationClientPublic struct {
	ID     *identifier.Identifier `json:"id"`
	Client ClientRef              `json:"client"`
}

func (c *OrganizationApplicationClientPublic) Validate(ctx context.Context, applicationTemplate *ApplicationTemplate, values map[string]string) errors.E {
	if c.ID == nil {
		id := identifier.New()
		c.ID = &id
	}

	client := applicationTemplate.GetClientPublic(c.Client.ID)
	if client == nil {
		errE := errors.New("unable to find referenced public client")
		errors.Details(errE)["id"] = c.Client.ID
		return errE
	}

	// We do not check if interpolated templates have duplicates.
	// This would be hard to fix for the user of the application template anyway.
	for i, template := range client.RedirectURITemplates {
		errE := validateRedirectURIsTemplate(template, values)
		if errE != nil {
			errE = errors.WithMessage(errE, "redirect URI")
			errors.Details(errE)["i"] = i
			if template != "" {
				errors.Details(errE)["template"] = template
			}
			return errE
		}
	}

	return nil
}

type OrganizationApplicationClientBackend struct {
	ID     *identifier.Identifier `json:"id"`
	Client ClientRef              `json:"client"`

	// TODO: This should really be a []byte, but should not be base64 encoded when in JSON.
	//       Go JSONv2 might support that with "format:string".
	Secret string `json:"secret"`
}

func (c *OrganizationApplicationClientBackend) Validate(ctx context.Context, applicationTemplate *ApplicationTemplate, values map[string]string) errors.E {
	if c.ID == nil {
		id := identifier.New()
		c.ID = &id
	}

	params, _, _, err := argon2id.DecodeHash(c.Secret)
	// TODO: What is a workflow to make these params stricter in the future?
	//       API calls will start failing with existing secrets on unrelated updates.
	if err != nil ||
		params.Memory < argon2idParams.Memory ||
		params.Iterations < argon2idParams.Iterations ||
		params.Parallelism < argon2idParams.Parallelism ||
		params.SaltLength < argon2idParams.SaltLength ||
		params.KeyLength < argon2idParams.KeyLength {
		errE := errors.WithMessage(err, "invalid client secret")
		errors.Details(errE)["id"] = *c.ID
		return errE
	}

	client := applicationTemplate.GetClientBackend(c.Client.ID)
	if client == nil {
		errE := errors.New("unable to find referenced backend client")
		errors.Details(errE)["id"] = c.Client.ID
		return errE
	}

	// We do not check if interpolated templates have duplicates.
	// This would be hard to fix for the user of the application template anyway.
	for i, template := range client.RedirectURITemplates {
		errE := validateRedirectURIsTemplate(template, values)
		if errE != nil {
			errE = errors.WithMessage(errE, "redirect URI")
			errors.Details(errE)["i"] = i
			if template != "" {
				errors.Details(errE)["template"] = template
			}
			return errE
		}
	}

	return nil
}

type OrganizationApplicationClientService struct {
	ID     *identifier.Identifier `json:"id"`
	Client ClientRef              `json:"client"`

	// TODO: This should really be a []byte, but should not be base64 encoded when in JSON.
	//       Go JSONv2 might support that with "format:string".
	Secret string `json:"secret"`
}

func (c *OrganizationApplicationClientService) Validate(ctx context.Context, applicationTemplate *ApplicationTemplate, values map[string]string) errors.E {
	if c.ID == nil {
		id := identifier.New()
		c.ID = &id
	}

	params, _, _, err := argon2id.DecodeHash(c.Secret)
	// TODO: What is a workflow to make these params stricter in the future?
	//       API calls will start failing with existing secrets on unrelated updates.
	if err != nil ||
		params.Memory < argon2idParams.Memory ||
		params.Iterations < argon2idParams.Iterations ||
		params.Parallelism < argon2idParams.Parallelism ||
		params.SaltLength < argon2idParams.SaltLength ||
		params.KeyLength < argon2idParams.KeyLength {
		errE := errors.WithMessage(err, "invalid client secret")
		errors.Details(errE)["id"] = *c.ID
		return errE
	}

	client := applicationTemplate.GetClientService(c.Client.ID)
	if client == nil {
		errE := errors.New("unable to find referenced service client")
		errors.Details(errE)["id"] = c.Client.ID
		return errE
	}

	return nil
}

type OrganizationApplication struct {
	ID *identifier.Identifier `json:"id"`

	// We store full application template for this deployment, so if upstream
	// application template changes, this one continues to be consistent.
	// It can in fact be even a template which has not been published at all.
	// TODO: Show to the organization admin that upstream template changed and invite them to update their template.
	ApplicationTemplate ApplicationTemplate `json:"applicationTemplate"`

	Values         []Value                                `json:"values"`
	ClientsPublic  []OrganizationApplicationClientPublic  `json:"clientsPublic"`
	ClientsBackend []OrganizationApplicationClientBackend `json:"clientsBackend"`
	ClientsService []OrganizationApplicationClientService `json:"clientsService"`
}

func (a *OrganizationApplication) GetClientPublic(ctx context.Context, id identifier.Identifier) *OrganizationApplicationClientPublic {
	for _, client := range a.ClientsPublic {
		if *client.ID == id {
			return &client
		}
	}

	return nil
}

func (a *OrganizationApplication) GetClientBackend(ctx context.Context, id identifier.Identifier) *OrganizationApplicationClientBackend {
	for _, client := range a.ClientsBackend {
		if *client.ID == id {
			return &client
		}
	}

	return nil
}

func (a *OrganizationApplication) GetClientService(ctx context.Context, id identifier.Identifier) *OrganizationApplicationClientService {
	for _, client := range a.ClientsService {
		if *client.ID == id {
			return &client
		}
	}

	return nil
}

func (a *OrganizationApplication) Validate(ctx context.Context) errors.E {
	if a.ID == nil {
		id := identifier.New()
		a.ID = &id
	}

	// This validation adds current user to admins of the embedded application template
	// (the admin of the original application template might be somebody else). This is
	// fine because we in the next step set admins to nil anyway.
	errE := a.ApplicationTemplate.Validate(ctx)
	if errE != nil {
		return errE
	}

	// When we embed a copy of the application template, we set admin always to nil.
	a.ApplicationTemplate.Admins = nil

	values := map[string]string{}
	valuesSet := mapset.NewThreadUnsafeSet[string]()
	for i, value := range a.Values {
		errE := value.Validate(ctx)
		if errE != nil {
			errE = errors.WithMessage(errE, "value")
			errors.Details(errE)["i"] = i
			if value.Name != "" {
				errors.Details(errE)["name"] = value.Name
			}
			return errE
		}

		if valuesSet.Contains(value.Name) {
			errE := errors.New("duplicate value")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["name"] = value.Name
			return errE
		}
		valuesSet.Add(value.Name)
		values[value.Name] = value.Value

		// Value might have been changed by Validate, so we assign it back.
		a.Values[i] = value
	}

	variablesSet := mapset.NewThreadUnsafeSet[string]()
	for _, variable := range a.ApplicationTemplate.Variables {
		// Variables have already been validated by us validating a.ApplicationTemplate above.
		variablesSet.Add(variable.Name)
	}

	if !valuesSet.Equal(variablesSet) {
		errE := errors.New("values do not match variables")
		extra := valuesSet.Difference(variablesSet).ToSlice()
		slices.Sort(extra)
		missing := variablesSet.Difference(valuesSet).ToSlice()
		slices.Sort(missing)
		errors.Details(errE)["extra"] = extra
		errors.Details(errE)["missing"] = missing
		return errE
	}

	// We require unique IDs across all clients.
	// TODO: IDs should be unique across all clients across all organizations.
	clientSet := mapset.NewThreadUnsafeSet[identifier.Identifier]()

	for i, client := range a.ClientsPublic {
		errE := client.Validate(ctx, &a.ApplicationTemplate, values)
		if errE != nil {
			errE = errors.WithMessage(errE, "public client")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["id"] = *client.ID
			return errE
		}

		if clientSet.Contains(*client.ID) {
			errE := errors.New("duplicate client ID")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["id"] = *client.ID
			return errE
		}
		clientSet.Add(*client.ID)

		// Client might have been changed by Validate, so we assign it back.
		a.ClientsPublic[i] = client
	}

	for i, client := range a.ClientsBackend {
		errE := client.Validate(ctx, &a.ApplicationTemplate, values)
		if errE != nil {
			errE = errors.WithMessage(errE, "backend client")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["id"] = *client.ID
			return errE
		}

		if clientSet.Contains(*client.ID) {
			errE := errors.New("duplicate client ID")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["id"] = *client.ID
			return errE
		}
		clientSet.Add(*client.ID)

		// Client might have been changed by Validate, so we assign it back.
		a.ClientsBackend[i] = client
	}

	for i, client := range a.ClientsService {
		errE := client.Validate(ctx, &a.ApplicationTemplate, values)
		if errE != nil {
			errE = errors.WithMessage(errE, "service client")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["id"] = *client.ID
			return errE
		}

		if clientSet.Contains(*client.ID) {
			errE := errors.New("duplicate client ID")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["id"] = *client.ID
			return errE
		}
		clientSet.Add(*client.ID)

		// Client might have been changed by Validate, so we assign it back.
		a.ClientsService[i] = client
	}

	return nil
}

type Organization struct {
	ID *identifier.Identifier `json:"id"`

	Admins []AccountRef `json:"admins"`

	Name         string                    `json:"name"`
	Active       bool                      `json:"active"`
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
		errE := orgApp.Validate(ctx)
		if errE != nil {
			errE = errors.WithMessage(errE, "application")
			errors.Details(errE)["i"] = i
			if orgApp.ID != nil {
				errors.Details(errE)["id"] = *orgApp.ID
			}
			return nil
		}

		if appsSet.Contains(*orgApp.ID) {
			errE := errors.New("duplicate application ID")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["id"] = *orgApp.ID
			return errE
		}
		appsSet.Add(*orgApp.ID)

		// We on purpose allow that organization can use same application template multiple
		// times so we do not check if orgApp.Application.ID are repeated.

		// OrganizationApplication might have been changed by Validate, so we assign it back.
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
