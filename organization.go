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

var charonOrganization = identifier.MustFromString("TCD1UhKfBDewGv2TgPnFsX") //nolint:gochecknoglobals

var (
	ErrOrganizationNotFound         = errors.Base("organization not found")
	ErrOrganizationAlreadyExists    = errors.Base("organization already exists")
	ErrOrganizationUnauthorized     = errors.Base("organization change unauthorized")
	ErrOrganizationValidationFailed = errors.Base("organization validation failed")
)

var (
	organizations   = make(map[identifier.Identifier][]byte) //nolint:gochecknoglobals
	organizationsMu = sync.RWMutex{}                         //nolint:gochecknoglobals
)

type Value struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (v *Value) Validate(_ context.Context) errors.E {
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

func (c *OrganizationApplicationClientPublic) Validate(
	ctx context.Context, existing *OrganizationApplicationClientPublic,
	applicationTemplate *ApplicationTemplatePublic, values map[string]string,
) errors.E {
	if existing == nil {
		if c.ID != nil {
			errE := errors.New("ID provided for new document")
			errors.Details(errE)["id"] = *c.ID
			return errE
		}
		id := identifier.New()
		c.ID = &id
	} else if c.ID == nil {
		// This should not really happen because we fetch existing based on c.ID.
		return errors.New("ID missing for existing document")
	} else if existing.ID == nil {
		// This should not really happen because we always store documents with ID.
		return errors.New("ID missing for existing document")
	} else if *c.ID != *existing.ID {
		// This should not really happen because we fetch existing based on c.ID.
		errE := errors.New("payload ID does not match existing ID")
		errors.Details(errE)["payload"] = *c.ID
		errors.Details(errE)["existing"] = *existing.ID
		return errE
	}

	client := applicationTemplate.GetClientPublic(&c.Client.ID)
	if client == nil {
		errE := errors.New("unable to find referenced public client")
		errors.Details(errE)["id"] = c.Client.ID
		return errE
	}

	// We do not check if interpolated templates have duplicates.
	// This would be hard to fix for the user of the application template anyway.
	for i, template := range client.RedirectURITemplates {
		// TODO: We could store interpolated redirect URIs somewhere after this point so that we do not have to do interpolation again and again.
		errE := validateRedirectURIsTemplate(ctx, template, values)
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

func (c *OrganizationApplicationClientBackend) Validate(
	ctx context.Context, existing *OrganizationApplicationClientBackend,
	applicationTemplate *ApplicationTemplatePublic, values map[string]string,
) errors.E {
	if existing == nil {
		if c.ID != nil {
			errE := errors.New("ID provided for new document")
			errors.Details(errE)["id"] = *c.ID
			return errE
		}
		id := identifier.New()
		c.ID = &id
	} else if c.ID == nil {
		// This should not really happen because we fetch existing based on c.ID.
		return errors.New("ID missing for existing document")
	} else if existing.ID == nil {
		// This should not really happen because we always store documents with ID.
		return errors.New("ID missing for existing document")
	} else if *c.ID != *existing.ID {
		// This should not really happen because we fetch existing based on c.ID.
		errE := errors.New("payload ID does not match existing ID")
		errors.Details(errE)["payload"] = *c.ID
		errors.Details(errE)["existing"] = *existing.ID
		return errE
	}

	params, _, _, err := argon2id.DecodeHash(c.Secret)
	// TODO: What is a workflow to make these params stricter in the future?
	//       API calls will start failing with existing secrets on unrelated updates.
	if err != nil ||
		params.Memory < Argon2idParams.Memory ||
		params.Iterations < Argon2idParams.Iterations ||
		params.Parallelism < Argon2idParams.Parallelism ||
		params.SaltLength < Argon2idParams.SaltLength ||
		params.KeyLength < Argon2idParams.KeyLength {
		errE := errors.WithMessage(err, "invalid client secret")
		errors.Details(errE)["id"] = *c.ID
		return errE
	}

	client := applicationTemplate.GetClientBackend(&c.Client.ID)
	if client == nil {
		errE := errors.New("unable to find referenced backend client")
		errors.Details(errE)["id"] = c.Client.ID
		return errE
	}

	// We do not check if interpolated templates have duplicates.
	// This would be hard to fix for the user of the application template anyway.
	for i, template := range client.RedirectURITemplates {
		// TODO: We could store interpolated redirect URIs somewhere after this point so that we do not have to do interpolation again and again.
		errE := validateRedirectURIsTemplate(ctx, template, values)
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

func (c *OrganizationApplicationClientService) Validate(
	_ context.Context, existing *OrganizationApplicationClientService,
	applicationTemplate *ApplicationTemplatePublic, _ map[string]string,
) errors.E {
	if existing == nil {
		if c.ID != nil {
			errE := errors.New("ID provided for new document")
			errors.Details(errE)["id"] = *c.ID
			return errE
		}
		id := identifier.New()
		c.ID = &id
	} else if c.ID == nil {
		// This should not really happen because we fetch existing based on c.ID.
		return errors.New("ID missing for existing document")
	} else if existing.ID == nil {
		// This should not really happen because we always store documents with ID.
		return errors.New("ID missing for existing document")
	} else if *c.ID != *existing.ID {
		// This should not really happen because we fetch existing based on c.ID.
		errE := errors.New("payload ID does not match existing ID")
		errors.Details(errE)["payload"] = *c.ID
		errors.Details(errE)["existing"] = *existing.ID
		return errE
	}

	params, _, _, err := argon2id.DecodeHash(c.Secret)
	// TODO: What is a workflow to make these params stricter in the future?
	//       API calls will start failing with existing secrets on unrelated updates.
	if err != nil ||
		params.Memory < Argon2idParams.Memory ||
		params.Iterations < Argon2idParams.Iterations ||
		params.Parallelism < Argon2idParams.Parallelism ||
		params.SaltLength < Argon2idParams.SaltLength ||
		params.KeyLength < Argon2idParams.KeyLength {
		errE := errors.WithMessage(err, "invalid client secret")
		errors.Details(errE)["id"] = *c.ID
		return errE
	}

	client := applicationTemplate.GetClientService(&c.Client.ID)
	if client == nil {
		errE := errors.New("unable to find referenced service client")
		errors.Details(errE)["id"] = c.Client.ID
		return errE
	}

	return nil
}

type OrganizationApplication struct {
	ID *identifier.Identifier `json:"id"`

	Active bool `json:"active"`

	// We store full application template for this deployment, so if upstream
	// application template changes, this one continues to be consistent.
	// It can in fact be even a template which has not been published at all.
	// TODO: Show to the organization admin that upstream template changed and invite them to update their template.
	ApplicationTemplate ApplicationTemplatePublic `json:"applicationTemplate"`

	Values         []Value                                `json:"values"`
	ClientsPublic  []OrganizationApplicationClientPublic  `json:"clientsPublic"`
	ClientsBackend []OrganizationApplicationClientBackend `json:"clientsBackend"`
	ClientsService []OrganizationApplicationClientService `json:"clientsService"`
}

func (a *OrganizationApplication) GetClientPublic(id *identifier.Identifier) *OrganizationApplicationClientPublic {
	if a == nil {
		return nil
	}
	if id == nil {
		return nil
	}

	for _, client := range a.ClientsPublic {
		if client.ID != nil && *client.ID == *id {
			return &client
		}
	}

	return nil
}

func (a *OrganizationApplication) GetClientBackend(id *identifier.Identifier) *OrganizationApplicationClientBackend {
	if a == nil {
		return nil
	}
	if id == nil {
		return nil
	}

	for _, client := range a.ClientsBackend {
		if client.ID != nil && *client.ID == *id {
			return &client
		}
	}

	return nil
}

func (a *OrganizationApplication) GetClientService(id *identifier.Identifier) *OrganizationApplicationClientService {
	if a == nil {
		return nil
	}
	if id == nil {
		return nil
	}

	for _, client := range a.ClientsService {
		if client.ID != nil && *client.ID == *id {
			return &client
		}
	}

	return nil
}

func (a *OrganizationApplication) Validate(ctx context.Context, existing *OrganizationApplication) errors.E {
	if existing == nil {
		if a.ID != nil {
			errE := errors.New("ID provided for new document")
			errors.Details(errE)["id"] = *a.ID
			return errE
		}
		id := identifier.New()
		a.ID = &id
	} else if a.ID == nil {
		// This should not really happen because we fetch existing based on a.ID.
		return errors.New("ID missing for existing document")
	} else if existing.ID == nil {
		// This should not really happen because we always store documents with ID.
		return errors.New("ID missing for existing document")
	} else if *a.ID != *existing.ID {
		// This should not really happen because we fetch existing based on a.ID.
		errE := errors.New("payload ID does not match existing ID")
		errors.Details(errE)["payload"] = *a.ID
		errors.Details(errE)["existing"] = *existing.ID
		return errE
	}

	var e *ApplicationTemplatePublic
	if existing != nil {
		e = &existing.ApplicationTemplate
	} else if a.ApplicationTemplate.ID != nil {
		at, errE := GetApplicationTemplate(ctx, *a.ApplicationTemplate.ID)
		if errE == nil {
			e = &at.ApplicationTemplatePublic
		} else if !errors.Is(errE, ErrApplicationTemplateNotFound) {
			return errE
		}
	}
	errE := a.ApplicationTemplate.Validate(ctx, e)
	if errE != nil {
		return errE
	}

	if a.Values == nil {
		a.Values = []Value{}
	}

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

	if a.ClientsPublic == nil {
		a.ClientsPublic = []OrganizationApplicationClientPublic{}
	}

	if a.ClientsBackend == nil {
		a.ClientsBackend = []OrganizationApplicationClientBackend{}
	}

	if a.ClientsService == nil {
		a.ClientsService = []OrganizationApplicationClientService{}
	}

	// We require unique IDs across all clients.
	// TODO: IDs should be unique across all clients across all organizations.
	clientSet := mapset.NewThreadUnsafeSet[identifier.Identifier]()

	for i, client := range a.ClientsPublic {
		errE := client.Validate(ctx, existing.GetClientPublic(client.ID), &a.ApplicationTemplate, values)
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
		errE := client.Validate(ctx, existing.GetClientBackend(client.ID), &a.ApplicationTemplate, values)
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
		errE := client.Validate(ctx, existing.GetClientService(client.ID), &a.ApplicationTemplate, values)
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
	OrganizationPublic

	Admins []AccountRef `json:"admins"`

	Applications []OrganizationApplication `json:"applications"`
}

func (o *Organization) GetApplication(id *identifier.Identifier) *OrganizationApplication {
	if o == nil {
		return nil
	}
	if id == nil {
		return nil
	}

	for _, orgApp := range o.Applications {
		if orgApp.ID != nil && *orgApp.ID == *id {
			return &orgApp
		}
	}

	return nil
}

type OrganizationPublic struct {
	ID          *identifier.Identifier `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
}

func (o *OrganizationPublic) Validate(_ context.Context, existing *OrganizationPublic) errors.E {
	if existing == nil {
		if o.ID != nil {
			errE := errors.New("ID provided for new document")
			errors.Details(errE)["id"] = *o.ID
			return errE
		}
		id := identifier.New()
		o.ID = &id
	} else if o.ID == nil {
		// This should not really happen because we fetch existing based on o.ID.
		return errors.New("ID missing for existing document")
	} else if existing.ID == nil {
		// This should not really happen because we always store documents with ID.
		return errors.New("ID missing for existing document")
	} else if *o.ID != *existing.ID {
		// This should not really happen because we fetch existing based on o.ID.
		errE := errors.New("payload ID does not match existing ID")
		errors.Details(errE)["payload"] = *o.ID
		errors.Details(errE)["existing"] = *existing.ID
		return errE
	}

	if o.Name == "" {
		return errors.New("name is required")
	}

	return nil
}

type OrganizationRef struct {
	ID identifier.Identifier `json:"id"`
}

func (o *Organization) Validate(ctx context.Context, existing *Organization) errors.E {
	var e *OrganizationPublic
	if existing == nil {
		e = nil
	} else {
		e = &existing.OrganizationPublic
	}
	errE := o.OrganizationPublic.Validate(ctx, e)
	if errE != nil {
		return errE
	}

	accountID := mustGetAccountID(ctx)
	accountRef := AccountRef{ID: accountID}
	if !slices.Contains(o.Admins, accountRef) {
		o.Admins = append(o.Admins, accountRef)
	}

	// We sort and remove duplicates.
	slices.SortFunc(o.Admins, func(a AccountRef, b AccountRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	o.Admins = slices.Compact(o.Admins)

	if o.Applications == nil {
		o.Applications = []OrganizationApplication{}
	}

	appsSet := mapset.NewThreadUnsafeSet[identifier.Identifier]()
	for i, orgApp := range o.Applications {
		errE := orgApp.Validate(ctx, existing.GetApplication(orgApp.ID))
		if errE != nil {
			errE = errors.WithMessage(errE, "application")
			errors.Details(errE)["i"] = i
			if orgApp.ID != nil {
				errors.Details(errE)["id"] = *orgApp.ID
			}
			return errE
		}

		if appsSet.Contains(*orgApp.ID) {
			errE := errors.New("duplicate application ID")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["id"] = *orgApp.ID
			return errE
		}
		appsSet.Add(*orgApp.ID)

		// We on purpose allow that organization can use same application template multiple
		// times so we do not check if orgApp.ApplicationTemplate.ID are repeated.

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
	errE := organization.Validate(ctx, nil)
	if errE != nil {
		return errors.WrapWith(errE, ErrOrganizationValidationFailed)
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
	organizationsMu.Lock()
	defer organizationsMu.Unlock()

	if organization.ID == nil {
		return errors.WithMessage(ErrOrganizationValidationFailed, "ID is missing")
	}

	existingData, ok := organizations[*organization.ID]
	if !ok {
		return errors.WithDetails(ErrOrganizationNotFound, "id", *organization.ID)
	}

	var existingOrganization Organization
	errE := x.UnmarshalWithoutUnknownFields(existingData, &existingOrganization)
	if errE != nil {
		errors.Details(errE)["id"] = *organization.ID
		return errE
	}

	accountID := mustGetAccountID(ctx)
	if !slices.Contains(existingOrganization.Admins, AccountRef{ID: accountID}) {
		return errors.WithDetails(ErrOrganizationUnauthorized, "id", organization.ID)
	}

	errE = organization.Validate(ctx, &existingOrganization)
	if errE != nil {
		return errors.WrapWith(errE, ErrOrganizationValidationFailed)
	}

	data, errE := x.MarshalWithoutEscapeHTML(organization)
	if errE != nil {
		errors.Details(errE)["id"] = *organization.ID
		return errE
	}

	organizations[*organization.ID] = data
	return nil
}

func (s *Service) OrganizationGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) OrganizationCreate(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false) == nil {
		return
	}

	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) OrganizationList(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
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

func (s *Service) returnOrganizationRef(_ context.Context, w http.ResponseWriter, req *http.Request, organization *Organization) {
	s.WriteJSON(w, req, OrganizationRef{ID: *organization.ID}, nil)
}

func (s *Service) OrganizationGetGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := req.Context()

	session, errE := s.getSessionFromRequest(w, req)
	if errE == nil {
		ctx = context.WithValue(ctx, accountIDContextKey, session.AccountID)
	} else if !errors.Is(errE, ErrSessionNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
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

	if session != nil && slices.Contains(organization.Admins, AccountRef{ID: session.AccountID}) {
		s.WriteJSON(w, req, organization, map[string]interface{}{
			"can_update": true,
		})
		return
	}

	s.WriteJSON(w, req, organization.OrganizationPublic, nil)
}

func (s *Service) OrganizationListGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
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

	ctx := s.RequireAuthenticated(w, req, true)
	if ctx == nil {
		return
	}

	var organization Organization
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &organization)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	// If organization.ID == nil, UpdateOrganization returns an error.
	if organization.ID != nil && params["id"] != organization.ID.String() {
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
		s.NotFound(w, req)
		return
	} else if errors.Is(errE, ErrOrganizationValidationFailed) {
		s.BadRequestWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnOrganizationRef(ctx, w, req, &organization)
}

func (s *Service) OrganizationCreatePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true)
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
	if errors.Is(errE, ErrOrganizationValidationFailed) {
		s.BadRequestWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnOrganizationRef(ctx, w, req, &organization)
}
