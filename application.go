package charon

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ory/fosite"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

var (
	ErrApplicationTemplateNotFound      = errors.Base("application template not found")
	ErrApplicationTemplateAlreadyExists = errors.Base("application template already exists")
	ErrApplicationTemplateUnauthorized  = errors.Base("application template change unauthorized")
)

type ClientType string

const (
	ClientPublic  ClientType = "public"
	ClientBackend ClientType = "backend"
	ClientService ClientType = "service"
)

var (
	applicationTemplates   = make(map[identifier.Identifier][]byte) //nolint:gochecknoglobals
	applicationTemplatesMu = sync.RWMutex{}                         //nolint:gochecknoglobals
)

func validateRedirectURITemplates(redirectURITemplates []string, variables []Variable) ([]string, errors.E) {
	if redirectURITemplates == nil {
		redirectURITemplates = []string{}
	}

	values := map[string]string{}
	for _, variable := range variables {
		values[variable.Name] = validationValues[variable.Type]
	}

	templatesSet := mapset.NewThreadUnsafeSet[string]()
	for i, template := range redirectURITemplates {
		errE := validateRedirectURIsTemplate(template, values)
		if errE != nil {
			errE = errors.WithMessage(errE, "redirect URI template")
			errors.Details(errE)["i"] = i
			if template != "" {
				errors.Details(errE)["template"] = template
			}
			return nil, errE
		}

		if templatesSet.Contains(template) {
			errE := errors.New("duplicate redirect URI template")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["template"] = template
			return nil, errE
		}
		templatesSet.Add(template)
	}

	return redirectURITemplates, nil
}

func validateRedirectURIsTemplate(template string, values map[string]string) errors.E {
	if template == "" {
		return errors.New("cannot be empty")
	}

	value, errE := interpolateVariables(template, values)
	if errE != nil {
		return errE
	}

	u, err := url.Parse(value)
	if err != nil {
		errE := errors.Wrap(err, "unable to parse resulting URI")
		errors.Details(errE)["template"] = template
		return errE
	}

	// The following two checks are the same as what we configured fosite to check.

	if !fosite.IsValidRedirectURI(u) {
		errE := errors.Wrap(err, "resulting URI is not a valid redirect URI")
		errors.Details(errE)["template"] = template
		return errE
	}

	if !fosite.IsRedirectURISecureStrict(u) {
		errE := errors.Wrap(err, "resulting URI is not secure")
		errors.Details(errE)["template"] = template
		return errE
	}

	return nil
}

type ClientRef struct {
	ID identifier.Identifier `json:"id"`
}

type ApplicationTemplateClientPublic struct {
	ID          *identifier.Identifier `json:"id"`
	Description string                 `json:"description,omitempty"`

	AdditionalScopes []string `json:"additionalScopes"`

	RedirectURITemplates []string `json:"redirectUriTemplates"`
}

func (c *ApplicationTemplateClientPublic) Validate(_ context.Context, variables []Variable) errors.E {
	if c.ID == nil {
		id := identifier.New()
		c.ID = &id
	}

	if c.AdditionalScopes == nil {
		c.AdditionalScopes = []string{}
	}

	// We sort and remove duplicates.
	slices.Sort(c.AdditionalScopes)
	c.AdditionalScopes = slices.Compact(c.AdditionalScopes)

	redirectURIsTemplates, errE := validateRedirectURITemplates(c.RedirectURITemplates, variables)
	if errE != nil {
		return errE
	}
	c.RedirectURITemplates = redirectURIsTemplates

	return nil
}

type ApplicationTemplateClientBackend struct {
	ID          *identifier.Identifier `json:"id"`
	Description string                 `json:"description,omitempty"`

	AdditionalScopes []string `json:"additionalScopes"`

	RedirectURITemplates []string `json:"redirectUriTemplates"`
}

func (c *ApplicationTemplateClientBackend) Validate(_ context.Context, variables []Variable) errors.E {
	if c.ID == nil {
		id := identifier.New()
		c.ID = &id
	}

	if c.AdditionalScopes == nil {
		c.AdditionalScopes = []string{}
	}

	// We sort and remove duplicates.
	slices.Sort(c.AdditionalScopes)
	c.AdditionalScopes = slices.Compact(c.AdditionalScopes)

	redirectURIsTemplates, errE := validateRedirectURITemplates(c.RedirectURITemplates, variables)
	if errE != nil {
		return errE
	}
	c.RedirectURITemplates = redirectURIsTemplates

	return nil
}

type ApplicationTemplateClientService struct {
	ID          *identifier.Identifier `json:"id"`
	Description string                 `json:"description,omitempty"`

	AdditionalScopes []string `json:"additionalScopes"`
}

func (c *ApplicationTemplateClientService) Validate(_ context.Context, _ []Variable) errors.E {
	if c.ID == nil {
		id := identifier.New()
		c.ID = &id
	}

	if c.AdditionalScopes == nil {
		c.AdditionalScopes = []string{}
	}

	// We sort and remove duplicates.
	slices.Sort(c.AdditionalScopes)
	c.AdditionalScopes = slices.Compact(c.AdditionalScopes)

	return nil
}

type VariableType string

const (
	VariableTypeURIPrefix VariableType = "uriPrefix"
)

var validationValues = map[VariableType]string{ //nolint:gochecknoglobals
	VariableTypeURIPrefix: "https://sub.example.com:8080/foo",
}

type Variable struct {
	Name        string       `json:"name"`
	Type        VariableType `json:"type"`
	Description string       `json:"description,omitempty"`
}

func (v *Variable) Validate(_ context.Context) errors.E {
	if v.Name == "" {
		return errors.New("name is required")
	}

	switch v.Type {
	case VariableTypeURIPrefix:
	default:
		return errors.New("invalid type")
	}

	return nil
}

var variableRegexp = regexp.MustCompile(`\{([^}]+)\}`)

func interpolateVariables(template string, values map[string]string) (string, errors.E) {
	unmatchedVariables := []string{}
	result := variableRegexp.ReplaceAllStringFunc(template, func(match string) string {
		varName := match[1 : len(match)-1] // Removing the curly braces.
		if value, ok := values[varName]; ok {
			return value
		}
		// Unmatched variable.
		unmatchedVariables = append(unmatchedVariables, varName)
		return ""
	})

	if len(unmatchedVariables) > 0 {
		errE := errors.New("unknown variables")
		slices.Sort(unmatchedVariables)
		unmatchedVariables = slices.Compact(unmatchedVariables)
		errors.Details(errE)["variables"] = unmatchedVariables
		return "", errE
	}

	return result, nil
}

// ApplicationTemplate is an application template which can be deployed multiple times.
type ApplicationTemplate struct {
	ID *identifier.Identifier `json:"id"`

	// When this application template is embedded into OrganizationApplication, the
	// list of admins is set to nil and we do not want it to be shown as a field.
	Admins []AccountRef `json:"admins,omitempty"`

	Name string `json:"name"`

	IDScopes []string `json:"idScopes"`

	Variables      []Variable                         `json:"variables"`
	ClientsPublic  []ApplicationTemplateClientPublic  `json:"clientsPublic"`
	ClientsBackend []ApplicationTemplateClientBackend `json:"clientsBackend"`
	ClientsService []ApplicationTemplateClientService `json:"clientsService"`
}

func (a *ApplicationTemplate) GetClientPublic(id identifier.Identifier) *ApplicationTemplateClientPublic {
	for _, client := range a.ClientsPublic {
		if client.ID != nil && *client.ID == id {
			return &client
		}
	}

	return nil
}

func (a *ApplicationTemplate) GetClientBackend(id identifier.Identifier) *ApplicationTemplateClientBackend {
	for _, client := range a.ClientsBackend {
		if client.ID != nil && *client.ID == id {
			return &client
		}
	}

	return nil
}

func (a *ApplicationTemplate) GetClientService(id identifier.Identifier) *ApplicationTemplateClientService {
	for _, client := range a.ClientsService {
		if client.ID != nil && *client.ID == id {
			return &client
		}
	}

	return nil
}

type ApplicationTemplateRef struct {
	ID identifier.Identifier `json:"id"`
}

func (a *ApplicationTemplate) Validate(ctx context.Context) errors.E {
	if a.ID == nil {
		id := identifier.New()
		a.ID = &id
	}

	account := mustGetAccount(ctx)
	accountRef := AccountRef{account}
	if !slices.Contains(a.Admins, accountRef) {
		a.Admins = append(a.Admins, accountRef)
	}

	// We sort and remove duplicates.
	slices.SortFunc(a.Admins, func(a AccountRef, b AccountRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	a.Admins = slices.Compact(a.Admins)

	if a.Name == "" {
		return errors.New("name is required")
	}

	if a.IDScopes == nil {
		a.IDScopes = []string{}
	}

	// We sort and remove duplicates.
	slices.Sort(a.IDScopes)
	a.IDScopes = slices.Compact(a.IDScopes)

	// TODO: Validate that a.IDScopes is a (non-strict) subset of supported ID scopes.

	if a.Variables == nil {
		// Default variable.
		a.Variables = []Variable{{
			Name:        "uriBase",
			Type:        VariableTypeURIPrefix,
			Description: "uriBase is a URI prefix used to construct URIs (e.g., OIDC redirect URIs) based on the domain on which the application is deployed.",
		}}
	}

	variablesSet := mapset.NewThreadUnsafeSet[string]()
	for i, variable := range a.Variables {
		errE := variable.Validate(ctx)
		if errE != nil {
			errE = errors.WithMessage(errE, "variable")
			errors.Details(errE)["i"] = i
			if variable.Name != "" {
				errors.Details(errE)["name"] = variable.Name
			}
			return errE
		}

		if variablesSet.Contains(variable.Name) {
			errE := errors.New("duplicate variable name")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["name"] = variable.Name
			return errE
		}
		variablesSet.Add(variable.Name)

		// Variable might have been changed by Validate, so we assign it back.
		a.Variables[i] = variable
	}

	if a.ClientsPublic == nil {
		a.ClientsPublic = []ApplicationTemplateClientPublic{}
	}

	if a.ClientsBackend == nil {
		a.ClientsBackend = []ApplicationTemplateClientBackend{}
	}

	if a.ClientsService == nil {
		a.ClientsService = []ApplicationTemplateClientService{}
	}

	clientsSet := mapset.NewThreadUnsafeSet[identifier.Identifier]()

	for i, client := range a.ClientsPublic {
		errE := client.Validate(ctx, a.Variables)
		if errE != nil {
			errE = errors.WithMessage(errE, "public client")
			errors.Details(errE)["i"] = i
			if client.ID != nil {
				errors.Details(errE)["id"] = *client.ID
			}
			return errE
		}

		if clientsSet.Contains(*client.ID) {
			errE := errors.New("duplicate client ID")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["id"] = *client.ID
			return errE
		}
		clientsSet.Add(*client.ID)

		// Client might have been changed by Validate, so we assign it back.
		a.ClientsPublic[i] = client
	}

	for i, client := range a.ClientsBackend {
		errE := client.Validate(ctx, a.Variables)
		if errE != nil {
			errE = errors.WithMessage(errE, "backend client")
			errors.Details(errE)["i"] = i
			if client.ID != nil {
				errors.Details(errE)["id"] = *client.ID
			}

			return errE
		}

		if clientsSet.Contains(*client.ID) {
			errE := errors.New("duplicate client ID")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["id"] = *client.ID
			return errE
		}
		clientsSet.Add(*client.ID)

		// Client might have been changed by Validate, so we assign it back.
		a.ClientsBackend[i] = client
	}

	for i, client := range a.ClientsService {
		errE := client.Validate(ctx, a.Variables)
		if errE != nil {
			errE = errors.WithMessage(errE, "service client")
			errors.Details(errE)["i"] = i
			if client.ID != nil {
				errors.Details(errE)["id"] = *client.ID
			}
			return errE
		}

		if clientsSet.Contains(*client.ID) {
			errE := errors.New("duplicate client ID")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["id"] = *client.ID
			return errE
		}
		clientsSet.Add(*client.ID)

		// Client might have been changed by Validate, so we assign it back.
		a.ClientsService[i] = client
	}

	return nil
}

func GetApplicationTemplate(ctx context.Context, id identifier.Identifier) (*ApplicationTemplate, errors.E) { //nolint:revive
	applicationTemplatesMu.RLock()
	defer applicationTemplatesMu.RUnlock()

	data, ok := applicationTemplates[id]
	if !ok {
		return nil, errors.WithDetails(ErrApplicationTemplateNotFound, "id", id)
	}
	var applicationTemplate ApplicationTemplate
	errE := x.UnmarshalWithoutUnknownFields(data, &applicationTemplate)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, errE
	}
	return &applicationTemplate, nil
}

func CreateApplicationTemplate(ctx context.Context, applicationTemplate *ApplicationTemplate) errors.E {
	errE := applicationTemplate.Validate(ctx)
	if errE != nil {
		return errE
	}

	data, errE := x.MarshalWithoutEscapeHTML(applicationTemplate)
	if errE != nil {
		return errE
	}

	applicationTemplatesMu.Lock()
	defer applicationTemplatesMu.Unlock()

	applicationTemplates[*applicationTemplate.ID] = data
	return nil
}

func UpdateApplicationTemplate(ctx context.Context, applicationTemplate *ApplicationTemplate) errors.E {
	errE := applicationTemplate.Validate(ctx)
	if errE != nil {
		return errE
	}

	data, errE := x.MarshalWithoutEscapeHTML(applicationTemplate)
	if errE != nil {
		errors.Details(errE)["id"] = *applicationTemplate.ID
		return errE
	}

	applicationTemplatesMu.Lock()
	defer applicationTemplatesMu.Unlock()

	existingData, ok := applicationTemplates[*applicationTemplate.ID]
	if !ok {
		return errors.WithDetails(ErrApplicationTemplateNotFound, "id", *applicationTemplate.ID)
	}

	var existingApplicationTemplate ApplicationTemplate
	errE = x.UnmarshalWithoutUnknownFields(existingData, &existingApplicationTemplate)
	if errE != nil {
		errors.Details(errE)["id"] = *applicationTemplate.ID
		return errE
	}

	account := mustGetAccount(ctx)
	if !slices.Contains(existingApplicationTemplate.Admins, AccountRef{account}) {
		return errors.WithDetails(ErrApplicationTemplateUnauthorized, "id", *applicationTemplate.ID)
	}

	applicationTemplates[*applicationTemplate.ID] = data
	return nil
}

func (s *Service) ApplicationTemplate(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false, "Charon Dashboard") == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) ApplicationTemplateCreate(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false, "Charon Dashboard") == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) ApplicationTemplates(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false, "Charon Dashboard") == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func getApplicationTemplateFromID(ctx context.Context, value string) (*ApplicationTemplate, errors.E) {
	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrApplicationTemplateNotFound)
	}

	return GetApplicationTemplate(ctx, id)
}

func (s *Service) returnApplicationTemplate(ctx context.Context, w http.ResponseWriter, req *http.Request, applicationTemplate *ApplicationTemplate) {
	account := mustGetAccount(ctx)

	s.WriteJSON(w, req, applicationTemplate, map[string]interface{}{
		"can_update": slices.Contains(applicationTemplate.Admins, AccountRef{account}),
	})
}

func (s *Service) returnApplicationTemplateRef(_ context.Context, w http.ResponseWriter, req *http.Request, applicationTemplate *ApplicationTemplate) {
	s.WriteJSON(w, req, ApplicationTemplateRef{ID: *applicationTemplate.ID}, nil)
}

func (s *Service) ApplicationTemplateGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	applicationTemplate, errE := getApplicationTemplateFromID(ctx, params["id"])
	if errors.Is(errE, ErrApplicationTemplateNotFound) {
		s.NotFound(w, req)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnApplicationTemplate(ctx, w, req, applicationTemplate)
}

func (s *Service) ApplicationTemplatesGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	result := []ApplicationTemplateRef{}

	applicationTemplatesMu.RLock()
	defer applicationTemplatesMu.RUnlock()

	for id := range applicationTemplates {
		result = append(result, ApplicationTemplateRef{ID: id})
	}

	slices.SortFunc(result, func(a ApplicationTemplateRef, b ApplicationTemplateRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) ApplicationTemplateUpdatePost(w http.ResponseWriter, req *http.Request, params waf.Params) { //nolint:dupl
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	var applicationTemplate ApplicationTemplate
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &applicationTemplate)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if applicationTemplate.ID == nil {
		id, errE := identifier.FromString(params["id"]) //nolint:govet
		if errE != nil {
			s.BadRequestWithError(w, req, errE)
		}
		applicationTemplate.ID = &id
	} else if params["id"] != applicationTemplate.ID.String() {
		errE = errors.New("params ID does not match payload ID")
		errors.Details(errE)["params"] = params["id"]
		errors.Details(errE)["payload"] = *applicationTemplate.ID
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = UpdateApplicationTemplate(ctx, &applicationTemplate)
	if errors.Is(errE, ErrApplicationTemplateUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errors.Is(errE, ErrApplicationTemplateNotFound) {
		waf.Error(w, req, http.StatusNotFound)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnApplicationTemplate(ctx, w, req, &applicationTemplate)
}

func (s *Service) ApplicationTemplateCreatePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	var applicationTemplate ApplicationTemplate
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &applicationTemplate)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if applicationTemplate.ID != nil {
		s.BadRequestWithError(w, req, errors.New("payload contains ID"))
		return
	}

	errE = CreateApplicationTemplate(ctx, &applicationTemplate)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnApplicationTemplateRef(ctx, w, req, &applicationTemplate)
}
