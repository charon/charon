package charon

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

var (
	ErrApplicationNotFound      = errors.Base("application not found")
	ErrApplicationAlreadyExists = errors.Base("application already exists")
	ErrApplicationUnauthorized  = errors.Base("application change unauthorized")
)

type ClientType string

const (
	ClientPublic  ClientType = "public"
	ClientBackend ClientType = "backend"
	ClientService ClientType = "service"
)

var (
	applications   = make(map[identifier.Identifier][]byte) //nolint:gochecknoglobals
	applicationsMu = sync.RWMutex{}                         //nolint:gochecknoglobals
)

func validateRedirectURITemplates(redirectURITemplates []string, variables []Variable) ([]string, errors.E) {
	if redirectURITemplates == nil {
		redirectURITemplates = []string{}
	}

	templatesSet := mapset.NewThreadUnsafeSet[string]()
	for i, template := range redirectURITemplates {
		errE := validateRedirectURIsTemplate(template, variables)
		if errE != nil {
			errE = errors.WithMessage(errE, "redirect URI template")
			errors.Details(errE)["i"] = i
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

func validateRedirectURIsTemplate(template string, variables []Variable) errors.E {
	if template == "" {
		return errors.New("cannot be empty")
	}

	vars := map[string]string{}
	for _, variable := range variables {
		vars[variable.Name] = validationValues[variable.Type]
	}

	value, errE := interpolateVariables(template, vars)
	if errE != nil {
		return errE
	}

	_, err := url.Parse(value)
	if err != nil {
		errE := errors.Wrap(err, "unable to parse resulting URI")
		errors.Details(errE)["template"] = template
		return errE
	}

	return nil
}

type clientType interface {
	GetID() identifier.Identifier
	GetClientType() ClientType
	Validate(ctx context.Context, variables []Variable) errors.E
}

var _ clientType = (*ApplicationClientPublic)(nil)

type ApplicationClientPublic struct {
	ID          *identifier.Identifier `json:"id"`
	Type        ClientType             `json:"type"`
	Description string                 `json:"description,omitempty"`

	RedirectURITemplates []string `json:"redirectUriTemplates"`
}

// GetID implements clientType.
func (c *ApplicationClientPublic) GetID() identifier.Identifier {
	return *c.ID
}

// GetClientType implements clientType.
func (c *ApplicationClientPublic) GetClientType() ClientType {
	return c.Type
}

// Validate implements clientType.
func (c *ApplicationClientPublic) Validate(_ context.Context, variables []Variable) errors.E {
	if c.ID == nil {
		id := identifier.New()
		c.ID = &id
	}

	if c.Type != ClientPublic {
		return errors.New("invalid type")
	}

	redirectURIsTemplates, errE := validateRedirectURITemplates(c.RedirectURITemplates, variables)
	if errE != nil {
		return errE
	}
	c.RedirectURITemplates = redirectURIsTemplates

	return nil
}

var _ clientType = (*ApplicationClientBackend)(nil)

type ApplicationClientBackend struct {
	ID          *identifier.Identifier `json:"id"`
	Type        ClientType             `json:"type"`
	Description string                 `json:"description,omitempty"`

	RedirectURITemplates []string `json:"redirectUriTemplates"`
}

// GetID implements clientType.
func (c *ApplicationClientBackend) GetID() identifier.Identifier {
	return *c.ID
}

// GetClientType implements getClientType.
func (c *ApplicationClientBackend) GetClientType() ClientType {
	return c.Type
}

// Validate implements clientType.
func (c *ApplicationClientBackend) Validate(_ context.Context, variables []Variable) errors.E {
	if c.ID == nil {
		id := identifier.New()
		c.ID = &id
	}

	if c.Type != ClientBackend {
		return errors.New("invalid type")
	}

	redirectURIsTemplates, errE := validateRedirectURITemplates(c.RedirectURITemplates, variables)
	if errE != nil {
		return errE
	}
	c.RedirectURITemplates = redirectURIsTemplates

	return nil
}

var _ clientType = (*ApplicationClientService)(nil)

type ApplicationClientService struct {
	ID          *identifier.Identifier `json:"id"`
	Type        ClientType             `json:"type"`
	Description string                 `json:"description,omitempty"`
}

// GetID implements clientType.
func (c *ApplicationClientService) GetID() identifier.Identifier {
	return *c.ID
}

// GetClientType implements clientType.
func (c *ApplicationClientService) GetClientType() ClientType {
	return c.Type
}

// Validate implements clientType.
func (c *ApplicationClientService) Validate(_ context.Context, _ []Variable) errors.E {
	if c.ID == nil {
		id := identifier.New()
		c.ID = &id
	}

	if c.Type != ClientService {
		return errors.New("invalid type")
	}

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

func interpolateVariables(template string, variables map[string]string) (string, errors.E) {
	unmatchedVariables := []string{}
	result := variableRegexp.ReplaceAllStringFunc(template, func(match string) string {
		varName := match[1 : len(match)-1] // Removing the curly braces.
		if value, ok := variables[varName]; ok {
			return value
		}
		// Unmatched variable.
		unmatchedVariables = append(unmatchedVariables, varName)
		return ""
	})

	if len(unmatchedVariables) > 0 {
		errE := errors.New("unknown variables")
		sort.Strings(unmatchedVariables)
		errors.Details(errE)["variables"] = unmatchedVariables
		return "", errE
	}

	return result, nil
}

type Application struct {
	ID *identifier.Identifier `json:"id"`

	Admins []AccountRef `json:"admins"`

	Name string `json:"name"`

	IDScopes  []string `json:"idScopes"`
	AppScopes []string `json:"appScopes"`

	Variables []Variable   `json:"variables"`
	Clients   []clientType `json:"clients"`
}

type ApplicationRef struct {
	ID identifier.Identifier `json:"id"`
}

func (a *Application) Validate(ctx context.Context) errors.E {
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

	// We sort and remove duplicates.
	slices.Sort(a.IDScopes)
	a.IDScopes = slices.Compact(a.IDScopes)

	// We sort and remove duplicates.
	slices.Sort(a.AppScopes)
	a.AppScopes = slices.Compact(a.AppScopes)

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

	if a.Clients == nil {
		a.Clients = []clientType{}
	}

	clientsSet := mapset.NewThreadUnsafeSet[identifier.Identifier]()
	for i, client := range a.Clients {
		errE := client.Validate(ctx, a.Variables)
		if errE != nil {
			errE = errors.WithMessage(errE, "client")
			errors.Details(errE)["i"] = i
			return errE
		}

		if clientsSet.Contains(client.GetID()) {
			errE := errors.New("duplicate client ID")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["id"] = client.GetID()
			return errE
		}
		clientsSet.Add(client.GetID())

		// We do not need to assign client back because it is an interface (a pointer).
	}

	return nil
}

func GetApplication(ctx context.Context, id identifier.Identifier) (*Application, errors.E) { //nolint:revive
	applicationsMu.RLock()
	defer applicationsMu.RUnlock()

	data, ok := applications[id]
	if !ok {
		return nil, errors.WithDetails(ErrApplicationNotFound, "id", id)
	}
	var application Application
	errE := x.UnmarshalWithoutUnknownFields(data, &application)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, errE
	}
	return &application, nil
}

func CreateApplication(ctx context.Context, application *Application) errors.E {
	errE := application.Validate(ctx)
	if errE != nil {
		return errE
	}

	data, errE := x.MarshalWithoutEscapeHTML(application)
	if errE != nil {
		return errE
	}

	applicationsMu.Lock()
	defer applicationsMu.Unlock()

	applications[*application.ID] = data
	return nil
}

func UpdateApplication(ctx context.Context, application *Application) errors.E {
	errE := application.Validate(ctx)
	if errE != nil {
		return errE
	}

	data, errE := x.MarshalWithoutEscapeHTML(application)
	if errE != nil {
		errors.Details(errE)["id"] = *application.ID
		return errE
	}

	applicationsMu.Lock()
	defer applicationsMu.Unlock()

	existingData, ok := applications[*application.ID]
	if !ok {
		return errors.WithDetails(ErrApplicationNotFound, "id", *application.ID)
	}

	var existingApplication Application
	errE = x.UnmarshalWithoutUnknownFields(existingData, &existingApplication)
	if errE != nil {
		errors.Details(errE)["id"] = *application.ID
		return errE
	}

	account := mustGetAccount(ctx)
	if !slices.Contains(existingApplication.Admins, AccountRef{account}) {
		return errors.WithDetails(ErrApplicationUnauthorized, "id", *application.ID)
	}

	applications[*application.ID] = data
	return nil
}

func (s *Service) Application(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false, "Charon Dashboard") == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) ApplicationCreate(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false, "Charon Dashboard") == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) Applications(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false, "Charon Dashboard") == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func getApplicationFromID(ctx context.Context, value string) (*Application, errors.E) {
	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrApplicationNotFound)
	}

	return GetApplication(ctx, id)
}

func (s *Service) returnApplication(ctx context.Context, w http.ResponseWriter, req *http.Request, application *Application) {
	account := mustGetAccount(ctx)

	s.WriteJSON(w, req, application, map[string]interface{}{
		"can_update": slices.Contains(application.Admins, AccountRef{account}),
	})
}

func (s *Service) returnApplicationRef(_ context.Context, w http.ResponseWriter, req *http.Request, application *Application) {
	s.WriteJSON(w, req, ApplicationRef{ID: *application.ID}, nil)
}

func (s *Service) ApplicationGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	application, errE := getApplicationFromID(ctx, params["id"])
	if errors.Is(errE, ErrApplicationNotFound) {
		s.NotFound(w, req)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnApplication(ctx, w, req, application)
}

func (s *Service) ApplicationsGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	result := []ApplicationRef{}

	applicationsMu.RLock()
	defer applicationsMu.RUnlock()

	for id := range applications {
		result = append(result, ApplicationRef{ID: id})
	}

	slices.SortFunc(result, func(a ApplicationRef, b ApplicationRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) ApplicationUpdatePost(w http.ResponseWriter, req *http.Request, params waf.Params) { //nolint:dupl
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	var application Application
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &application)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if application.ID == nil {
		id, errE := identifier.FromString(params["id"]) //nolint:govet
		if errE != nil {
			s.BadRequestWithError(w, req, errE)
		}
		application.ID = &id
	} else if params["id"] != application.ID.String() {
		errE = errors.New("params ID does not match payload ID")
		errors.Details(errE)["params"] = params["id"]
		errors.Details(errE)["payload"] = *application.ID
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = UpdateApplication(ctx, &application)
	if errors.Is(errE, ErrApplicationUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errors.Is(errE, ErrApplicationNotFound) {
		waf.Error(w, req, http.StatusNotFound)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnApplication(ctx, w, req, &application)
}

func (s *Service) ApplicationCreatePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	var application Application
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &application)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if application.ID != nil {
		s.BadRequestWithError(w, req, errors.New("payload contains ID"))
		return
	}

	errE = CreateApplication(ctx, &application)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnApplicationRef(ctx, w, req, &application)
}
