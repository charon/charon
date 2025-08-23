package charon

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ory/fosite"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

var (
	ErrApplicationTemplateNotFound         = errors.Base("application template not found")
	ErrApplicationTemplateAlreadyExists    = errors.Base("application template already exists")
	ErrApplicationTemplateUnauthorized     = errors.Base("application template change unauthorized")
	ErrApplicationTemplateValidationFailed = errors.Base("application template validation failed")
)

type ClientType string

const (
	ClientPublic  ClientType = "public"
	ClientBackend ClientType = "backend"
	ClientService ClientType = "service"
)

// From RFC 6749: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ).
var validScopeRegexp = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`)

func validateRedirectURITemplates(ctx context.Context, redirectURITemplates []string, values map[string]string) ([]string, errors.E) {
	if redirectURITemplates == nil {
		redirectURITemplates = []string{}
	}

	templatesSet := mapset.NewThreadUnsafeSet[string]()
	for i, template := range redirectURITemplates {
		errE := validateRedirectURIsTemplate(ctx, template, values)
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

func validateURI(ctx context.Context, uri string) errors.E {
	u, err := url.ParseRequestURI(uri)
	if err != nil {
		errE := errors.Wrap(err, "unable to parse URI")
		errors.Details(errE)["uri"] = uri
		return errE
	}

	// The following two checks are the same as what we configured fosite to check.

	if !fosite.IsValidRedirectURI(u) {
		errE := errors.New("URI is not valid")
		errors.Details(errE)["uri"] = uri
		return errE
	}

	if !fosite.IsRedirectURISecureStrict(ctx, u) {
		errE := errors.New("URI is not secure")
		errors.Details(errE)["uri"] = uri
		return errE
	}

	return nil
}

func validateRedirectURIsTemplate(ctx context.Context, template string, values map[string]string) errors.E {
	if template == "" {
		return errors.New("is required")
	}

	value, errE := interpolateVariables(template, values)
	if errE != nil {
		return errE
	}

	return validateURI(ctx, value)
}

type ClientRef struct {
	ID identifier.Identifier `json:"id"`
}

type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return x.MarshalWithoutEscapeHTML(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	errE := x.UnmarshalWithoutUnknownFields(b, &s)
	if errE != nil {
		return errE
	}
	tmp, err := time.ParseDuration(s)
	if err != nil {
		return errors.WithDetails(err, "duration", s)
	}
	*d = Duration(tmp)
	return nil
}

type ApplicationTemplateClientPublic struct {
	ID          *identifier.Identifier `json:"id"`
	Description string                 `json:"description"`

	AdditionalScopes []string `json:"additionalScopes"`

	AccessTokenType AccessTokenType `json:"accessTokenType"`

	RedirectURITemplates []string `json:"redirectUriTemplates"`

	AccessTokenLifespan  Duration  `json:"accessTokenLifespan"`
	IDTokenLifespan      Duration  `json:"idTokenLifespan"`
	RefreshTokenLifespan *Duration `json:"refreshTokenLifespan,omitempty"`
}

func (c *ApplicationTemplateClientPublic) Validate(ctx context.Context, existing *ApplicationTemplateClientPublic, values map[string]string) errors.E {
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

	if c.AdditionalScopes == nil {
		c.AdditionalScopes = []string{}
	}

	for i, scope := range c.AdditionalScopes {
		if !validScopeRegexp.MatchString(scope) {
			errE := errors.New("invalid scope")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["scope"] = scope
			return errE
		}
	}

	// We remove duplicates and empty strings.
	c.AdditionalScopes = removeDuplicates(c.AdditionalScopes)
	c.AdditionalScopes = slices.DeleteFunc(c.AdditionalScopes, func(scope string) bool {
		return scope == ""
	})

	switch c.AccessTokenType {
	case AccessTokenJWT:
	case AccessTokenHMAC:
	default:
		errE := errors.New("unsupported access token type")
		errors.Details(errE)["type"] = c.AccessTokenType
		return errE
	}

	redirectURIsTemplates, errE := validateRedirectURITemplates(ctx, c.RedirectURITemplates, values)
	if errE != nil {
		return errE
	}
	c.RedirectURITemplates = redirectURIsTemplates

	if c.AccessTokenLifespan <= 0 {
		return errors.New("access token lifespan is not set")
	}
	if c.IDTokenLifespan <= 0 {
		return errors.New("ID token lifespan is not set")
	}
	if c.RefreshTokenLifespan != nil && *c.RefreshTokenLifespan <= 0 {
		return errors.New("refresh token lifespan is invalid")
	}

	return nil
}

type ApplicationTemplateClientBackend struct {
	ID          *identifier.Identifier `json:"id"`
	Description string                 `json:"description"`

	AdditionalScopes []string `json:"additionalScopes"`

	AccessTokenType AccessTokenType `json:"accessTokenType"`

	TokenEndpointAuthMethod string   `json:"tokenEndpointAuthMethod"`
	RedirectURITemplates    []string `json:"redirectUriTemplates"`

	AccessTokenLifespan  Duration  `json:"accessTokenLifespan"`
	IDTokenLifespan      Duration  `json:"idTokenLifespan"`
	RefreshTokenLifespan *Duration `json:"refreshTokenLifespan,omitempty"`
}

func (c *ApplicationTemplateClientBackend) Validate(ctx context.Context, existing *ApplicationTemplateClientBackend, values map[string]string) errors.E {
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

	if c.AdditionalScopes == nil {
		c.AdditionalScopes = []string{}
	}

	for i, scope := range c.AdditionalScopes {
		if !validScopeRegexp.MatchString(scope) {
			errE := errors.New("invalid scope")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["scope"] = scope
			return errE
		}
	}

	// We remove duplicates and empty strings.
	c.AdditionalScopes = removeDuplicates(c.AdditionalScopes)
	c.AdditionalScopes = slices.DeleteFunc(c.AdditionalScopes, func(scope string) bool {
		return scope == ""
	})

	switch c.AccessTokenType {
	case AccessTokenJWT:
	case AccessTokenHMAC:
	default:
		errE := errors.New("unsupported access token type")
		errors.Details(errE)["type"] = c.AccessTokenType
		return errE
	}

	switch c.TokenEndpointAuthMethod {
	case "client_secret_post":
	case "client_secret_basic":
	default:
		errE := errors.New("unsupported token endpoint auth method")
		errors.Details(errE)["method"] = c.TokenEndpointAuthMethod
		return errE
	}

	redirectURIsTemplates, errE := validateRedirectURITemplates(ctx, c.RedirectURITemplates, values)
	if errE != nil {
		return errE
	}
	c.RedirectURITemplates = redirectURIsTemplates

	if c.AccessTokenLifespan <= 0 {
		return errors.New("access token lifespan is not set")
	}
	if c.IDTokenLifespan <= 0 {
		return errors.New("ID token lifespan is not set")
	}
	if c.RefreshTokenLifespan != nil && *c.RefreshTokenLifespan <= 0 {
		return errors.New("refresh token lifespan is invalid")
	}

	return nil
}

type ApplicationTemplateClientService struct {
	ID          *identifier.Identifier `json:"id"`
	Description string                 `json:"description"`

	AdditionalScopes []string `json:"additionalScopes"`

	AccessTokenType AccessTokenType `json:"accessTokenType"`

	TokenEndpointAuthMethod string `json:"tokenEndpointAuthMethod"`

	AccessTokenLifespan  Duration  `json:"accessTokenLifespan"`
	IDTokenLifespan      Duration  `json:"idTokenLifespan"`
	RefreshTokenLifespan *Duration `json:"refreshTokenLifespan,omitempty"`
}

func (c *ApplicationTemplateClientService) Validate(_ context.Context, existing *ApplicationTemplateClientService, _ map[string]string) errors.E {
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

	if c.AdditionalScopes == nil {
		c.AdditionalScopes = []string{}
	}

	for i, scope := range c.AdditionalScopes {
		if !validScopeRegexp.MatchString(scope) {
			errE := errors.New("invalid scope")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["scope"] = scope
			return errE
		}
	}

	// We remove duplicates and empty strings.
	c.AdditionalScopes = removeDuplicates(c.AdditionalScopes)
	c.AdditionalScopes = slices.DeleteFunc(c.AdditionalScopes, func(scope string) bool {
		return scope == ""
	})

	switch c.AccessTokenType {
	case AccessTokenJWT:
	case AccessTokenHMAC:
	default:
		errE := errors.New("unsupported access token type")
		errors.Details(errE)["type"] = c.AccessTokenType
		return errE
	}

	switch c.TokenEndpointAuthMethod {
	case "client_secret_post":
	case "client_secret_basic":
	default:
		errE := errors.New("unsupported token endpoint auth method")
		errors.Details(errE)["method"] = c.TokenEndpointAuthMethod
		return errE
	}

	if c.AccessTokenLifespan <= 0 {
		return errors.New("access token lifespan is not set")
	}
	if c.IDTokenLifespan <= 0 {
		return errors.New("ID token lifespan is not set")
	}
	if c.RefreshTokenLifespan != nil && *c.RefreshTokenLifespan <= 0 {
		return errors.New("refresh token lifespan is invalid")
	}

	return nil
}

type VariableType string

const (
	VariableURIPrefix VariableType = "uriPrefix"
)

var validationValues = map[VariableType]string{ //nolint:gochecknoglobals
	VariableURIPrefix: "https://sub.example.com:8080/foo",
}

type Variable struct {
	Name        string       `json:"name"`
	Type        VariableType `json:"type"`
	Description string       `json:"description"`
}

func (v *Variable) Validate(_ context.Context) errors.E {
	if v.Name == "" {
		return errors.New("name is required")
	}

	switch v.Type {
	case VariableURIPrefix:
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
	ApplicationTemplatePublic

	Admins []IdentityRef `json:"admins"`
}

type ApplicationTemplatePublic struct {
	ID *identifier.Identifier `json:"id"`

	Name             string `json:"name"`
	Description      string `json:"description"`
	HomepageTemplate string `json:"homepageTemplate"`

	IDScopes []string `json:"idScopes"`

	Variables      []Variable                         `json:"variables"`
	ClientsPublic  []ApplicationTemplateClientPublic  `json:"clientsPublic"`
	ClientsBackend []ApplicationTemplateClientBackend `json:"clientsBackend"`
	ClientsService []ApplicationTemplateClientService `json:"clientsService"`
}

func (a *ApplicationTemplatePublic) GetClientPublic(id *identifier.Identifier) *ApplicationTemplateClientPublic {
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

func (a *ApplicationTemplatePublic) GetClientBackend(id *identifier.Identifier) *ApplicationTemplateClientBackend {
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

func (a *ApplicationTemplatePublic) GetClientService(id *identifier.Identifier) *ApplicationTemplateClientService {
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

type ApplicationTemplateRef struct {
	ID identifier.Identifier `json:"id"`
}

func (a *ApplicationTemplatePublic) Validate(ctx context.Context, existing *ApplicationTemplatePublic) errors.E {
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

	if a.Name == "" {
		return errors.New("name is required")
	}

	if a.IDScopes == nil {
		a.IDScopes = []string{}
	}

	for i, scope := range a.IDScopes {
		if !validScopeRegexp.MatchString(scope) {
			errE := errors.New("invalid scope")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["scope"] = scope
			return errE
		}
	}

	// We remove duplicates and empty strings.
	a.IDScopes = removeDuplicates(a.IDScopes)
	a.IDScopes = slices.DeleteFunc(a.IDScopes, func(scope string) bool {
		return scope == ""
	})

	// TODO: Validate that a.IDScopes is a (non-strict) subset of supported ID scopes.

	if a.Variables == nil {
		// Default variable.
		a.Variables = []Variable{{
			Name:        "uriBase",
			Type:        VariableURIPrefix,
			Description: "uriBase is a URI prefix used to construct URIs (e.g., OIDC redirect URIs) based on the domain on which the application is deployed.",
		}}
	}

	values := map[string]string{}
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
		values[variable.Name] = validationValues[variable.Type]

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
		errE := client.Validate(ctx, existing.GetClientPublic(client.ID), values)
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
		errE := client.Validate(ctx, existing.GetClientBackend(client.ID), values)
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
		errE := client.Validate(ctx, existing.GetClientService(client.ID), values)
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

	// If there is standard uriBase variable, we populate with default homepage.
	if a.HomepageTemplate == "" && slices.ContainsFunc(a.Variables, func(v Variable) bool { return v.Name == "uriBase" }) {
		a.HomepageTemplate = "{uriBase}"
	}

	if a.HomepageTemplate == "" {
		return errors.New("homepage template: is required")
	}

	errE := validateRedirectURIsTemplate(ctx, a.HomepageTemplate, values)
	if errE != nil {
		errE = errors.WithMessage(errE, "homepage template")
		errors.Details(errE)["template"] = a.HomepageTemplate
		return errE
	}

	return nil
}

func (a *ApplicationTemplate) HasAdminAccess(identities ...IdentityRef) bool {
	for _, identity := range identities {
		if slices.Contains(a.Admins, identity) {
			return true
		}
	}
	return false
}

// Validate requires ctx with identityIDContextKey set.
func (a *ApplicationTemplate) Validate(ctx context.Context, existing *ApplicationTemplate, service *Service) errors.E {
	var e *ApplicationTemplatePublic
	if existing == nil {
		e = nil
	} else {
		e = &existing.ApplicationTemplatePublic
	}
	errE := a.ApplicationTemplatePublic.Validate(ctx, e)
	if errE != nil {
		return errE
	}

	// Current user must be among admins if it is changing the application template.
	// We check this elsewhere, here we make sure the user is stored as an admin.
	identity := IdentityRef{ID: mustGetIdentityID(ctx)}
	if !a.HasAdminAccess(identity) {
		a.Admins = append(a.Admins, identity)
	}

	// We remove duplicates.
	a.Admins = removeDuplicates(a.Admins)

	// TODO: Once we have an invitation system, limit only to identities which have been joined the Charon organization.
	//       For now we have to allow all identities so that a user can add another identity before they decide to join the Charon organization.
	//       With the invitation system, identities will be added to admins only after they have accepted the invitation.
	//       With general permission system this field will be moved out of the organization document anyway, too.
	unknown := service.hasIdentities(ctx, mapset.NewThreadUnsafeSet(a.Admins...), true)
	if !unknown.IsEmpty() {
		errE := errors.New("unknown identities")
		identities := unknown.ToSlice()
		slices.SortFunc(identities, func(a IdentityRef, b IdentityRef) int {
			return bytes.Compare(a.ID[:], b.ID[:])
		})
		errors.Details(errE)["identities"] = identities
		return errE
	}

	return nil
}

func (s *Service) getApplicationTemplate(_ context.Context, id identifier.Identifier) (*ApplicationTemplate, errors.E) {
	s.applicationTemplatesMu.RLock()
	defer s.applicationTemplatesMu.RUnlock()

	data, ok := s.applicationTemplates[id]
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

func (s *Service) createApplicationTemplate(ctx context.Context, applicationTemplate *ApplicationTemplate) errors.E {
	errE := applicationTemplate.Validate(ctx, nil, s)
	if errE != nil {
		return errors.WrapWith(errE, ErrApplicationTemplateValidationFailed)
	}

	data, errE := x.MarshalWithoutEscapeHTML(applicationTemplate)
	if errE != nil {
		return errE
	}

	s.applicationTemplatesMu.Lock()
	defer s.applicationTemplatesMu.Unlock()

	s.applicationTemplates[*applicationTemplate.ID] = data

	errE = s.logActivity(ctx, ActivityApplicationTemplateCreate, nil, nil, applicationTemplate.ID, nil)
	if errE != nil {
		return errE
	}

	return nil
}

func (s *Service) updateApplicationTemplate(ctx context.Context, applicationTemplate *ApplicationTemplate) errors.E {
	s.applicationTemplatesMu.Lock()
	defer s.applicationTemplatesMu.Unlock()

	if applicationTemplate.ID == nil {
		return errors.WithMessage(ErrApplicationTemplateValidationFailed, "ID is missing")
	}

	existingData, ok := s.applicationTemplates[*applicationTemplate.ID]
	if !ok {
		return errors.WithDetails(ErrApplicationTemplateNotFound, "id", *applicationTemplate.ID)
	}

	var existingApplicationTemplate ApplicationTemplate
	errE := x.UnmarshalWithoutUnknownFields(existingData, &existingApplicationTemplate)
	if errE != nil {
		errors.Details(errE)["id"] = *applicationTemplate.ID
		return errE
	}

	if !existingApplicationTemplate.HasAdminAccess(IdentityRef{ID: mustGetIdentityID(ctx)}) {
		return errors.WithDetails(ErrApplicationTemplateUnauthorized, "id", *applicationTemplate.ID)
	}

	errE = applicationTemplate.Validate(ctx, &existingApplicationTemplate, s)
	if errE != nil {
		return errors.WrapWith(errE, ErrApplicationTemplateValidationFailed)
	}

	data, errE := x.MarshalWithoutEscapeHTML(applicationTemplate)
	if errE != nil {
		errors.Details(errE)["id"] = *applicationTemplate.ID
		return errE
	}

	s.applicationTemplates[*applicationTemplate.ID] = data

	errE = s.logActivity(ctx, ActivityApplicationTemplateUpdate, nil, nil, applicationTemplate.ID, nil)
	if errE != nil {
		return errE
	}

	return nil
}

func (s *Service) ApplicationTemplateGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) ApplicationTemplateCreate(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	// We always serve the page and leave to the API call to check permissions.

	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) ApplicationTemplateList(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) getApplicationTemplateFromID(ctx context.Context, value string) (*ApplicationTemplate, errors.E) {
	id, errE := identifier.MaybeString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrApplicationTemplateNotFound)
	}

	return s.getApplicationTemplate(ctx, id)
}

func (s *Service) returnApplicationTemplateRef(_ context.Context, w http.ResponseWriter, req *http.Request, applicationTemplate *ApplicationTemplate) {
	s.WriteJSON(w, req, ApplicationTemplateRef{ID: *applicationTemplate.ID}, nil)
}

func (s *Service) ApplicationTemplateGetGet(w http.ResponseWriter, req *http.Request, params waf.Params) { //nolint:dupl
	ctx := req.Context()
	co := s.charonOrganization()

	hasIdentity := false
	identityID, _, sessionID, errE := s.getIdentityFromRequest(w, req, co.AppID.String())
	if errE == nil {
		ctx = s.withIdentityID(ctx, identityID)
		ctx = s.withSessionID(ctx, sessionID)
		hasIdentity = true
	} else if !errors.Is(errE, ErrIdentityNotPresent) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	applicationTemplate, errE := s.getApplicationTemplateFromID(ctx, params["id"])
	if errors.Is(errE, ErrApplicationTemplateNotFound) {
		s.NotFound(w, req)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if hasIdentity && applicationTemplate.HasAdminAccess(IdentityRef{ID: identityID}) {
		s.WriteJSON(w, req, applicationTemplate, map[string]interface{}{
			"can_update": true,
		})
		return
	}

	s.WriteJSON(w, req, applicationTemplate.ApplicationTemplatePublic, nil)
}

func (s *Service) ApplicationTemplateListGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	result := []ApplicationTemplateRef{}

	s.applicationTemplatesMu.RLock()
	defer s.applicationTemplatesMu.RUnlock()

	for id := range s.applicationTemplates {
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

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	var applicationTemplate ApplicationTemplate
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &applicationTemplate)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	// If applicationTemplate.ID == nil, updateApplicationTemplate returns an error.
	if applicationTemplate.ID != nil && params["id"] != applicationTemplate.ID.String() {
		errE = errors.New("params ID does not match payload ID")
		errors.Details(errE)["params"] = params["id"]
		errors.Details(errE)["payload"] = *applicationTemplate.ID
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = s.updateApplicationTemplate(ctx, &applicationTemplate)
	if errors.Is(errE, ErrApplicationTemplateUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errors.Is(errE, ErrApplicationTemplateNotFound) {
		s.NotFound(w, req)
		return
	} else if errors.Is(errE, ErrApplicationTemplateValidationFailed) {
		s.BadRequestWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnApplicationTemplateRef(ctx, w, req, &applicationTemplate)
}

func (s *Service) ApplicationTemplateCreatePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
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

	errE = s.createApplicationTemplate(ctx, &applicationTemplate)
	if errors.Is(errE, ErrApplicationTemplateValidationFailed) {
		s.BadRequestWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnApplicationTemplateRef(ctx, w, req, &applicationTemplate)
}
