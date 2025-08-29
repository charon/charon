package charon

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"reflect"
	"slices"

	"github.com/alexedwards/argon2id"
	mapset "github.com/deckarep/golang-set/v2"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

var (
	ErrOrganizationNotFound         = errors.Base("organization not found")
	ErrOrganizationAlreadyExists    = errors.Base("organization already exists")
	ErrOrganizationUnauthorized     = errors.Base("organization change unauthorized")
	ErrOrganizationValidationFailed = errors.Base("organization validation failed")
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

type OrganizationApplicationPublic struct {
	ID *identifier.Identifier `json:"id"`

	Active bool `json:"active"`

	// We store full application template for this deployment, so if upstream
	// application template changes, this one continues to be consistent.
	// It can in fact be even a template which has not been published at all.
	// TODO: Show to the organization admin that upstream template changed and invite them to update their template.
	ApplicationTemplate ApplicationTemplatePublic `json:"applicationTemplate"`

	Values []Value `json:"values"`
}

func (a *OrganizationApplicationPublic) Validate(ctx context.Context, existing *OrganizationApplicationPublic, service *Service) errors.E {
	_, errE := a.validate(ctx, existing, service)
	return errE
}

// validate is a version of Validate which returns values as well.
func (a *OrganizationApplicationPublic) validate(ctx context.Context, existing *OrganizationApplicationPublic, service *Service) (map[string]string, errors.E) {
	if existing == nil {
		if a.ID != nil {
			errE := errors.New("ID provided for new document")
			errors.Details(errE)["id"] = *a.ID
			return nil, errE
		}
		id := identifier.New()
		a.ID = &id
	} else if a.ID == nil {
		// This should not really happen because we fetch existing based on a.ID.
		return nil, errors.New("ID missing for existing document")
	} else if existing.ID == nil {
		// This should not really happen because we always store documents with ID.
		return nil, errors.New("ID missing for existing document")
	} else if *a.ID != *existing.ID {
		// This should not really happen because we fetch existing based on a.ID.
		errE := errors.New("payload ID does not match existing ID")
		errors.Details(errE)["payload"] = *a.ID
		errors.Details(errE)["existing"] = *existing.ID
		return nil, errE
	}

	var e *ApplicationTemplatePublic
	if existing != nil {
		e = &existing.ApplicationTemplate
	} else if a.ApplicationTemplate.ID != nil {
		at, errE := service.getApplicationTemplate(ctx, *a.ApplicationTemplate.ID)
		if errE == nil {
			e = &at.ApplicationTemplatePublic
		} else if !errors.Is(errE, ErrApplicationTemplateNotFound) {
			return nil, errE
		}
	}
	errE := a.ApplicationTemplate.Validate(ctx, e)
	if errE != nil {
		return nil, errE
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
			return nil, errE
		}

		if valuesSet.Contains(value.Name) {
			errE := errors.New("duplicate value")
			errors.Details(errE)["i"] = i
			errors.Details(errE)["name"] = value.Name
			return nil, errE
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
		return nil, errE
	}

	return values, nil
}

type OrganizationApplication struct {
	OrganizationApplicationPublic

	ClientsPublic  []OrganizationApplicationClientPublic  `json:"clientsPublic"`
	ClientsBackend []OrganizationApplicationClientBackend `json:"clientsBackend"`
	ClientsService []OrganizationApplicationClientService `json:"clientsService"`
}

type OrganizationApplicationApplicationRef struct {
	ID identifier.Identifier `json:"id"`
}

func organizationApplicationApplicationRefCmp(a OrganizationApplicationApplicationRef, b OrganizationApplicationApplicationRef) int {
	return bytes.Compare(a.ID[:], b.ID[:])
}

type OrganizationApplicationRef struct {
	Organization OrganizationRef                       `json:"organization"`
	Application  OrganizationApplicationApplicationRef `json:"application"`
}

func organizationApplicationRefCmp(a OrganizationApplicationRef, b OrganizationApplicationRef) int {
	if c := organizationRefCmp(a.Organization, b.Organization); c != 0 {
		return c
	}
	return organizationApplicationApplicationRefCmp(a.Application, b.Application)
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

func (a *OrganizationApplication) Validate(ctx context.Context, existing *OrganizationApplication, service *Service) errors.E {
	var e *OrganizationApplicationPublic
	if existing == nil {
		e = nil
	} else {
		e = &existing.OrganizationApplicationPublic
	}
	values, errE := a.OrganizationApplicationPublic.validate(ctx, e, service)
	if errE != nil {
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

type BlockedIdentityType string

const (
	BlockedIdentityNotBlocked  BlockedIdentityType = "notBlocked"
	BlockedIdentityOnly        BlockedIdentityType = "onlyIdentity"
	BlockedIdentityAndAccounts BlockedIdentityType = "identityAndAccounts"
)

type BlockedIdentity struct {
	OrganizationNote string
	IdentityNote     string
}

type Organization struct {
	OrganizationPublic

	Admins []IdentityRef `json:"admins"`

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

func organizationRefCmp(a OrganizationRef, b OrganizationRef) int {
	return bytes.Compare(a.ID[:], b.ID[:])
}

// HasAdminAccess returns true if at least one of the identities is among admins.
func (o *Organization) HasAdminAccess(identities ...IdentityRef) bool {
	for _, identity := range identities {
		if slices.Contains(o.Admins, identity) {
			return true
		}
	}
	return false
}

// Validate requires ctx with identityIDContextKey set.
func (o *Organization) Validate(ctx context.Context, existing *Organization, service *Service) errors.E {
	// Current user must be among admins if it is changing the organization.
	// We check this elsewhere, here we make sure the user is stored as an admin.
	currentIdentity := IdentityRef{ID: mustGetIdentityID(ctx)}
	if !o.HasAdminAccess(currentIdentity) {
		o.Admins = append(o.Admins, currentIdentity)
	}

	return o.validate(ctx, existing, service)
}

// validate is a version of Validate which allows empty Admins.
func (o *Organization) validate(ctx context.Context, existing *Organization, service *Service) errors.E {
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

	// We remove duplicates.
	o.Admins = removeDuplicates(o.Admins)

	// TODO: Once we have an invitation system, limit only to identities which have been joined the Charon organization.
	//       For now we have to allow all identities so that a user can add another identity before they decide to join the Charon organization.
	//       With the invitation system, identities will be added to admins only after they have accepted the invitation.
	//       With general permission system this field will be moved out of the organization document anyway, too.
	unknown := service.hasIdentities(ctx, mapset.NewThreadUnsafeSet(o.Admins...), true)
	if !unknown.IsEmpty() {
		errE := errors.New("unknown identities")
		identities := unknown.ToSlice()
		slices.SortFunc(identities, identityRefCmp)
		errors.Details(errE)["identities"] = identities
	}

	if o.Applications == nil {
		o.Applications = []OrganizationApplication{}
	}

	appsSet := mapset.NewThreadUnsafeSet[identifier.Identifier]()
	for i, orgApp := range o.Applications {
		errE := orgApp.Validate(ctx, existing.GetApplication(orgApp.ID), service)
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

// Changes compares the current Organization with an existing one and returns the types of changes
// that occurred, admin identities that were added or removed and organization applications
// that were added, removed or changed.
func (o *Organization) Changes(existing *Organization) ([]ActivityChangeType, []IdentityRef, []OrganizationApplicationRef) {
	changes := []ActivityChangeType{}

	if !reflect.DeepEqual(o.OrganizationPublic, existing.OrganizationPublic) {
		changes = append(changes, ActivityChangeOtherData)
	}

	adminsAdded, adminsRemoved := detectSliceChanges(existing.Admins, o.Admins)

	if !adminsAdded.IsEmpty() {
		changes = append(changes, ActivityChangePermissionsAdded)
	}
	if !adminsRemoved.IsEmpty() {
		changes = append(changes, ActivityChangePermissionsRemoved)
	}

	identitiesChanged := adminsAdded.Union(adminsRemoved).ToSlice()
	slices.SortFunc(identitiesChanged, identityRefCmp)

	// We make copies of app structs on purpose, so that we can change Active field as needed.
	existingAppMap := make(map[OrganizationApplicationRef]OrganizationApplication)
	for _, app := range existing.Applications {
		existingAppMap[OrganizationApplicationRef{
			Organization: OrganizationRef{ID: *o.ID},
			Application: OrganizationApplicationApplicationRef{
				ID: *app.ID,
			},
		}] = app
	}
	newAppMap := make(map[OrganizationApplicationRef]OrganizationApplication)
	for _, app := range o.Applications {
		newAppMap[OrganizationApplicationRef{
			Organization: OrganizationRef{ID: *o.ID},
			Application: OrganizationApplicationApplicationRef{
				ID: *app.ID,
			},
		}] = app
	}

	existingAppSet := mapset.NewThreadUnsafeSetFromMapKeys(existingAppMap)
	newAppSet := mapset.NewThreadUnsafeSetFromMapKeys(newAppMap)

	addedAppSet := newAppSet.Difference(existingAppSet)
	removedAppSet := existingAppSet.Difference(newAppSet)

	changedAppSet := mapset.NewThreadUnsafeSet[OrganizationApplicationRef]()
	activatedAppSet := mapset.NewThreadUnsafeSet[OrganizationApplicationRef]()
	disabledAppSet := mapset.NewThreadUnsafeSet[OrganizationApplicationRef]()

	// Compare applications which are in both sets.
	for appRef := range mapset.Elements(newAppSet.Intersect(existingAppSet)) {
		existingApp := existingAppMap[appRef]
		newApp := newAppMap[appRef]

		if newApp.Active && !existingApp.Active {
			activatedAppSet.Add(appRef)
		}
		if !newApp.Active && existingApp.Active {
			disabledAppSet.Add(appRef)
		}

		// We make Active field the same and in this way compare the rest.
		existingApp.Active = newApp.Active
		if !reflect.DeepEqual(existingApp, newApp) {
			changedAppSet.Add(appRef)
		}
	}

	if !addedAppSet.IsEmpty() {
		changes = append(changes, ActivityChangeMembershipAdded)
	}
	if !removedAppSet.IsEmpty() {
		changes = append(changes, ActivityChangeMembershipRemoved)
	}
	if !changedAppSet.IsEmpty() {
		changes = append(changes, ActivityChangeMembershipChanged)
	}
	if !activatedAppSet.IsEmpty() {
		changes = append(changes, ActivityChangeMembershipActivated)
	}
	if !disabledAppSet.IsEmpty() {
		changes = append(changes, ActivityChangeMembershipDisabled)
	}

	appsChanged := addedAppSet.Union(removedAppSet).Union(changedAppSet).Union(activatedAppSet).Union(disabledAppSet).ToSlice()
	slices.SortFunc(appsChanged, organizationApplicationRefCmp)

	return changes, identitiesChanged, appsChanged
}

func (s *Service) getOrganization(_ context.Context, id identifier.Identifier) (*Organization, errors.E) {
	s.organizationsMu.RLock()
	defer s.organizationsMu.RUnlock()

	data, ok := s.organizations[id]
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

func (s *Service) createOrganization(ctx context.Context, organization *Organization) errors.E {
	errE := organization.Validate(ctx, nil, s)
	if errE != nil {
		return errors.WrapWith(errE, ErrOrganizationValidationFailed)
	}

	data, errE := x.MarshalWithoutEscapeHTML(organization)
	if errE != nil {
		return errE
	}

	s.organizationsMu.Lock()
	defer s.organizationsMu.Unlock()

	s.organizations[*organization.ID] = data

	errE = s.logActivity(ctx, ActivityOrganizationCreate, nil, []OrganizationRef{{ID: *organization.ID}}, nil, nil, nil, nil, nil)
	if errE != nil {
		return errE
	}

	return nil
}

func (s *Service) updateOrganization(ctx context.Context, organization *Organization) errors.E {
	s.organizationsMu.Lock()
	defer s.organizationsMu.Unlock()

	if organization.ID == nil {
		return errors.WithMessage(ErrOrganizationValidationFailed, "ID is missing")
	}

	existingData, ok := s.organizations[*organization.ID]
	if !ok {
		return errors.WithDetails(ErrOrganizationNotFound, "id", *organization.ID)
	}

	var existingOrganization Organization
	errE := x.UnmarshalWithoutUnknownFields(existingData, &existingOrganization)
	if errE != nil {
		errors.Details(errE)["id"] = *organization.ID
		return errE
	}

	currentIdentity := IdentityRef{ID: mustGetIdentityID(ctx)}
	if !existingOrganization.HasAdminAccess(currentIdentity) {
		return errors.WithDetails(ErrOrganizationUnauthorized, "id", organization.ID)
	}

	errE = organization.Validate(ctx, &existingOrganization, s)
	if errE != nil {
		return errors.WrapWith(errE, ErrOrganizationValidationFailed)
	}

	data, errE := x.MarshalWithoutEscapeHTML(organization)
	if errE != nil {
		errors.Details(errE)["id"] = *organization.ID
		return errE
	}

	changes, identities, organizationApplications := organization.Changes(&existingOrganization)

	if len(changes) == 0 {
		// No changes, do not continue.
		return nil
	}

	s.organizations[*organization.ID] = data

	errE = s.logActivity(ctx, ActivityOrganizationUpdate, identities, []OrganizationRef{{ID: *organization.ID}}, nil, organizationApplications, nil, changes, nil)
	if errE != nil {
		return errE
	}

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
	// We always serve the page and leave to the API call to check permissions.

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

func (s *Service) OrganizationUsers(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) getOrganizationFromID(ctx context.Context, value string) (*Organization, errors.E) {
	id, errE := identifier.MaybeString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrOrganizationNotFound)
	}

	return s.getOrganization(ctx, id)
}

func (s *Service) returnOrganizationRef(_ context.Context, w http.ResponseWriter, req *http.Request, organization *Organization) {
	s.WriteJSON(w, req, OrganizationRef{ID: *organization.ID}, nil)
}

func (s *Service) OrganizationGetGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := req.Context()
	co := s.charonOrganization()

	hasIdentity := false
	identityID, _, _, errE := s.getIdentityFromRequest(w, req, co.AppID.String())
	if errE == nil {
		hasIdentity = true
	} else if !errors.Is(errE, ErrIdentityNotPresent) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	organization, errE := s.getOrganizationFromID(ctx, params["id"])
	if errors.Is(errE, ErrOrganizationNotFound) {
		s.NotFoundWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if hasIdentity && organization.HasAdminAccess(IdentityRef{ID: identityID}) {
		s.WriteJSON(w, req, organization, map[string]interface{}{
			"can_update": true,
		})
		return
	}

	s.WriteJSON(w, req, organization.OrganizationPublic, nil)
}

// TODO: We should get rid of OrganizationApp API endpoint and make OrganizationGetGet return a list of public data for all its applications.

func (s *Service) OrganizationAppGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := req.Context()

	organization, errE := s.getOrganizationFromID(ctx, params["id"])
	if errors.Is(errE, ErrOrganizationNotFound) {
		s.NotFoundWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	appID, errE := identifier.MaybeString(params["appId"])
	if errE != nil {
		s.NotFoundWithError(w, req, errors.WrapWith(errE, ErrApplicationTemplateNotFound))
		return
	}

	orgApp := organization.GetApplication(&appID)
	if orgApp == nil {
		s.NotFound(w, req)
		return
	}

	if !orgApp.Active {
		s.NotFound(w, req)
		return
	}

	s.WriteJSON(w, req, orgApp.OrganizationApplicationPublic, nil)
}

type OrganizationIdentity struct {
	IdentityPublic

	Organizations []IdentityOrganization `json:"organizations,omitempty"`
}

func (s *Service) getIdentityFromOrganization(_ context.Context, organizationID, identityID identifier.Identifier) (*Identity, *IdentityOrganization, errors.E) {
	s.identitiesMu.RLock()
	defer s.identitiesMu.RUnlock()

	// TODO: Use an index instead of iterating over all identities.
	for id, data := range s.identities {
		var identity Identity
		errE := x.UnmarshalWithoutUnknownFields(data, &identity)
		if errE != nil {
			errors.Details(errE)["id"] = id
			return nil, nil, errE
		}

		idOrg := identity.GetOrganization(&organizationID)
		if idOrg == nil || *idOrg.ID != identityID {
			continue
		}

		return &identity, idOrg, nil
	}

	return nil, nil, errors.WithDetails(ErrIdentityNotFound, "id", identityID)
}

// Anyone with valid access token for the organization can access public data about any
// identity in the organization given the organization-scoped identity ID.
//
// A special case is for admins of the organization, which can also authenticate using
// valid Charon organization access token. In that case, also Organizations field is returned
// with IdentityOrganization struct for just this organization.
func (s *Service) OrganizationIdentityGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := req.Context()
	co := s.charonOrganization()

	organizationID, errE := identifier.MaybeString(params["id"])
	if errE != nil {
		s.NotFoundWithError(w, req, errors.WrapWith(errE, ErrOrganizationNotFound))
		return
	}

	identityID, errE := identifier.MaybeString(params["identityId"])
	if errE != nil {
		s.NotFoundWithError(w, req, errors.WrapWith(errE, ErrIdentityNotFound))
		return
	}

	hasOrganizationAccessToken := true

	// We do not use RequireAuthenticated here, because we want to use a (possibly) non-Charon organization ID.
	currentIdentityID, accountID, _, errE := s.getIdentityFromRequest(w, req, organizationID.String())
	if errors.Is(errE, ErrIdentityNotPresent) {
		// User is not authenticated for this organization.
		// Maybe they are authenticated using Charon organization and are admin of the organization.

		hasOrganizationAccessToken = false

		currentIdentityID, accountID, _, errE = s.getIdentityFromRequest(w, req, co.AppID.String())
		if errors.Is(errE, ErrIdentityNotPresent) {
			s.WithError(ctx, errE)
			waf.Error(w, req, http.StatusUnauthorized)
			return
		} else if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		organization, errE := s.getOrganizationFromID(ctx, params["id"]) //nolint:govet
		if errors.Is(errE, ErrOrganizationNotFound) {
			s.NotFoundWithError(w, req, errE)
			return
		} else if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		if !organization.HasAdminAccess(IdentityRef{ID: currentIdentityID}) {
			waf.Error(w, req, http.StatusUnauthorized)
			return
		}
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	var identity *Identity
	var idOrg *IdentityOrganization

	if co.ID == organizationID {
		// A special case for Charon organization: organization-scoped identity ID is the same as the identity ID.
		// We need a special case here because we want to return even identities which have not been added to the
		// Charon organization (so that users can give permissions over identities to other users while those
		// identities have never been used with the Charon organization itself).

		// TODO: This allows everyone to access data about an identity given only its database ID.
		//       This is problematic because somebody might create an identity to be used only with a particular organization,
		//       never to be shared with other users (so there is no need for identity to be available through this endpoint),
		//       without giving any consent that data can be shared with others. While we do not expose all database IDs it is
		//       still problematic that data is protected only by secrecy of the database ID. Currently we do this to allow
		//       permissions between identities. But once we have an invitation system and general permission system,
		//       then we can expose through this endpoint only identities a) which have joined the Charon organization, or
		//       b) have accepted an invite to be added to a permission. Importantly, identities which have been invited but never
		//       accepted the invite should not have their data revealed, only information provided by the inviter should be shown.

		identity, errE = s.getIdentityWithoutAccessCheck(ctx, identityID)
		if errors.Is(errE, ErrIdentityNotFound) {
			s.NotFoundWithError(w, req, errE)
			return
		} else if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		idOrg = identity.GetOrganization(&organizationID)
	} else {
		identity, idOrg, errE = s.getIdentityFromOrganization(ctx, organizationID, identityID)
		if errors.Is(errE, ErrIdentityNotFound) {
			s.NotFoundWithError(w, req, errE)
			return
		} else if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		if !idOrg.Active {
			s.NotFound(w, req)
			return
		}

		// We do not want to expose the link between the database ID and the organization-scoped ID.
		identity.ID = idOrg.ID
	}

	// TODO: Expose only those fields the access tokens have access to through its scopes.
	//       E.g., backend access token might access e-mail address while frontend access token might not need access to e-mail address.
	//       How can we support that the frontend access token accesses e-mail address of the currently signed-in user but not of all other users?

	// TODO: Can we expose only those identities to which the user needs access but not to all of them?
	//       (Because they are referenced by anything the user has access to.) On the other hand, the user can access only identities for which they know
	//       their ID and presumably they learned those IDs by having access to something which referenced those IDs. So unless we enable identity enumeration,
	//       how it is might be enough (and even then we would probably enable enumeration only to identities to which user needs access).

	ids, isCreator, errE := s.getIdentitiesForAccount(ctx, accountID, IdentityRef{ID: *identity.ID})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if hasOrganizationAccessToken {
		// Only when organization admin is requesting identity information,
		// we return additional field Organizations.
		idOrg = nil
	}

	organizations := []IdentityOrganization{}
	if idOrg != nil {
		organizations = append(organizations, *idOrg)
	}

	s.WriteJSON(w, req, OrganizationIdentity{
		IdentityPublic: identity.IdentityPublic,
		Organizations:  organizations,
	}, map[string]interface{}{
		"can_use":    identity.HasUserAccess(ids),
		"can_update": identity.HasAdminAccess(ids, isCreator),
		// identity.ID is organization-scoped (we make it so above) and it makes sense to
		// compare it with currentIdentityID only if currentIdentityID belongs to the same
		// organization and not to Charon organization from the special case.
		// (It might be that organization is in fact Charon organization, but that should be
		// then handled as the first case and not as the special case.)
		"is_current": hasOrganizationAccessToken && *identity.ID == currentIdentityID,
	})
}

func (s *Service) OrganizationListGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	result := []OrganizationRef{}

	s.organizationsMu.RLock()
	defer s.organizationsMu.RUnlock()

	for id := range s.organizations {
		result = append(result, OrganizationRef{ID: id})
	}

	slices.SortFunc(result, organizationRefCmp)

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) OrganizationUpdatePost(w http.ResponseWriter, req *http.Request, params waf.Params) { //nolint:dupl
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	var organization Organization
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &organization)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	// If organization.ID == nil, updateOrganization returns an error.
	if organization.ID != nil && params["id"] != organization.ID.String() {
		errE = errors.New("params ID does not match payload ID")
		errors.Details(errE)["params"] = params["id"]
		errors.Details(errE)["payload"] = *organization.ID
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = s.updateOrganization(ctx, &organization)
	if errors.Is(errE, ErrOrganizationUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errors.Is(errE, ErrOrganizationNotFound) {
		s.NotFoundWithError(w, req, errE)
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

	ctx := s.RequireAuthenticated(w, req)
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

	errE = s.createOrganization(ctx, &organization)
	if errors.Is(errE, ErrOrganizationValidationFailed) {
		s.BadRequestWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnOrganizationRef(ctx, w, req, &organization)
}

func (s *Service) OrganizationUsersGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	organization, errE := s.getOrganizationFromID(ctx, params["id"])
	if errors.Is(errE, ErrOrganizationNotFound) {
		s.NotFoundWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if !organization.HasAdminAccess(IdentityRef{ID: mustGetIdentityID(ctx)}) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	}

	result := []IdentityRef{}

	s.identitiesMu.RLock()
	defer s.identitiesMu.RUnlock()

	for _, data := range s.identities {
		var identity Identity
		errE := x.UnmarshalWithoutUnknownFields(data, &identity)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		idOrg := identity.GetOrganization(organization.ID)
		// TODO: Should admins be able to see also users who have disabled organization, but have still joined in the past?
		//       If we allow this, we should also change OrganizationIdentityGet to return disabled identities for admins, too.
		if idOrg != nil && idOrg.Active {
			result = append(result, IdentityRef{ID: *idOrg.ID})
		}
	}

	slices.SortFunc(result, identityRefCmp)

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) isIdentityOrAccountBlockedInOrganization(_ context.Context, identity *Identity, accountID, organizationID identifier.Identifier) (bool, errors.E) {
	s.identitiesBlockedMu.RLock()
	defer s.identitiesBlockedMu.RUnlock()

	// Check if the identity is blocked in the organization.
	idOrg := identity.GetOrganization(&organizationID)
	if idOrg != nil && s.identitiesBlocked[organizationID] != nil {
		_, ok := s.identitiesBlocked[organizationID][*idOrg.ID]
		if ok {
			return true, nil
		}
	}

	// Check if the account is blocked in the organization.
	if s.accountsBlocked[organizationID] != nil {
		_, ok := s.accountsBlocked[organizationID][accountID]
		if ok {
			return true, nil
		}
	}

	return false, nil
}

func (s *Service) unblockIdentity(ctx context.Context, identity *Identity, orgIdentityID, organizationID identifier.Identifier) errors.E {
	s.identitiesBlockedMu.Lock()
	defer s.identitiesBlockedMu.Unlock()

	if s.identitiesBlocked[organizationID] == nil {
		return nil
	}

	_, ok := s.identitiesBlocked[organizationID][orgIdentityID]

	delete(s.identitiesBlocked[organizationID], orgIdentityID)

	if len(s.identitiesBlocked[organizationID]) == 0 {
		delete(s.identitiesBlocked, organizationID)
	}

	// We log only the first time the identity is unblocked.
	if ok {
		return s.logActivity(ctx, ActivityIdentityUnblocked, []IdentityRef{{ID: *identity.ID}}, []OrganizationRef{{ID: organizationID}}, nil, nil, nil, nil, nil)
	}

	return nil
}

func (s *Service) blockIdentity(
	ctx context.Context, identity *Identity, orgIdentityID, organizationID identifier.Identifier,
	organizationNote, identityNote string,
) errors.E {
	s.identitiesBlockedMu.Lock()
	defer s.identitiesBlockedMu.Unlock()

	if s.identitiesBlocked[organizationID] == nil {
		s.identitiesBlocked[organizationID] = map[identifier.Identifier]BlockedIdentity{}
	}

	_, ok := s.identitiesBlocked[organizationID][orgIdentityID]

	// It is OK to overwrite the note because we do not allow multiple notes for the same identity.
	s.identitiesBlocked[organizationID][orgIdentityID] = BlockedIdentity{
		OrganizationNote: organizationNote,
		IdentityNote:     identityNote,
	}

	// We log only the first time the identity is blocked.
	if !ok {
		return s.logActivity(ctx, ActivityIdentityBlocked, []IdentityRef{{ID: *identity.ID}}, []OrganizationRef{{ID: organizationID}}, nil, nil, nil, nil, nil)
	}

	return nil
}

func (s *Service) blockAccounts(
	ctx context.Context, identity *Identity, orgIdentityID, organizationID identifier.Identifier,
	organizationNote, identityNote string,
) errors.E {
	accountIDs := s.getAccountsForIdentityWithLock(IdentityRef{ID: *identity.ID})

	s.identitiesBlockedMu.Lock()
	defer s.identitiesBlockedMu.Unlock()

	if s.accountsBlocked[organizationID] == nil {
		s.accountsBlocked[organizationID] = map[identifier.Identifier]map[identifier.Identifier]BlockedIdentity{}
	}

	blockedAccountIDs := []AccountRef{}

	for accountID := range accountIDs {
		if s.accountsBlocked[organizationID][accountID] == nil {
			s.accountsBlocked[organizationID][accountID] = map[identifier.Identifier]BlockedIdentity{}
		}

		_, ok := s.accountsBlocked[organizationID][accountID][orgIdentityID]

		// It is OK to overwrite the note because we do not allow multiple notes for the same account & identity pair.
		s.accountsBlocked[organizationID][accountID][orgIdentityID] = BlockedIdentity{
			OrganizationNote: organizationNote,
			IdentityNote:     identityNote,
		}

		// We log only the first time the identity is blocked.
		if !ok {
			blockedAccountIDs = append(blockedAccountIDs, AccountRef{ID: accountID})
		}
	}

	if len(blockedAccountIDs) > 0 {
		// All accounts have access to the identity, so it is OK to have the identity itself logged and exposed.
		// We do never expose accounts, so we can log for all of them all together once.
		return s.logActivity(ctx, ActivityAccountBlocked, []IdentityRef{{ID: *identity.ID}}, []OrganizationRef{{ID: organizationID}}, nil, nil, blockedAccountIDs, nil, nil)
	}

	return nil
}

func (s *Service) OrganizationBlockUser(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

type OrganizationBlockRequest struct {
	Type             BlockedIdentityType `json:"type"`
	OrganizationNote string              `json:"organizationNote"`
	IdentityNote     string              `json:"identityNote"`
}

func (s *Service) OrganizationBlockUserPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	organization, errE := s.getOrganizationFromID(ctx, params["id"])
	if errors.Is(errE, ErrOrganizationNotFound) {
		s.NotFoundWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	identityID, errE := identifier.MaybeString(params["identityId"])
	if errE != nil {
		s.NotFoundWithError(w, req, errors.WrapWith(errE, ErrIdentityNotFound))
		return
	}
	identity, idOrg, errE := s.getIdentityFromOrganization(ctx, *organization.ID, identityID)
	if errors.Is(errE, ErrIdentityNotFound) {
		// It is OK that we leak here if identity is in organization or not because
		// we do the same in OrganizationIdentityGet.
		s.NotFoundWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	} else if !idOrg.Active {
		s.NotFound(w, req)
		return
	}

	if !organization.HasAdminAccess(IdentityRef{ID: mustGetIdentityID(ctx)}) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	}

	var blockRequest OrganizationBlockRequest
	errE = x.DecodeJSONWithoutUnknownFields(req.Body, &blockRequest)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	switch blockRequest.Type {
	case BlockedIdentityNotBlocked:
		errE := s.unblockIdentity(ctx, identity, *idOrg.ID, *organization.ID)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
	case BlockedIdentityAndAccounts:
		errE := s.blockAccounts(ctx, identity, *idOrg.ID, *organization.ID, blockRequest.OrganizationNote, blockRequest.IdentityNote)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		fallthrough
	case BlockedIdentityOnly:
		errE := s.blockIdentity(ctx, identity, *idOrg.ID, *organization.ID, blockRequest.OrganizationNote, blockRequest.IdentityNote)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
	default:
		errE := errors.New("unsupported type")
		errors.Details(errE)["type"] = blockRequest.Type
		s.BadRequestWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, []byte(`{"success":true}`), nil)
}

type OrganizationBlockedStatusNotes struct {
	Identity         IdentityRef `json:"identity"`
	OrganizationNote string      `json:"organizationNote,omitempty"`
	IdentityNote     string      `json:"identityNote,omitempty"`
}

type OrganizationBlockedStatus struct {
	Blocked BlockedIdentityType              `json:"blocked"`
	Notes   []OrganizationBlockedStatusNotes `json:"notes,omitempty"`
}

func (s *Service) OrganizationBlockedStatusGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	// We allow getting identities with the access token or session cookie.
	ctx := s.requireAuthenticatedForIdentity(w, req)
	if ctx == nil {
		return
	}

	organization, errE := s.getOrganizationFromID(ctx, params["id"])
	if errors.Is(errE, ErrOrganizationNotFound) {
		s.NotFoundWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	identityID, errE := identifier.MaybeString(params["identityId"])
	if errE != nil {
		s.NotFoundWithError(w, req, errors.WrapWith(errE, ErrIdentityNotFound))
		return
	}

	identity, idOrg, errE := s.getIdentityFromOrganization(ctx, *organization.ID, identityID)
	if errors.Is(errE, ErrIdentityNotFound) {
		// It is OK that we leak here if identity is in organization or not because
		// we do the same in OrganizationIdentityGet.
		s.NotFoundWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	currentAccountID := mustGetAccountID(ctx)
	ids, isCreator, errE := s.getIdentitiesForAccount(ctx, currentAccountID, IdentityRef{ID: *identity.ID})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// We use this to check if this is an organization admin (of active identity in the organization)?
	isOrgAdmin := organization.HasAdminAccess(IdentityRef{ID: mustGetIdentityID(ctx)})

	// We use these to check if this is somebody with access to the identity (active or not in the organization)?
	hasUserAccess := identity.HasUserAccess(ids)
	hasAdminAccess := identity.HasAdminAccess(ids, isCreator)

	s.identitiesBlockedMu.RLock()
	defer s.identitiesBlockedMu.RUnlock()

	// Check if the identity is blocked in the organization.
	if (isOrgAdmin && idOrg.Active) || hasUserAccess || hasAdminAccess {
		if s.identitiesBlocked[*organization.ID] != nil {
			blockedIdentity, ok := s.identitiesBlocked[*organization.ID][*idOrg.ID]
			if ok {
				// Only organization admin can see organization note.
				if !isOrgAdmin {
					blockedIdentity.OrganizationNote = ""
				}

				s.WriteJSON(w, req, OrganizationBlockedStatus{
					Blocked: BlockedIdentityOnly,
					Notes: []OrganizationBlockedStatusNotes{{
						Identity:         IdentityRef{ID: *idOrg.ID},
						OrganizationNote: blockedIdentity.OrganizationNote,
						IdentityNote:     blockedIdentity.IdentityNote,
					}},
				}, nil)
				return
			}
		}
	}

	// Check if the account (of caller) is blocked in the organization,
	// then also this identity is blocked for them.
	if hasUserAccess || hasAdminAccess {
		if s.accountsBlocked[*organization.ID] != nil {
			blockedIdentities, ok := s.accountsBlocked[*organization.ID][currentAccountID]
			if ok {
				notes := []OrganizationBlockedStatusNotes{}
				for orgIdentityID, blockedIdentity := range blockedIdentities {
					// Only organization admin can see organization note.
					if !isOrgAdmin {
						blockedIdentity.OrganizationNote = ""
					}
					notes = append(notes, OrganizationBlockedStatusNotes{
						Identity:         IdentityRef{ID: orgIdentityID},
						OrganizationNote: blockedIdentity.OrganizationNote,
						IdentityNote:     blockedIdentity.IdentityNote,
					})
				}

				slices.SortFunc(notes, func(a, b OrganizationBlockedStatusNotes) int {
					return identityRefCmp(a.Identity, b.Identity)
				})

				s.WriteJSON(w, req, OrganizationBlockedStatus{
					Blocked: BlockedIdentityAndAccounts,
					Notes:   notes,
				}, nil)
				return
			}
		}
	}

	// If we got to here and caller has access, then identity is not blocked.
	if (isOrgAdmin && idOrg.Active) || hasUserAccess || hasAdminAccess {
		s.WriteJSON(w, req, OrganizationBlockedStatus{
			Blocked: BlockedIdentityNotBlocked,
			Notes:   nil,
		}, nil)
		return
	}

	waf.Error(w, req, http.StatusUnauthorized)
}
