package charon

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"slices"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

var (
	ErrIdentityNotFound         = errors.Base("identity not found")
	ErrIdentityAlreadyExists    = errors.Base("identity already exists")
	ErrIdentityUnauthorized     = errors.Base("identity change unauthorized")
	ErrIdentityValidationFailed = errors.Base("identity validation failed")
)

var (
	identities   = make(map[identifier.Identifier][]byte) //nolint:gochecknoglobals
	identitiesMu = sync.RWMutex{}                         //nolint:gochecknoglobals
)

type IdentityOrganization struct {
	// ID is also ID of this identity in the organization.
	ID *identifier.Identifier `json:"id"`

	Active bool `json:"active"`

	Organization OrganizationRef `json:"organization"`
}

func (i *IdentityOrganization) Validate(_ context.Context, existing *IdentityOrganization) errors.E {
	if existing == nil {
		if i.ID != nil {
			errE := errors.New("ID provided for new document")
			errors.Details(errE)["id"] = *i.ID
			return errE
		}
		id := identifier.New()
		i.ID = &id
	} else if i.ID == nil {
		// This should not really happen because we fetch existing based on i.ID.
		return errors.New("ID missing for existing document")
	} else if existing.ID == nil {
		// This should not really happen because we always store documents with ID.
		return errors.New("ID missing for existing document")
	} else if *i.ID != *existing.ID {
		// This should not really happen because we fetch existing based on i.ID.
		errE := errors.New("payload ID does not match existing ID")
		errors.Details(errE)["payload"] = *i.ID
		errors.Details(errE)["existing"] = *existing.ID
		return errE
	}

	// TODO: Validate that i.Organization really exists?

	return nil
}

type Identity struct {
	ID *identifier.Identifier `json:"id"`

	Username   string `json:"username"`
	Email      string `json:"email"`
	GivenName  string `json:"givenName"`
	FullName   string `json:"fullName"`
	PictureURL string `json:"pictureUrl"`

	Description string `json:"description"`

	Users  []AccountRef `json:"users,omitempty"`
	Admins []AccountRef `json:"admins"`

	Organizations []IdentityOrganization `json:"organizations"`
}

func (i *Identity) GetIdentityOrganization(id *identifier.Identifier) *IdentityOrganization {
	if i == nil {
		return nil
	}
	if id == nil {
		return nil
	}

	for _, idOrg := range i.Organizations {
		if idOrg.ID != nil && *idOrg.ID == *id {
			return &idOrg
		}
	}

	return nil
}

func (i *Identity) GetOrganization(id identifier.Identifier) *IdentityOrganization {
	for _, idOrg := range i.Organizations {
		if idOrg.Organization.ID == id {
			return &idOrg
		}
	}

	return nil
}

type IdentityRef struct {
	ID identifier.Identifier `json:"id"`
}

func (i *Identity) Validate(ctx context.Context, existing *Identity) errors.E {
	if existing == nil {
		if i.ID != nil {
			errE := errors.New("ID provided for new document")
			errors.Details(errE)["id"] = *i.ID
			return errE
		}
		id := identifier.New()
		i.ID = &id
	} else if i.ID == nil {
		// This should not really happen because we fetch existing based on i.ID.
		return errors.New("ID missing for existing document")
	} else if existing.ID == nil {
		// This should not really happen because we always store documents with ID.
		return errors.New("ID missing for existing document")
	} else if *i.ID != *existing.ID {
		// This should not really happen because we fetch existing based on i.ID.
		errE := errors.New("payload ID does not match existing ID")
		errors.Details(errE)["payload"] = *i.ID
		errors.Details(errE)["existing"] = *existing.ID
		return errE
	}

	if i.Username != "" {
		username, errE := normalizeUsernameCasePreserved(i.Username)
		if errE != nil {
			errE = errors.WithMessage(errE, "username")
			errors.Details(errE)["username"] = i.Username
			return errE
		}

		if len(username) < emailOrUsernameMinLength {
			errE := errors.New("username too short")
			errors.Details(errE)["username"] = i.Username
			return errE
		}

		i.Username = username
	}

	// TODO: E-mails should be possible to be only those which have been validated.

	if i.Email != "" {
		email, errE := normalizeUsernameCasePreserved(i.Email)
		if errE != nil {
			errE = errors.WithMessage(errE, "e-mail")
			errors.Details(errE)["email"] = i.Email
			return errE
		}

		if len(email) < emailOrUsernameMinLength {
			errE := errors.New("e-mail too short")
			errors.Details(errE)["email"] = i.Email
			return errE
		}

		i.Email = email
	}

	// TODO: Normalize GivenName and FullName.

	if i.PictureURL != "" {
		errE := validateURI(ctx, i.PictureURL)
		if errE != nil {
			return errors.WithMessage(errE, "picture URL")
		}
	}

	// At least something is required.
	if i.Username == "" && i.Email == "" && i.GivenName == "" && i.FullName == "" && i.PictureURL == "" {
		return errors.New("empty identity")
	}

	accountID := mustGetAccountID(ctx)
	accountRef := AccountRef{ID: accountID}
	if !slices.Contains(i.Admins, accountRef) {
		i.Admins = append(i.Admins, accountRef)
	}

	// We sort and remove duplicates.
	slices.SortFunc(i.Admins, func(a AccountRef, b AccountRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	i.Admins = slices.Compact(i.Admins)
	slices.SortFunc(i.Users, func(a AccountRef, b AccountRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	i.Users = slices.Compact(i.Users)

	// Admins should not be users as well.
	adminsSet := mapset.NewThreadUnsafeSet[AccountRef]()
	adminsSet.Append(i.Admins...)
	i.Users = slices.DeleteFunc(i.Users, func(ar AccountRef) bool {
		return adminsSet.Contains(ar)
	})

	if i.Organizations == nil {
		i.Organizations = []IdentityOrganization{}
	}

	idOrgsSet := mapset.NewThreadUnsafeSet[identifier.Identifier]()
	organizationsSet := mapset.NewThreadUnsafeSet[identifier.Identifier]()
	for ii, idOrg := range i.Organizations {
		errE := idOrg.Validate(ctx, existing.GetIdentityOrganization(idOrg.ID))
		if errE != nil {
			errE = errors.WithMessage(errE, "organization")
			errors.Details(errE)["i"] = ii
			if idOrg.ID != nil {
				errors.Details(errE)["id"] = *idOrg.ID
			}
			return errE
		}

		if idOrgsSet.Contains(*idOrg.ID) {
			errE := errors.New("duplicate organization ID")
			errors.Details(errE)["i"] = ii
			errors.Details(errE)["id"] = *idOrg.ID
			return errE
		}
		idOrgsSet.Add(*idOrg.ID)

		if organizationsSet.Contains(idOrg.Organization.ID) {
			errE := errors.New("duplicate organization")
			errors.Details(errE)["i"] = ii
			errors.Details(errE)["id"] = idOrg.Organization.ID
			return errE
		}
		organizationsSet.Add(idOrg.Organization.ID)

		// IdentityOrganization might have been changed by Validate, so we assign it back.
		i.Organizations[ii] = idOrg
	}

	return nil
}

func GetIdentity(ctx context.Context, id identifier.Identifier) (*Identity, errors.E) {
	identitiesMu.RLock()
	defer identitiesMu.RUnlock()

	data, ok := identities[id]
	if !ok {
		return nil, errors.WithDetails(ErrIdentityNotFound, "id", id)
	}
	var identity Identity
	errE := x.UnmarshalWithoutUnknownFields(data, &identity)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, errE
	}
	accountID := mustGetAccountID(ctx)
	if !slices.Contains(identity.Users, AccountRef{accountID}) && !slices.Contains(identity.Admins, AccountRef{accountID}) {
		return nil, errors.WithDetails(ErrIdentityUnauthorized, "id", id)
	}
	return &identity, nil
}

func CreateIdentity(ctx context.Context, identity *Identity) errors.E {
	errE := identity.Validate(ctx, nil)
	if errE != nil {
		return errors.WrapWith(errE, ErrIdentityValidationFailed)
	}

	data, errE := x.MarshalWithoutEscapeHTML(identity)
	if errE != nil {
		return errE
	}

	identitiesMu.Lock()
	defer identitiesMu.Unlock()

	identities[*identity.ID] = data
	return nil
}

func UpdateIdentity(ctx context.Context, identity *Identity) errors.E { //nolint:dupl
	identitiesMu.Lock()
	defer identitiesMu.Unlock()

	if identity.ID == nil {
		return errors.WithMessage(ErrIdentityValidationFailed, "ID is missing")
	}

	existingData, ok := identities[*identity.ID]
	if !ok {
		return errors.WithDetails(ErrIdentityNotFound, "id", *identity.ID)
	}

	var existingIdentity Identity
	errE := x.UnmarshalWithoutUnknownFields(existingData, &existingIdentity)
	if errE != nil {
		errors.Details(errE)["id"] = *identity.ID
		return errE
	}

	accountID := mustGetAccountID(ctx)
	if !slices.Contains(existingIdentity.Admins, AccountRef{ID: accountID}) {
		return errors.WithDetails(ErrIdentityUnauthorized, "id", *identity.ID)
	}

	errE = identity.Validate(ctx, &existingIdentity)
	if errE != nil {
		return errors.WrapWith(errE, ErrIdentityValidationFailed)
	}

	data, errE := x.MarshalWithoutEscapeHTML(identity)
	if errE != nil {
		errors.Details(errE)["id"] = *identity.ID
		return errE
	}

	identities[*identity.ID] = data
	return nil
}

// TODO: This is full of races, use transactions once we use proper database to store identities.
func selectAndActivateIdentity(ctx context.Context, identityID, organizationID identifier.Identifier) (*Identity, errors.E) {
	identity, errE := GetIdentity(ctx, identityID)
	if errE != nil {
		return nil, errE
	}

	for i, idOrg := range identity.Organizations {
		if idOrg.Organization.ID == organizationID {
			if idOrg.Active {
				// Organization already present and active, nothing to do.
				return identity, nil
			}

			// Organization already present but not active, we activate it.
			idOrg.Active = true
			// IdentityOrganization has been changed, so we assign it back.
			identity.Organizations[i] = idOrg

			return identity, UpdateIdentity(ctx, identity)
		}
	}

	// Organization not present, we add it (active).
	identity.Organizations = append(identity.Organizations, IdentityOrganization{
		ID:     nil,
		Active: true,
		Organization: OrganizationRef{
			ID: organizationID,
		},
	})

	return identity, UpdateIdentity(ctx, identity)
}

func (s *Service) IdentityGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) IdentityCreate(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false) == nil {
		return
	}

	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) IdentityList(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func getIdentityFromID(ctx context.Context, value string) (*Identity, errors.E) {
	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrIdentityNotFound)
	}

	return GetIdentity(ctx, id)
}

func (s *Service) returnIdentityRef(_ context.Context, w http.ResponseWriter, req *http.Request, identity *Identity) {
	s.WriteJSON(w, req, IdentityRef{ID: *identity.ID}, nil)
}

func (s *Service) IdentityGetGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true)
	if ctx == nil {
		return
	}

	identity, errE := getIdentityFromID(ctx, params["id"])
	if errors.Is(errE, ErrIdentityUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errors.Is(errE, ErrIdentityNotFound) {
		s.NotFound(w, req)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	accountID := mustGetAccountID(ctx)
	if slices.Contains(identity.Admins, AccountRef{ID: accountID}) {
		s.WriteJSON(w, req, identity, map[string]interface{}{
			"can_get":    true,
			"can_update": true,
		})
		return
	}

	s.WriteJSON(w, req, identity, map[string]interface{}{
		"can_get": true,
	})
}

func (s *Service) IdentityListGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true)
	if ctx == nil {
		return
	}

	accountID := mustGetAccountID(ctx)

	result := []IdentityRef{}

	identitiesMu.RLock()
	defer identitiesMu.RUnlock()

	var organization *identifier.Identifier
	if org := req.Form.Get("org"); org != "" {
		o, errE := identifier.FromString(org)
		if errE != nil {
			s.BadRequestWithError(w, req, errors.WithMessage(errE, `invalid "org" parameter`))
			return
		}
		organization = &o
	}

	var notOrganization *identifier.Identifier
	if org := req.Form.Get("notorg"); org != "" {
		o, errE := identifier.FromString(org)
		if errE != nil {
			s.BadRequestWithError(w, req, errors.WithMessage(errE, `invalid "notorg" parameter`))
			return
		}
		notOrganization = &o
	}

	for id, data := range identities {
		var identity Identity
		errE := x.UnmarshalWithoutUnknownFields(data, &identity)
		if errE != nil {
			errors.Details(errE)["id"] = id
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		if slices.Contains(identity.Users, AccountRef{ID: accountID}) || slices.Contains(identity.Admins, AccountRef{ID: accountID}) {
			// TODO: Do not filter in list endpoint but filter in search endpoint.
			if organization != nil && identity.GetOrganization(*organization) != nil {
				result = append(result, IdentityRef{ID: id})
			} else if notOrganization != nil && identity.GetOrganization(*notOrganization) == nil {
				result = append(result, IdentityRef{ID: id})
			} else if organization == nil && notOrganization == nil {
				result = append(result, IdentityRef{ID: id})
			}
		}
	}

	slices.SortFunc(result, func(a IdentityRef, b IdentityRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) IdentityUpdatePost(w http.ResponseWriter, req *http.Request, params waf.Params) { //nolint:dupl
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true)
	if ctx == nil {
		return
	}

	var identity Identity
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &identity)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	// If identity.ID == nil, UpdateIdentity returns an error.
	if identity.ID != nil && params["id"] != identity.ID.String() {
		errE = errors.New("params ID does not match payload ID")
		errors.Details(errE)["params"] = params["id"]
		errors.Details(errE)["payload"] = *identity.ID
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = UpdateIdentity(ctx, &identity)
	if errors.Is(errE, ErrIdentityUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errors.Is(errE, ErrIdentityNotFound) {
		s.NotFound(w, req)
		return
	} else if errors.Is(errE, ErrIdentityValidationFailed) {
		s.BadRequestWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnIdentityRef(ctx, w, req, &identity)
}

func (s *Service) IdentityCreatePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true)
	if ctx == nil {
		return
	}

	var identity Identity
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &identity)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if identity.ID != nil {
		s.BadRequestWithError(w, req, errors.New("payload contains ID"))
		return
	}

	errE = CreateIdentity(ctx, &identity)
	if errors.Is(errE, ErrIdentityValidationFailed) {
		s.BadRequestWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnIdentityRef(ctx, w, req, &identity)
}
