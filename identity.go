package charon

import (
	"bytes"
	"cmp"
	"context"
	"io"
	"net/http"
	"slices"

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

	errEmptyIdentity = errors.Base("empty identity")
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

type IdentityAccount struct {
	IdentityID identifier.Identifier `json:"identityId"`
	AccountID  identifier.Identifier `json:"accountId"`
}

func cmpIdentityAccount(a IdentityAccount, b IdentityAccount) int {
	return cmp.Or(
		bytes.Compare(a.IdentityID[:], b.IdentityID[:]),
		bytes.Compare(a.AccountID[:], b.AccountID[:]),
	)
}

type Identity struct {
	ID *identifier.Identifier `json:"id"`

	Username   string `json:"username"`
	Email      string `json:"email"`
	GivenName  string `json:"givenName"`
	FullName   string `json:"fullName"`
	PictureURL string `json:"pictureUrl"`

	Description string `json:"description"`

	// TODO: When sending Identity out, we should not expose account IDs.

	// For identities we have an exception where we use accounts for access control,
	// but we expose them through related identities to users.
	Users  []IdentityAccount `json:"users,omitempty"`
	Admins []IdentityAccount `json:"admins"`

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

func (i *Identity) HasUserAccess(accountID identifier.Identifier) bool {
	for _, identityAccount := range i.Users {
		if identityAccount.AccountID == accountID {
			return true
		}
	}
	return false
}

func (i *Identity) HasAdminAccess(accountID identifier.Identifier) bool {
	for _, identityAccount := range i.Admins {
		if identityAccount.AccountID == accountID {
			return true
		}
	}
	return false
}

type IdentityRef struct {
	ID identifier.Identifier `json:"id"`
}

// Validate requires ctx with identityIDContextKey set.
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
		return errors.WithStack(errEmptyIdentity)
	}

	// Current user must be among admins if it is changing the identity.
	// We check this elsewhere, here we make sure the user is stored as an admin.
	identityID, ok := getIdentityID(ctx)
	accountID := mustGetAccountID(ctx)
	if !ok && existing != nil {
		// We are updating an existing identity using session cookie. In this case we just check
		// (again, it has been checked in updateIdentity already) that the account is among admins,
		// but we cannot add the current user to admins ourselves.
		if !existing.HasAdminAccess(accountID) {
			// This should not really happen because we check this in updateIdentity.
			return errors.New("current account is not already among admins")
		}
	} else {
		if !ok {
			// When creating a new identity for the current account while using a session cookie,
			// we do not set identityIDContextKey. We use the identity itself instead.
			identityID = *i.ID
		}
		identityAccount := IdentityAccount{identityID, accountID}
		if !slices.Contains(i.Admins, identityAccount) {
			i.Admins = append(i.Admins, identityAccount)
		}
	}

	// We sort and remove duplicates.
	slices.SortFunc(i.Admins, cmpIdentityAccount)
	i.Admins = slices.Compact(i.Admins)
	slices.SortFunc(i.Users, cmpIdentityAccount)
	i.Users = slices.Compact(i.Users)

	// Admins should not be users as well.
	adminsSet := mapset.NewThreadUnsafeSet[IdentityAccount]()
	adminsSet.Append(i.Admins...)
	i.Users = slices.DeleteFunc(i.Users, func(ia IdentityAccount) bool {
		return adminsSet.Contains(ia)
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

func (s *Service) getIdentity(ctx context.Context, id identifier.Identifier) (*Identity, errors.E) {
	s.identitiesMu.RLock()
	defer s.identitiesMu.RUnlock()

	data, ok := s.identities[id]
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
	if identity.HasUserAccess(accountID) || identity.HasAdminAccess(accountID) {
		return &identity, nil
	}
	return nil, errors.WithDetails(ErrIdentityUnauthorized, "id", id)
}

// createIdentity should have ctx with both identityIDContextKey and accountIDContextKey set,
// unless it is used to create a new identity for a new user without any other identity
// (but which has an account). Only in such case, the identityIDContextKey does not have to
// be set and the identity itself will be used instead.
func (s *Service) createIdentity(ctx context.Context, identity *Identity) errors.E {
	errE := identity.Validate(ctx, nil)
	if errE != nil {
		return errors.WrapWith(errE, ErrIdentityValidationFailed)
	}

	data, errE := x.MarshalWithoutEscapeHTML(identity)
	if errE != nil {
		return errE
	}

	s.identitiesMu.Lock()
	defer s.identitiesMu.Unlock()

	s.identities[*identity.ID] = data
	return nil
}

func (s *Service) updateIdentity(ctx context.Context, identity *Identity) errors.E {
	s.identitiesMu.Lock()
	defer s.identitiesMu.Unlock()

	if identity.ID == nil {
		return errors.WithMessage(ErrIdentityValidationFailed, "ID is missing")
	}

	existingData, ok := s.identities[*identity.ID]
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
	if !existingIdentity.HasAdminAccess(accountID) {
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

	s.identities[*identity.ID] = data
	return nil
}

// TODO: This is full of races, use transactions once we use proper database to store identities.
func (s *Service) selectAndActivateIdentity(ctx context.Context, identityID, organizationID identifier.Identifier) (*Identity, errors.E) {
	identity, errE := s.getIdentity(ctx, identityID)
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

			return identity, s.updateIdentity(ctx, identity)
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

	return identity, s.updateIdentity(ctx, identity)
}

func (s *Service) IdentityGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	// We always serve the page and leave to the API call to check permissions.

	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) IdentityCreate(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	// We always serve the page and leave to the API call to check permissions.

	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) IdentityList(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	// We always serve the page and leave to the API call to check permissions.

	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) getIdentityFromID(ctx context.Context, value string) (*Identity, errors.E) {
	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrIdentityNotFound)
	}

	return s.getIdentity(ctx, id)
}

func (s *Service) returnIdentityRef(_ context.Context, w http.ResponseWriter, req *http.Request, identity *Identity) {
	s.WriteJSON(w, req, IdentityRef{ID: *identity.ID}, nil)
}

func (s *Service) IdentityGetGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	// We allow getting identities with the access token or session cookie.
	ctx := s.requireAuthenticatedForIdentity(w, req)
	if ctx == nil {
		return
	}

	identity, errE := s.getIdentityFromID(ctx, params["id"])
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
	if identity.HasAdminAccess(accountID) {
		// getIdentityFromID checked that user has user or admin access to the identity
		// so here we know that they have both.
		s.WriteJSON(w, req, identity, map[string]interface{}{
			"can_get":    true,
			"can_update": true,
		})
		return
	}

	// getIdentityFromID checked that user has user or admin access to the identity
	// so here we know that they have only user access.
	s.WriteJSON(w, req, identity, map[string]interface{}{
		"can_get": true,
	})
}

func (s *Service) IdentityListGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	// We allow getting identities with the access token or session cookie.
	ctx := s.requireAuthenticatedForIdentity(w, req)
	if ctx == nil {
		return
	}

	accountID := mustGetAccountID(ctx)

	result := []IdentityRef{}

	s.identitiesMu.RLock()
	defer s.identitiesMu.RUnlock()

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

	for id, data := range s.identities {
		var identity Identity
		errE := x.UnmarshalWithoutUnknownFields(data, &identity)
		if errE != nil {
			errors.Details(errE)["id"] = id
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		if identity.HasUserAccess(accountID) || identity.HasAdminAccess(accountID) {
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

func (s *Service) IdentityUpdatePost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	// We allow creating identities with the access token or session cookie.
	ctx := s.requireAuthenticatedForIdentity(w, req)
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

	errE = s.updateIdentity(ctx, &identity)
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

	// We allow creating identities with the access token or session cookie.
	ctx := s.requireAuthenticatedForIdentity(w, req)
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

	errE = s.createIdentity(ctx, &identity)
	if errors.Is(errE, ErrIdentityValidationFailed) {
		s.BadRequestWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnIdentityRef(ctx, w, req, &identity)
}
