package charon

import (
	"bytes"
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

type Identity struct {
	ID *identifier.Identifier `json:"id"`

	Username   string `json:"username"`
	Email      string `json:"email"`
	GivenName  string `json:"givenName"`
	FullName   string `json:"fullName"`
	PictureURL string `json:"pictureUrl"`

	Description string `json:"description"`

	Users  []IdentityRef `json:"users,omitempty"`
	Admins []IdentityRef `json:"admins"`

	Organizations []IdentityOrganization `json:"organizations"`
}

// GetIdentityOrganization returns IdentityOrganization based on IdentityOrganization's ID.
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

// GetOrganization returns IdentityOrganization based on IdentityOrganization's Organization's ID.
func (i *Identity) GetOrganization(id *identifier.Identifier) *IdentityOrganization {
	if i == nil {
		return nil
	}
	if id == nil {
		return nil
	}

	for _, idOrg := range i.Organizations {
		if idOrg.Organization.ID == *id {
			return &idOrg
		}
	}

	return nil
}

// HasUserAccess returns true if at least one of the identities is among users.
func (i *Identity) HasUserAccess(identities ...IdentityRef) bool {
	for _, identity := range identities {
		if slices.Contains(i.Users, identity) {
			return true
		}
	}
	return false
}

// HasAdminAccess returns true if at least one of the identities is among admins.
func (i *Identity) HasAdminAccess(identities ...IdentityRef) bool {
	for _, identity := range identities {
		if slices.Contains(i.Admins, identity) {
			return true
		}
	}
	return false
}

type IdentityRef struct {
	ID identifier.Identifier `json:"id"`
}

// Validate uses ctx with identityIDContextKey if set.
// When not set, changes to admins are not allowed.
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
	if !ok && existing != nil {
		// We are updating an existing identity using session cookie. In this case it has been checked
		// in updateIdentity already that the current user is among admins, but we cannot add the
		// current user to admins ourselves. Because of this, we do not allow changes to admins
		// at all when using a session cookie.
		if !slices.Equal(existing.Admins, i.Admins) {
			return errors.New("admins changed when using session cookie")
		}
	} else {
		if !ok {
			// When creating a new identity for the current account while using a session cookie,
			// we do not set identityIDContextKey. We use the identity itself instead.
			identityID = *i.ID
		}
		identity := IdentityRef{ID: identityID}
		if !i.HasAdminAccess(identity) {
			i.Admins = append(i.Admins, identity)
		}
	}

	// We sort and remove duplicates.
	slices.SortFunc(i.Admins, func(a IdentityRef, b IdentityRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	i.Admins = slices.Compact(i.Admins)
	slices.SortFunc(i.Users, func(a IdentityRef, b IdentityRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	i.Users = slices.Compact(i.Users)

	// Admins should not be users as well.
	adminsSet := mapset.NewThreadUnsafeSet[IdentityRef]()
	adminsSet.Append(i.Admins...)
	i.Users = slices.DeleteFunc(i.Users, func(ia IdentityRef) bool {
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

// getIdentitiesForAccount returns all identities the account has access to.
//
// s.accountsToIdentitiesMu should be locked for reading while calling this function.
func (s *Service) getIdentitiesForAccount(_ context.Context, accountID identifier.Identifier) ([]IdentityRef, errors.E) { //nolint:unparam
	return s.accountsToIdentities[accountID], nil
}

func (s *Service) getIdentity(ctx context.Context, id identifier.Identifier) (*Identity, bool, errors.E) {
	accountID := mustGetAccountID(ctx)

	s.identitiesMu.RLock()
	defer s.identitiesMu.RUnlock()

	// We lock s.accountsToIdentitiesMu inside s.identitiesMu lock to have
	// consistent view of identities and accounts.
	s.accountsToIdentitiesMu.RLock()
	defer s.accountsToIdentitiesMu.RUnlock()

	data, ok := s.identities[id]
	if !ok {
		return nil, false, errors.WithDetails(ErrIdentityNotFound, "id", id)
	}
	var identity Identity
	errE := x.UnmarshalWithoutUnknownFields(data, &identity)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, false, errE
	}

	ids, errE := s.getIdentitiesForAccount(ctx, accountID)
	if errE != nil {
		return nil, false, errE
	}
	// We could also just check if slices.Contains(ids, IdentityRef{ID: *identity.ID}),
	// but this gives us information about the type of the access. Furthermore, it makes
	// things safer in the case that collecting ids is buggy and returns too many ids.
	if identity.HasUserAccess(ids...) {
		return &identity, false, nil
	}
	if identity.HasAdminAccess(ids...) {
		return &identity, true, nil
	}
	return nil, false, errors.WithDetails(ErrIdentityUnauthorized, "id", id)
}

// createIdentity should have ctx with both identityIDContextKey and accountIDContextKey set,
// unless it is used to create a new identity for a new user without any other identity
// (but which has an account). Only in such case, the identityIDContextKey does not have to
// be set and the identity itself will be used instead.
func (s *Service) createIdentity(ctx context.Context, identity *Identity) errors.E {
	accountID := mustGetAccountID(ctx)

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

	// We lock s.accountsToIdentitiesMu inside s.identitiesMu lock to have
	// consistent view of identities and accounts.
	s.accountsToIdentitiesMu.Lock()
	defer s.accountsToIdentitiesMu.Unlock()

	s.identities[*identity.ID] = data

	i := IdentityRef{ID: *identity.ID}

	identities := mapset.NewThreadUnsafeSet(identity.Users...)
	identities.Append(identity.Admins...)

	s.updateAccountForIdentity(accountID, i, mapset.NewThreadUnsafeSet[IdentityRef](), identities)

	return nil
}

// setAccountForIdentity adds the identity to the list of identities the account has
// access to, if it is not already on the list.
//
// s.accountsToIdentitiesMu should be locked while calling this function.
func (s *Service) setAccountForIdentity(accountID identifier.Identifier, identity IdentityRef) {
	identities := s.accountsToIdentities[accountID]
	if !slices.Contains(identities, identity) {
		s.accountsToIdentities[accountID] = append(identities, identity)
	}
}

// unsetAccountForIdentity removes the identity from the list of identities the account has
// access to, if it is in the list.
//
// s.accountsToIdentitiesMu should be locked while calling this function.
func (s *Service) unsetAccountForIdentity(accountID identifier.Identifier, identity IdentityRef) {
	identities := s.accountsToIdentities[accountID]
	if i := slices.Index(identities, identity); i >= 0 {
		s.accountsToIdentities[accountID] = slices.Delete(identities, i, i+1)
	}
}

// getAccountsForIdentities returns all accounts that have access to any of the
// given identities.
//
// s.accountsToIdentitiesMu should be locked while calling this function.
func (s *Service) getAccountsForIdentities(identities mapset.Set[IdentityRef]) mapset.Set[identifier.Identifier] {
	accountIDs := mapset.NewThreadUnsafeSet[identifier.Identifier]()
	for accountID, ids := range s.accountsToIdentities {
		if identities.ContainsAny(ids...) {
			accountIDs.Add(accountID)
		}
	}
	return accountIDs
}

func (s *Service) updateIdentity(ctx context.Context, identity *Identity) errors.E {
	accountID := mustGetAccountID(ctx)

	s.identitiesMu.Lock()
	defer s.identitiesMu.Unlock()

	// We lock s.accountsToIdentitiesMu inside s.identitiesMu lock to have
	// consistent view of identities and accounts.
	s.accountsToIdentitiesMu.Lock()
	defer s.accountsToIdentitiesMu.Unlock()

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

	ids, errE := s.getIdentitiesForAccount(ctx, accountID)
	if errE != nil {
		return errE
	}
	if !existingIdentity.HasAdminAccess(ids...) {
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

	i := IdentityRef{ID: *identity.ID}

	identitiesBefore := mapset.NewThreadUnsafeSet(existingIdentity.Users...)
	identitiesBefore.Append(existingIdentity.Admins...)

	identitiesAfter := mapset.NewThreadUnsafeSet(identity.Users...)
	identitiesAfter.Append(identity.Admins...)

	s.updateAccountForIdentity(accountID, i, identitiesBefore, identitiesAfter)

	return nil
}

// updateAccountForIdentity updates accounts which have access to the identity after the set
// of identities with access to the identity has changed from identitiesBefore to identitiesAfter.
//
// It also recurses to identities which might use this identity in their Users and Admins slices.
//
// s.accountsToIdentitiesMu should be locked while calling this function.
func (s *Service) updateAccountForIdentity(accountID identifier.Identifier, identity IdentityRef, identitiesBefore, identitiesAfter mapset.Set[IdentityRef]) {
	identitySet := mapset.NewThreadUnsafeSet(identity)

	// For all identities which have been removed we remove corresponding accounts with access to those identities
	// from accounts which have access to the identity. This might remove too many accounts if account has access
	// through multiple identities (some of which have not been removed), but we will add those accounts back below.
	for a := range mapset.Elements(s.getAccountsForIdentities(identitiesBefore.Difference(identitiesAfter))) {
		s.unsetAccountForIdentity(a, identity)
	}

	// Current account is always added for the identity just created or updated. This is to make sure the access is
	// restored for the current account if it has just been removed above and to keep the invariant that the current
	// account always has access to the identity just created or updated, which is also checked in Validate
	// and the identity itself is added to admins there as well, if missing, establishing the link between
	// the identity and the account, for identities which have as admins only themselves, answering the question
	// which account do they belong to, bootstrapping correct propagation of which accounts have access based on identities.
	s.setAccountForIdentity(accountID, identity)

	// We add all accounts with access to identities in these slices to accounts which have access to the identity.
	// This includes accounts we erroneously removed above, but also accounts corresponding to identities which
	// have been added to Users and Admins slices.
	for a := range mapset.Elements(s.getAccountsForIdentities(identitiesAfter)) {
		s.setAccountForIdentity(a, identity)
	}

	// TODO: Propagate access to identities which might use this identity in their Users and Admins slices.
}

// TODO: This is full of races, use transactions once we use proper database to store identities.
func (s *Service) selectAndActivateIdentity(ctx context.Context, identityID, organizationID identifier.Identifier) (*Identity, errors.E) {
	identity, _, errE := s.getIdentity(ctx, identityID)
	if errE != nil {
		return nil, errE
	}

	for _, idOrg := range identity.Organizations {
		if idOrg.Organization.ID == organizationID {
			if idOrg.Active {
				// Organization already present and active, nothing to do.
				return identity, nil
			}

			return nil, errors.New("identity not active for organization")
		}
	}

	// Organization not present, we add it (as active).
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

func (s *Service) getIdentityFromID(ctx context.Context, value string) (*Identity, bool, errors.E) {
	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, false, errors.WrapWith(errE, ErrIdentityNotFound)
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

	identity, isAdmin, errE := s.getIdentityFromID(ctx, params["id"])
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

	if isAdmin {
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

	// We lock s.accountsToIdentitiesMu inside s.identitiesMu lock to have
	// consistent view of identities and accounts.
	s.accountsToIdentitiesMu.RLock()
	defer s.accountsToIdentitiesMu.RUnlock()

	ids, errE := s.getIdentitiesForAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

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

	active := false
	if b := req.Form.Get("active"); b != "" {
		switch b {
		case "true":
			active = true
		case "false":
			active = false
		default:
			s.BadRequestWithError(w, req, errors.New(`invalid "active" parameter`))
			return
		}
	}

	for id, data := range s.identities {
		var identity Identity
		errE := x.UnmarshalWithoutUnknownFields(data, &identity)
		if errE != nil {
			errors.Details(errE)["id"] = id
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		// We could also just check if slices.Contains(ids, IdentityRef{ID: *identity.ID}),
		// but this matches the logic in getIdentity to minimize any change of discrepancies.
		// Furthermore, it makes things safer in the case that collecting ids is buggy and
		// returns too many ids.
		// TODO: Do not filter in list endpoint but filter in search endpoint.
		if !identity.HasUserAccess(ids...) && !identity.HasAdminAccess(ids...) {
			continue
		}

		if idOrg := identity.GetOrganization(organization); organization != nil && idOrg != nil {
			// TODO: Do not filter in list endpoint but filter in search endpoint.
			// Or only active identities are requested, or we return all.
			if (active && idOrg.Active) || !active {
				result = append(result, IdentityRef{ID: id})
			}
		} else if idOrg := identity.GetOrganization(notOrganization); notOrganization != nil && idOrg == nil {
			result = append(result, IdentityRef{ID: id})
		} else if organization == nil && notOrganization == nil {
			result = append(result, IdentityRef{ID: id})
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
