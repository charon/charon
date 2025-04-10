package charon

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"reflect"
	"slices"

	mapset "github.com/deckarep/golang-set/v2"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

var (
	ErrIdentityNotFound      = errors.Base("identity not found")
	ErrIdentityAlreadyExists = errors.Base("identity already exists")
	// TODO: Should we remove ErrIdentityUnauthorized and just use ErrIdentityNotFound?
	ErrIdentityUnauthorized     = errors.Base("identity access unauthorized")
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
func (i *Identity) HasUserAccess(identities mapset.Set[IdentityRef]) bool {
	return identities.ContainsAny(i.Users...)
}

// HasAdminAccess returns true if at least one of the identities is among admins.
func (i *Identity) HasAdminAccess(identities mapset.Set[IdentityRef], isCreator bool) bool {
	admins := mapset.NewThreadUnsafeSet(i.Admins...)
	iRef := IdentityRef{ID: *i.ID}
	creatorIsAdmin := admins.Contains(iRef)
	if creatorIsAdmin {
		// Because we record that the creator is an admin by adding identity itself
		// as an admin, we need to remove it from the set of admins, otherwise anyone
		// with access to the identity (even just user access) would be seen as an admin,
		// but we want only the creator to be an admin in such a case.
		admins.Remove(iRef)
	}
	if identities.ContainsAnyElement(admins) {
		return true
	} else if isCreator && creatorIsAdmin {
		return true
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
		// We use true for isCreator here because we want HasAdminAccess to return true
		// always when the identity is not among admins, even in the case of the creator.
		if !i.HasAdminAccess(mapset.NewThreadUnsafeSet(identity), true) {
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
	adminsSet := mapset.NewThreadUnsafeSet(i.Admins...)
	i.Users = slices.DeleteFunc(i.Users, func(ia IdentityRef) bool {
		return adminsSet.Contains(ia)
	})

	// Users should not contain the identity itself. This is only allowed as a special case for admins
	// as a way to signal that the creator has admin access over the identity. We allow the special case
	// for admins even when there is no creator of an identity to make behavior the same for both types
	// of identities (with and without creator), but it does not influence anything.
	if slices.Contains(i.Users, IdentityRef{ID: *i.ID}) {
		return errors.New("identity contains itself as a user")
	}

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
// s.identitiesAccessMu should be locked for reading while calling this function.
func (s *Service) getIdentitiesForAccount(
	_ context.Context, accountID identifier.Identifier, identity IdentityRef,
) (mapset.Set[IdentityRef], bool, errors.E) { //nolint:unparam
	ids := mapset.NewThreadUnsafeSetFromMapKeys(s.identitiesAccess[accountID])
	isCreator := slices.ContainsFunc(s.identitiesAccess[accountID][identity], func(i []IdentityRef) bool {
		// Creator has empty support path.
		return slices.Equal(i, []IdentityRef{})
	})
	return ids, isCreator, nil
}

func (s *Service) getIdentity(ctx context.Context, id identifier.Identifier) (*Identity, bool, errors.E) {
	accountID := mustGetAccountID(ctx)

	s.identitiesMu.RLock()
	defer s.identitiesMu.RUnlock()

	// We lock s.identitiesAccessMu inside s.identitiesMu lock to have
	// consistent view of identities and accounts.
	s.identitiesAccessMu.RLock()
	defer s.identitiesAccessMu.RUnlock()

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

	ids, isCreator, errE := s.getIdentitiesForAccount(ctx, accountID, IdentityRef{ID: *identity.ID})
	if errE != nil {
		return nil, false, errE
	}
	// We could also just check if ids.Contains(IdentityRef{ID: *identity.ID}),
	// but this gives us information about the type of the access.
	if identity.HasAdminAccess(ids, isCreator) {
		return &identity, true, nil
	}
	// We first check for admin access because it has priority over user access.
	// We do not allow same identity in both admins and users, but it could still happen
	// that through transitivity, the same account has access through both admins and users.
	if identity.HasUserAccess(ids) {
		return &identity, false, nil
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

	// We lock s.identitiesAccessMu inside s.identitiesMu lock to have
	// consistent view of identities and accounts.
	s.identitiesAccessMu.Lock()
	defer s.identitiesAccessMu.Unlock()

	s.identities[*identity.ID] = data

	i := IdentityRef{ID: *identity.ID}

	if _, ok := getIdentityID(ctx); !ok {
		// When identity is created using only an account ID without identity ID in the context, identity itself
		// is added to admins in Validate. Here, we record the identity creator, establishing the link
		// between the identity and the account, bootstrapping correct propagation of which accounts have
		// access based on identities.
		s.identityCreators[i] = accountID
	}

	identities := mapset.NewThreadUnsafeSet(identity.Users...)
	identities.Append(identity.Admins...)

	return s.updateAccounts(i, mapset.NewThreadUnsafeSet[IdentityRef](), identities)
}

// setAccountForIdentity adds the identity to the set of identities the account has
// access to, recording the support for the access.
//
// s.identitiesAccessMu should be locked while calling this function.
func (s *Service) setAccountForIdentity(accountID identifier.Identifier, identity IdentityRef, support []IdentityRef) {
	if slices.Contains(support, identity) {
		// We do not do anything if the support path contains the identity
		// because it means that support forms a cycle.
		return
	}
	identities, ok := s.identitiesAccess[accountID]
	if !ok {
		s.identitiesAccess[accountID] = map[IdentityRef][][]IdentityRef{
			identity: {support},
		}
		return
	}
	supports := identities[identity]
	if slices.ContainsFunc(supports, func(e []IdentityRef) bool {
		return slices.Equal(e, support)
	}) {
		return
	}
	identities[identity] = append(supports, support)
}

// unsetAccountForIdentity removes the support from the set of identities the account has
// access to.
//
// s.identitiesAccessMu should be locked while calling this function.
func (s *Service) unsetAccountForIdentity(accountID identifier.Identifier, identity IdentityRef, support []IdentityRef) {
	identities, ok := s.identitiesAccess[accountID]
	if !ok {
		return
	}
	supports, ok := identities[identity]
	if !ok {
		return
	}
	identities[identity] = slices.DeleteFunc(supports, func(e []IdentityRef) bool {
		return slices.Equal(e, support)
	})
	if len(identities[identity]) == 0 {
		delete(identities, identity)
	}
	if len(identities) == 0 {
		delete(s.identitiesAccess, accountID)
	}
}

// getAccountsForIdentity returns all accounts that have access to the identity.
//
// s.identitiesAccessMu should be locked while calling this function.
func (s *Service) getAccountsForIdentity(identity IdentityRef) map[identifier.Identifier][][]IdentityRef {
	accountIDs := map[identifier.Identifier][][]IdentityRef{}
	for accountID, identities := range s.identitiesAccess {
		if supports, ok := identities[identity]; ok {
			accountIDs[accountID] = supports
		}
	}
	return accountIDs
}

func (s *Service) updateIdentity(ctx context.Context, identity *Identity) errors.E {
	accountID := mustGetAccountID(ctx)

	s.identitiesMu.Lock()
	defer s.identitiesMu.Unlock()

	// We lock s.identitiesAccessMu inside s.identitiesMu lock to have
	// consistent view of identities and accounts.
	s.identitiesAccessMu.Lock()
	defer s.identitiesAccessMu.Unlock()

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

	i := IdentityRef{ID: *identity.ID}

	ids, isCreator, errE := s.getIdentitiesForAccount(ctx, accountID, i)
	if errE != nil {
		return errE
	}
	if !existingIdentity.HasAdminAccess(ids, isCreator) {
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

	identitiesBefore := mapset.NewThreadUnsafeSet(existingIdentity.Users...)
	identitiesBefore.Append(existingIdentity.Admins...)

	identitiesAfter := mapset.NewThreadUnsafeSet(identity.Users...)
	identitiesAfter.Append(identity.Admins...)

	return s.updateAccounts(i, identitiesBefore, identitiesAfter)
}

// updateAccounts updates accounts which have access to the identity after the set
// of identities with access to the identity has changed from identitiesBefore to identitiesAfter.
//
// It also recurses to identities which might use this identity in their Users and Admins slices.
//
// s.identitiesMu and s.identitiesAccessMu should be locked while calling this function.
func (s *Service) updateAccounts(identity IdentityRef, identitiesBefore, identitiesAfter mapset.Set[IdentityRef]) errors.E {
	beforeAccounts := s.getAccountsForIdentity(identity)

	// We remove support from all removed identities from corresponding accounts for the identity.
	for removed := range mapset.Elements(identitiesBefore.Difference(identitiesAfter)) {
		for a, supports := range s.getAccountsForIdentity(removed) {
			for _, support := range supports {
				sp := slices.Clone(support)
				sp = append(sp, removed)
				s.unsetAccountForIdentity(a, identity, sp)
			}
		}
		if removed == identity {
			if a, ok := s.identityCreators[identity]; ok {
				s.unsetAccountForIdentity(a, identity, []IdentityRef{})
			}
		}
	}

	// We add support from all added identities to corresponding accounts for the identity.
	for added := range mapset.Elements(identitiesAfter.Difference(identitiesBefore)) {
		if added == identity {
			if a, ok := s.identityCreators[identity]; ok {
				s.setAccountForIdentity(a, identity, []IdentityRef{})
			}
		}
		for a, supports := range s.getAccountsForIdentity(added) {
			for _, support := range supports {
				sp := slices.Clone(support)
				sp = append(sp, added)
				s.setAccountForIdentity(a, identity, sp)
			}
		}
	}

	afterAccounts := s.getAccountsForIdentity(identity)

	if reflect.DeepEqual(beforeAccounts, afterAccounts) {
		// If nothing changed, we can stop here.
		return nil
	}

	// Now we propagate access changes to identities which might use this identity in their Users and Admins slices.
	return s.propagateAccountsUpdate(identity, beforeAccounts, afterAccounts)
}

type beforeAfterAccounts struct {
	identity IdentityRef
	before   map[identifier.Identifier][][]IdentityRef
	after    map[identifier.Identifier][][]IdentityRef
}

func (s *Service) propagateAccountsUpdate(identity IdentityRef, identityBeforeAccounts, identityAfterAccounts map[identifier.Identifier][][]IdentityRef) errors.E {
	changedIdentities := []beforeAfterAccounts{
		{
			identity: identity,
			before:   identityBeforeAccounts,
			after:    identityAfterAccounts,
		},
	}

	for len(changedIdentities) > 0 {
		i := changedIdentities[0].identity
		before := changedIdentities[0].before
		after := changedIdentities[0].after
		changedIdentities = changedIdentities[1:]

		identitySet := mapset.NewThreadUnsafeSet(i)

		for _, data := range s.identities {
			var otherIdentity Identity
			errE := x.UnmarshalWithoutUnknownFields(data, &otherIdentity)
			if errE != nil {
				return errE
			}

			// When the identity and support are the same it is a special case and it really means
			// the creator of the identity which we do not propagate.
			if *otherIdentity.ID == i.ID {
				continue
			}

			// We skip otherIdentity if the identity does not have access to it.
			// We use false for isCreator here because we do not want to propagate the special case
			// anyway here and otherIdentity and identitySet are disjoint anyway, too.
			if !otherIdentity.HasAdminAccess(identitySet, false) && !otherIdentity.HasUserAccess(identitySet) {
				continue
			}

			o := IdentityRef{ID: *otherIdentity.ID}

			beforeAccounts := s.getAccountsForIdentity(o)

			afterKeys := mapset.NewThreadUnsafeSetFromMapKeys(after)
			beforeKeys := mapset.NewThreadUnsafeSetFromMapKeys(before)

			// Before access to the identity changed, all accounts with access to the identity also had access to the otherIdentity
			// through the identity, so we remove support from identity for access to the otherIdentity for all removed accounts.
			for a := range mapset.Elements(beforeKeys.Difference(afterKeys)) {
				for _, support := range before[a] {
					sp := slices.Clone(support)
					sp = append(sp, i)
					s.unsetAccountForIdentity(a, o, sp)
				}
			}

			// For all accounts for which support has changed, we propagate support changes.
			for a := range mapset.Elements(beforeKeys.Intersect(afterKeys)) {
				if reflect.DeepEqual(before[a], after[a]) {
					// Nothing changed.
					continue
				}

				// First we remove all support from before.
				for _, support := range before[a] {
					sp := slices.Clone(support)
					sp = append(sp, i)
					s.unsetAccountForIdentity(a, o, sp)
				}
				// Then we add all support from after, this might re-add support from before, too.
				for _, support := range after[a] {
					sp := slices.Clone(support)
					sp = append(sp, i)
					s.setAccountForIdentity(a, o, sp)
				}
			}

			// All accounts in the accounts set have access to the identity and to the otherIdentity through the identity,
			// so we add support from identity for access to the otherIdentity for all added accounts.
			for a := range mapset.Elements(afterKeys.Difference(beforeKeys)) {
				for _, support := range after[a] {
					sp := slices.Clone(support)
					sp = append(sp, i)
					s.setAccountForIdentity(a, o, sp)
				}
			}

			afterAccounts := s.getAccountsForIdentity(o)

			if reflect.DeepEqual(beforeAccounts, afterAccounts) {
				// If nothing changed, we do not have to recurse for this identity.
				continue
			}

			changedIdentities = append(changedIdentities, beforeAfterAccounts{
				identity: o,
				before:   beforeAccounts,
				after:    afterAccounts,
			})
		}
	}

	return nil
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
	id, errE := identifier.MaybeString(value)
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

func (s *Service) identityList(ctx context.Context, organization, notOrganization *identifier.Identifier, active bool) ([]IdentityRef, errors.E) {
	accountID := mustGetAccountID(ctx)

	result := []IdentityRef{}

	s.identitiesMu.RLock()
	defer s.identitiesMu.RUnlock()

	// We lock s.identitiesAccessMu inside s.identitiesMu lock to have
	// consistent view of identities and accounts.
	s.identitiesAccessMu.RLock()
	defer s.identitiesAccessMu.RUnlock()

	for id, data := range s.identities {
		var identity Identity
		errE := x.UnmarshalWithoutUnknownFields(data, &identity)
		if errE != nil {
			errors.Details(errE)["id"] = id
			return nil, errE
		}

		i := IdentityRef{ID: id}

		ids, isCreator, errE := s.getIdentitiesForAccount(ctx, accountID, i)
		if errE != nil {
			return nil, errE
		}

		// We could also just check if ids.Contains(i), but this matches the logic in
		// getIdentity to minimize any chance of discrepancies.
		// TODO: Do not filter in list endpoint but filter in search endpoint.
		if !identity.HasUserAccess(ids) && !identity.HasAdminAccess(ids, isCreator) {
			continue
		}

		if idOrg := identity.GetOrganization(organization); organization != nil && idOrg != nil {
			// TODO: Do not filter in list endpoint but filter in search endpoint.
			// Or only active identities are requested, or we return all.
			if (active && idOrg.Active) || !active {
				result = append(result, i)
			}
		} else if idOrg := identity.GetOrganization(notOrganization); notOrganization != nil && idOrg == nil {
			result = append(result, i)
		} else if organization == nil && notOrganization == nil {
			result = append(result, i)
		}
	}

	slices.SortFunc(result, func(a IdentityRef, b IdentityRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})

	return result, nil
}

func (s *Service) IdentityListGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	// We allow getting identities with the access token or session cookie.
	ctx := s.requireAuthenticatedForIdentity(w, req)
	if ctx == nil {
		return
	}

	var organization *identifier.Identifier
	if org := req.Form.Get("org"); org != "" {
		o, errE := identifier.MaybeString(org)
		if errE != nil {
			s.BadRequestWithError(w, req, errors.WithMessage(errE, `invalid "org" parameter`))
			return
		}
		organization = &o
	}

	var notOrganization *identifier.Identifier
	if org := req.Form.Get("notorg"); org != "" {
		o, errE := identifier.MaybeString(org)
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

	result, errE := s.identityList(ctx, organization, notOrganization, active)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

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
