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
	ErrIdentityUpdateNotAllowed = errors.Base("identity update not allowed")
	ErrIdentityValidationFailed = errors.Base("identity validation failed")
	ErrIdentityBlocked          = errors.Base("identity blocked")

	errEmptyIdentity = errors.Base("empty identity")
)

type IdentityOrganization struct {
	// ID is also ID of this identity in the organization (it is organization-scoped).
	ID *identifier.Identifier `json:"id"`

	Active bool `json:"active"`

	Organization OrganizationRef                         `json:"organization"`
	Applications []OrganizationApplicationApplicationRef `json:"applications"`
}

func (i *IdentityOrganization) Validate(ctx context.Context, existing *IdentityOrganization, service *Service, identity *Identity) errors.E {
	if existing == nil {
		if i.ID != nil {
			errE := errors.New("ID provided for new document")
			errors.Details(errE)["id"] = *i.ID
			return errE
		}
		co := service.charonOrganization()
		if co.ID == i.Organization.ID {
			// A special case for Charon organization: organization-scoped identity ID is the same as the identity ID.
			// Permissions generally use organization-scoped IDs and operate only with identities which are added to
			// the organization, but for Charon organization we want permissions to operate also on identities which
			// have not been added to the Charon organization (so that users can give permissions over identities to
			// other users while those identities have never been used with the Charon organization itself). One way
			// to address this would be to always add all identities to the Charon organization so that they all get
			// assigned its organization-scoped IDs, but that would then mean that we would also have to prevent removing
			// Charon organization and also users will not know which identities they have previously used with the
			// Charon organization (as it would look like they used all of them). Instead, we use the identity ID as
			// organization-scoped ID. This allows us to have an ID for use in Charon organization identity permissions
			// even if the identity has not been added to the Charon organization. This also enables our approach of
			// recording that identity's creator is an admin by adding the identity itself as an admin for itself.
			// Otherwise we would not have an ID to do that, unless we would (again) add all identities to the Charon
			// organization by default. We could use an extra field to record creator's admin permission, but that is uglier.
			i.ID = identity.ID
		} else {
			id := identifier.New()
			i.ID = &id
		}
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

	if existing != nil && i.Organization.ID != existing.Organization.ID {
		errE := errors.New("payload organization ID does not match existing organization ID")
		errors.Details(errE)["payload"] = i.Organization.ID
		errors.Details(errE)["existing"] = existing.Organization.ID
		return errE
	}

	organization, errE := service.getOrganization(ctx, i.Organization.ID)
	if errors.Is(errE, ErrOrganizationNotFound) {
		errE = errors.New("unknown organization")
		errors.Details(errE)["organization"] = i.Organization.ID
		return errE
	} else if errE != nil {
		errors.Details(errE)["organization"] = i.Organization.ID
		return errE
	}

	// We remove duplicates.
	i.Applications = removeDuplicates(i.Applications)

	existingApplications := mapset.NewThreadUnsafeSet[OrganizationApplicationApplicationRef]()
	if existing != nil {
		existingApplications.Append(existing.Applications...)
	}

	// We validate only added applications so that we do not error out on disabled or removed applications.
	unknown := mapset.NewThreadUnsafeSet[OrganizationApplicationApplicationRef]()
	for newApplication := range mapset.Elements(mapset.NewThreadUnsafeSet(i.Applications...).Difference(existingApplications)) {
		if application := organization.GetApplication(&newApplication.ID); application == nil || !application.Active {
			unknown.Add(newApplication)
		}
	}
	if !unknown.IsEmpty() {
		errE := errors.New("unknown applications")
		applications := unknown.ToSlice()
		slices.SortFunc(applications, organizationApplicationApplicationRefCmp)
		errors.Details(errE)["applications"] = applications
	}

	return nil
}

type IdentityPublic struct {
	// ID is a database ID when stored in the database or it is an
	// IdentityOrganization's (organization-scoped) ID when exposing over API.
	ID *identifier.Identifier `json:"id"`

	Username   string `json:"username,omitempty"`
	Email      string `json:"email,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FullName   string `json:"fullName,omitempty"`
	PictureURL string `json:"pictureUrl,omitempty"`
}

func (i *IdentityPublic) Validate(ctx context.Context, existing *IdentityPublic) errors.E {
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

	return nil
}

type Identity struct {
	IdentityPublic

	// Description for users with access to the identity.
	Description string `json:"description,omitempty"`

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

func identityRefCmp(a IdentityRef, b IdentityRef) int {
	return bytes.Compare(a.ID[:], b.ID[:])
}

// Validate uses ctx with identityIDContextKey if set.
// When not set, changes to admins are not allowed.
func (i *Identity) Validate(ctx context.Context, existing *Identity, service *Service) errors.E {
	var e *IdentityPublic
	if existing == nil {
		e = nil
	} else {
		e = &existing.IdentityPublic
	}
	errE := i.IdentityPublic.Validate(ctx, e)
	if errE != nil {
		return errE
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

	// We remove duplicates.
	i.Admins = removeDuplicates(i.Admins)
	i.Users = removeDuplicates(i.Users)

	// Admins should not be users as well.
	adminsSet := mapset.NewThreadUnsafeSet(i.Admins...)
	i.Users = slices.DeleteFunc(i.Users, func(ia IdentityRef) bool {
		return adminsSet.Contains(ia)
	})

	// TODO: We will have to rethink this once we have an invitation system and general permission system.
	//       Because users permissions will probably be per organization (e.g., you can use my identity for this
	//       particular organization and not for all organizations I am using). But we will still want that
	//       users are using identities from other users without those identities having to join the
	//       Charon organization (but they have to join the target organization).
	identities := mapset.NewThreadUnsafeSet(i.Users...)
	identities.Append(i.Admins...)
	unknown := service.hasIdentities(ctx, identities, false)
	if !unknown.IsEmpty() {
		errE := errors.New("unknown identities")
		identities := unknown.ToSlice()
		slices.SortFunc(identities, identityRefCmp)
		errors.Details(errE)["identities"] = identities
	}

	if i.Organizations == nil {
		i.Organizations = []IdentityOrganization{}
	}

	idOrgsSet := mapset.NewThreadUnsafeSet[identifier.Identifier]()
	organizationsSet := mapset.NewThreadUnsafeSet[identifier.Identifier]()
	for ii, idOrg := range i.Organizations {
		errE := idOrg.Validate(ctx, existing.GetIdentityOrganization(idOrg.ID), service, i)
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

// Changes compares the current Identity with an existing one and returns the types of changes
// that occurred, user and admin identities that were added or removed, organizations
// that were added, removed or changed and applications that were added or removed.
func (i *Identity) Changes(existing *Identity) ([]ActivityChangeType, []IdentityRef, []OrganizationRef, []OrganizationApplicationRef) {
	changes := []ActivityChangeType{}

	if !reflect.DeepEqual(i.IdentityPublic, existing.IdentityPublic) || i.Description != existing.Description {
		changes = append(changes, ActivityChangeOtherData)
	}

	usersAdded, usersRemoved := detectSliceChanges(existing.Users, i.Users)
	adminsAdded, adminsRemoved := detectSliceChanges(existing.Admins, i.Admins)

	if !usersAdded.IsEmpty() || !adminsAdded.IsEmpty() {
		changes = append(changes, ActivityChangePermissionsAdded)
	}
	if !usersRemoved.IsEmpty() || !adminsRemoved.IsEmpty() {
		changes = append(changes, ActivityChangePermissionsRemoved)
	}

	identitiesChanged := usersAdded.Union(usersRemoved).Union(adminsAdded).Union(adminsRemoved).ToSlice()
	slices.SortFunc(identitiesChanged, identityRefCmp)

	// We make copies of organization structs on purpose, so that we can change Active field as needed.
	existingOrganizationMap := make(map[OrganizationRef]IdentityOrganization)
	for _, idOrg := range existing.Organizations {
		existingOrganizationMap[idOrg.Organization] = idOrg
	}
	newOrganizationMap := make(map[OrganizationRef]IdentityOrganization)
	for _, idOrg := range i.Organizations {
		newOrganizationMap[idOrg.Organization] = idOrg
	}

	existingOrganizationSet := mapset.NewThreadUnsafeSetFromMapKeys(existingOrganizationMap)
	newOrganizationSet := mapset.NewThreadUnsafeSetFromMapKeys(newOrganizationMap)

	addedOrganizationSet := newOrganizationSet.Difference(existingOrganizationSet)
	removedOrganizationSet := existingOrganizationSet.Difference(newOrganizationSet)

	addedAppSet := mapset.NewThreadUnsafeSet[OrganizationApplicationRef]()
	removedAppSet := mapset.NewThreadUnsafeSet[OrganizationApplicationRef]()

	for orgRef := range mapset.Elements(addedOrganizationSet) {
		for _, app := range newOrganizationMap[orgRef].Applications {
			addedAppSet.Add(OrganizationApplicationRef{
				Organization: orgRef,
				Application:  app,
			})
		}
	}

	for orgRef := range mapset.Elements(removedOrganizationSet) {
		for _, app := range existingOrganizationMap[orgRef].Applications {
			removedAppSet.Add(OrganizationApplicationRef{
				Organization: orgRef,
				Application:  app,
			})
		}
	}

	changedOrganizationSet := mapset.NewThreadUnsafeSet[OrganizationRef]()
	activatedOrganizationSet := mapset.NewThreadUnsafeSet[OrganizationRef]()
	disabledOrganizationSet := mapset.NewThreadUnsafeSet[OrganizationRef]()

	// Compare organizations which are in both sets.
	for orgRef := range mapset.Elements(newOrganizationSet.Intersect(existingOrganizationSet)) {
		existingOrg := existingOrganizationMap[orgRef]
		newOrg := newOrganizationMap[orgRef]

		if newOrg.Active && !existingOrg.Active {
			activatedOrganizationSet.Add(orgRef)
		}
		if !newOrg.Active && existingOrg.Active {
			disabledOrganizationSet.Add(orgRef)
		}

		appsAdded, appsRemoved := detectSliceChanges(existingOrg.Applications, newOrg.Applications)
		for app := range mapset.Elements(appsAdded) {
			addedAppSet.Add(OrganizationApplicationRef{
				Organization: orgRef,
				Application:  app,
			})
		}
		for app := range mapset.Elements(appsRemoved) {
			removedAppSet.Add(OrganizationApplicationRef{
				Organization: orgRef,
				Application:  app,
			})
		}

		// We make Active and Applications fields the same and in this way compare the rest.
		existingOrg.Active = newOrg.Active
		existingOrg.Applications = newOrg.Applications
		if !reflect.DeepEqual(existingOrg, newOrg) {
			changedOrganizationSet.Add(orgRef)
		}
	}

	if !addedOrganizationSet.IsEmpty() || !addedAppSet.IsEmpty() {
		changes = append(changes, ActivityChangeMembershipAdded)
	}
	if !removedOrganizationSet.IsEmpty() || !removedAppSet.IsEmpty() {
		changes = append(changes, ActivityChangeMembershipRemoved)
	}
	if !changedOrganizationSet.IsEmpty() {
		changes = append(changes, ActivityChangeMembershipChanged)
	}
	if !activatedOrganizationSet.IsEmpty() {
		changes = append(changes, ActivityChangeMembershipActivated)
	}
	if !disabledOrganizationSet.IsEmpty() {
		changes = append(changes, ActivityChangeMembershipDisabled)
	}

	organizationsChanged := addedOrganizationSet.Union(
		removedOrganizationSet,
	).Union(
		changedOrganizationSet,
	).Union(
		activatedOrganizationSet,
	).Union(
		disabledOrganizationSet,
	).ToSlice()
	slices.SortFunc(organizationsChanged, organizationRefCmp)

	applicationsChanged := addedAppSet.Union(removedAppSet).ToSlice()
	slices.SortFunc(applicationsChanged, organizationApplicationRefCmp)

	return changes, identitiesChanged, organizationsChanged, applicationsChanged
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

func (s *Service) getIdentityWithoutAccessCheck(_ context.Context, id identifier.Identifier) (*Identity, errors.E) {
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

	return &identity, nil
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

	errE := identity.Validate(ctx, nil, s)
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

	i := IdentityRef{ID: *identity.ID}

	if _, ok := getIdentityID(ctx); !ok {
		// When identity is created using only an account ID without identity ID in the context, identity itself
		// is added to admins in Validate. Here, we record the identity creator, establishing the link
		// between the identity and the account, bootstrapping correct propagation of which accounts have
		// access based on identities.
		s.identityCreators[i] = accountID

		// We also here current identity ID in the context, which is used by logActivity.
		ctx = s.withIdentityID(ctx, *identity.ID)
	}

	errE = s.logActivity(ctx, ActivityIdentityCreate, []IdentityRef{{ID: *identity.ID}}, nil, nil, nil, nil, nil)
	if errE != nil {
		return errE
	}

	s.identities[*identity.ID] = data

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

func (s *Service) getAccountsForIdentityWithLock(identity IdentityRef) map[identifier.Identifier][][]IdentityRef {
	s.identitiesAccessMu.RLock()
	defer s.identitiesAccessMu.RUnlock()

	return s.getAccountsForIdentity(identity)
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

	errE = identity.Validate(ctx, &existingIdentity, s)
	if errE != nil {
		return errors.WrapWith(errE, ErrIdentityValidationFailed)
	}

	data, errE := x.MarshalWithoutEscapeHTML(identity)
	if errE != nil {
		errors.Details(errE)["id"] = *identity.ID
		return errE
	}

	if _, ok := getIdentityID(ctx); !ok {
		// When identity is updated using only an account ID without identity ID in the context, we allow updating only if
		// only the identity itself has admin access to the identity. This is really meant for cases where user creates
		// an identity during an authentication flow and then notices a mistake and wants to update it.
		// It does not matter if we check existingIdentity.Admins or identity.Admins because when identity ID is
		// not in the context, Validate method prevents changes to admins.
		if len(existingIdentity.Admins) != 1 || existingIdentity.Admins[0].ID != *identity.ID {
			return errors.WithDetails(ErrIdentityUpdateNotAllowed, "id", *identity.ID)
		}

		// We set here current identity ID in the context, which is used by logActivity.
		ctx = s.withIdentityID(ctx, *identity.ID)
	}

	changes, identities, organizations, applications := identity.Changes(&existingIdentity)

	if len(changes) == 0 {
		// No changes, do not continue.
		return nil
	}

	// We make sure identity reference i is always the first element in identities. This might leave identities
	// with the duplicate identity i, but that is better than removing duplicates because it is deterministic
	// and the frontend can always then take the first element to be the identity that was updated.
	identities = append([]IdentityRef{i}, identities...)

	errE = s.logActivity(ctx, ActivityIdentityUpdate, identities, organizations, nil, applications, changes, nil)
	if errE != nil {
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
			if !otherIdentity.HasUserAccess(identitySet) && !otherIdentity.HasAdminAccess(identitySet, false) {
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
func (s *Service) selectAndActivateIdentity(ctx context.Context, identityID, organizationID, applicationID identifier.Identifier) (*Identity, errors.E) {
	identity, _, errE := s.getIdentity(ctx, identityID)
	if errE != nil {
		return nil, errE
	}

	isBlocked, errE := s.isIdentityOrAccountBlockedInOrganization(ctx, identity, mustGetAccountID(ctx), organizationID)
	if errE != nil {
		return nil, errE
	} else if isBlocked {
		return nil, errors.WithStack(ErrIdentityBlocked)
	}

	applicationRef := OrganizationApplicationApplicationRef{ID: applicationID}

	idOrg := identity.GetOrganization(&organizationID)
	if idOrg != nil {
		if idOrg.Active {
			// Organization already present and active.
			if slices.Contains(idOrg.Applications, applicationRef) {
				// Application already present, nothing to do.
				return identity, nil
			}

			// Application not present, we add it.
			idOrg.Applications = append(idOrg.Applications, applicationRef)

			return identity, s.updateIdentity(ctx, identity)
		}
		return nil, errors.New("identity not active for organization")
	}

	// Organization not present, we add it (as active).
	identity.Organizations = append(identity.Organizations, IdentityOrganization{
		ID:     nil,
		Active: true,
		Organization: OrganizationRef{
			ID: organizationID,
		},
		Applications: []OrganizationApplicationApplicationRef{applicationRef},
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

	currentIdentityID, hasCurrentIdentityID := getIdentityID(ctx)

	identity, isAdmin, errE := s.getIdentityFromID(ctx, params["id"])
	if errors.Is(errE, ErrIdentityUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errors.Is(errE, ErrIdentityNotFound) {
		s.NotFoundWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if isAdmin {
		// getIdentityFromID checked that user has user or admin access to the identity
		// so here we know that they have both.
		s.WriteJSON(w, req, identity, map[string]interface{}{
			"can_use":    true,
			"can_update": true,
			"is_current": hasCurrentIdentityID && *identity.ID == currentIdentityID,
		})
		return
	}

	// getIdentityFromID checked that user has user or admin access to the identity
	// so here we know that they have only user access.
	s.WriteJSON(w, req, identity, map[string]interface{}{
		"can_use":    true,
		"is_current": hasCurrentIdentityID && *identity.ID == currentIdentityID,
	})
}

func (s *Service) hasIdentities(_ context.Context, ids mapset.Set[IdentityRef], lock bool) mapset.Set[IdentityRef] {
	if lock {
		s.identitiesMu.RLock()
		defer s.identitiesMu.RUnlock()
	}

	unknown := mapset.NewThreadUnsafeSet[IdentityRef]()

	for id := range mapset.Elements(ids) {
		if _, ok := s.identities[id.ID]; !ok {
			unknown.Add(id)
		}
	}

	return unknown
}

func (s *Service) identityList(ctx context.Context) ([]IdentityRef, errors.E) {
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

		hasUserAccess := identity.HasUserAccess(ids)
		hasAdminAccess := identity.HasAdminAccess(ids, isCreator)
		if !hasUserAccess && !hasAdminAccess {
			continue
		}

		result = append(result, i)
	}

	slices.SortFunc(result, identityRefCmp)

	return result, nil
}

func (s *Service) IdentityListGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	// We allow getting identities with the access token or session cookie.
	ctx := s.requireAuthenticatedForIdentity(w, req)
	if ctx == nil {
		return
	}

	result, errE := s.identityList(ctx)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) IdentityUpdatePost(w http.ResponseWriter, req *http.Request, params waf.Params) { //nolint:dupl
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

	// If identity.ID == nil, updateIdentity returns an error.
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
		s.NotFoundWithError(w, req, errE)
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
