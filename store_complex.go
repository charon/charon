package charon

import (
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

// identityAccessEntry is the on-disk representation of a single
// identitiesAccess[accountID] entry: each row stores an identity (which the
// account has access to) and the list of support paths backing that access.
type identityAccessEntry struct {
	Identity IdentityRef     `json:"identity"`
	Supports [][]IdentityRef `json:"supports"`
}

// loadIdentityAccess returns the map[IdentityRef][][]IdentityRef stored under
// accountID. nil is returned (along with a nil error) when there is no entry.
//
// Caller must hold s.identitiesAccessMu (read or write).
func (s *Service) loadIdentityAccess(accountID identifier.Identifier) (map[IdentityRef][][]IdentityRef, errors.E) {
	data, ok := s.identitiesAccess.Get(accountID)
	if !ok {
		return nil, nil //nolint:nilnil
	}
	var entries []identityAccessEntry
	errE := x.UnmarshalWithoutUnknownFields(data, &entries)
	if errE != nil {
		errors.Details(errE)["accountId"] = accountID
		return nil, errE
	}
	m := make(map[IdentityRef][][]IdentityRef, len(entries))
	for _, e := range entries {
		m[e.Identity] = e.Supports
	}
	return m, nil
}

// saveIdentityAccess writes m for accountID, deleting the entry when m is
// empty. Caller must hold s.identitiesAccessMu for writing.
func (s *Service) saveIdentityAccess(accountID identifier.Identifier, m map[IdentityRef][][]IdentityRef) errors.E {
	if len(m) == 0 {
		return s.identitiesAccess.Delete(accountID)
	}
	entries := make([]identityAccessEntry, 0, len(m))
	for id, supports := range m {
		entries = append(entries, identityAccessEntry{Identity: id, Supports: supports})
	}
	data, errE := x.MarshalWithoutEscapeHTML(entries)
	if errE != nil {
		errors.Details(errE)["accountId"] = accountID
		return errE
	}
	return s.identitiesAccess.Set(accountID, data)
}

// loadIdentityCreator returns the creator account ID for identityID. ok is
// false when no creator is stored.
//
// Caller must hold s.identitiesAccessMu (read or write).
func (s *Service) loadIdentityCreator(identityID identifier.Identifier) (identifier.Identifier, bool, errors.E) {
	data, ok := s.identityCreators.Get(identityID)
	if !ok {
		return identifier.Identifier{}, false, nil
	}
	var accountID identifier.Identifier
	errE := x.UnmarshalWithoutUnknownFields(data, &accountID)
	if errE != nil {
		errors.Details(errE)["identityId"] = identityID
		return identifier.Identifier{}, false, errE
	}
	return accountID, true, nil
}

// saveIdentityCreator writes the creator account ID for identityID. Caller
// must hold s.identitiesAccessMu for writing.
func (s *Service) saveIdentityCreator(identityID, accountID identifier.Identifier) errors.E {
	data, errE := x.MarshalWithoutEscapeHTML(accountID)
	if errE != nil {
		errors.Details(errE)["identityId"] = identityID
		return errE
	}
	return s.identityCreators.Set(identityID, data)
}

// identityBlockedEntry is the on-disk representation of a single
// identitiesBlocked[orgID] entry.
type identityBlockedEntry struct {
	IdentityID       identifier.Identifier `json:"identityId"`
	OrganizationNote string                `json:"organizationNote"`
	UserNote         string                `json:"userNote"`
}

// loadIdentitiesBlocked returns map[orgIdentityID]blockedNotes for orgID. nil
// is returned with a nil error when no entry exists.
//
// Caller must hold s.identitiesBlockedMu (read or write).
func (s *Service) loadIdentitiesBlocked(orgID identifier.Identifier) (map[identifier.Identifier]blockedNotes, errors.E) {
	data, ok := s.identitiesBlocked.Get(orgID)
	if !ok {
		return nil, nil //nolint:nilnil
	}
	var entries []identityBlockedEntry
	errE := x.UnmarshalWithoutUnknownFields(data, &entries)
	if errE != nil {
		errors.Details(errE)["organizationId"] = orgID
		return nil, errE
	}
	m := make(map[identifier.Identifier]blockedNotes, len(entries))
	for _, e := range entries {
		m[e.IdentityID] = blockedNotes{OrganizationNote: e.OrganizationNote, UserNote: e.UserNote}
	}
	return m, nil
}

// saveIdentitiesBlocked persists m for orgID, deleting the entry when m is
// empty. Caller must hold s.identitiesBlockedMu for writing.
func (s *Service) saveIdentitiesBlocked(orgID identifier.Identifier, m map[identifier.Identifier]blockedNotes) errors.E {
	if len(m) == 0 {
		return s.identitiesBlocked.Delete(orgID)
	}
	entries := make([]identityBlockedEntry, 0, len(m))
	for id, n := range m {
		entries = append(entries, identityBlockedEntry{
			IdentityID:       id,
			OrganizationNote: n.OrganizationNote,
			UserNote:         n.UserNote,
		})
	}
	data, errE := x.MarshalWithoutEscapeHTML(entries)
	if errE != nil {
		errors.Details(errE)["organizationId"] = orgID
		return errE
	}
	return s.identitiesBlocked.Set(orgID, data)
}

// accountBlockedEntry is the on-disk representation of a single
// accountsBlocked[orgID][accountID] row: per-account list of identity-block
// notes.
type accountBlockedEntry struct {
	AccountID  identifier.Identifier  `json:"accountId"`
	Identities []identityBlockedEntry `json:"identities"`
}

// loadAccountsBlocked returns the inner per-account block map for orgID. nil
// is returned with a nil error when no entry exists.
//
// Caller must hold s.identitiesBlockedMu (read or write).
func (s *Service) loadAccountsBlocked(orgID identifier.Identifier) (map[identifier.Identifier]map[identifier.Identifier]blockedNotes, errors.E) {
	data, ok := s.accountsBlocked.Get(orgID)
	if !ok {
		return nil, nil //nolint:nilnil
	}
	var entries []accountBlockedEntry
	errE := x.UnmarshalWithoutUnknownFields(data, &entries)
	if errE != nil {
		errors.Details(errE)["organizationId"] = orgID
		return nil, errE
	}
	m := make(map[identifier.Identifier]map[identifier.Identifier]blockedNotes, len(entries))
	for _, e := range entries {
		inner := make(map[identifier.Identifier]blockedNotes, len(e.Identities))
		for _, n := range e.Identities {
			inner[n.IdentityID] = blockedNotes{OrganizationNote: n.OrganizationNote, UserNote: n.UserNote}
		}
		m[e.AccountID] = inner
	}
	return m, nil
}

// saveAccountsBlocked persists m for orgID, deleting the entry when m is
// empty. Caller must hold s.identitiesBlockedMu for writing.
func (s *Service) saveAccountsBlocked(
	orgID identifier.Identifier, m map[identifier.Identifier]map[identifier.Identifier]blockedNotes,
) errors.E {
	if len(m) == 0 {
		return s.accountsBlocked.Delete(orgID)
	}
	entries := make([]accountBlockedEntry, 0, len(m))
	for accountID, inner := range m {
		identities := make([]identityBlockedEntry, 0, len(inner))
		for id, n := range inner {
			identities = append(identities, identityBlockedEntry{
				IdentityID:       id,
				OrganizationNote: n.OrganizationNote,
				UserNote:         n.UserNote,
			})
		}
		entries = append(entries, accountBlockedEntry{AccountID: accountID, Identities: identities})
	}
	data, errE := x.MarshalWithoutEscapeHTML(entries)
	if errE != nil {
		errors.Details(errE)["organizationId"] = orgID
		return errE
	}
	return s.accountsBlocked.Set(orgID, data)
}
