package charon

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

var ErrAccountNotFound = errors.Base("account not found")

// Provider is the credential provider name.
type Provider string

// CredentialPublic represents public information about a credential.
type CredentialPublic struct {
	// ID is a public-facing ID used to identify the credential in public API.
	ID identifier.Identifier `json:"id"`
	// Base is the slice of strings from which the ID is derived. It is standalone (it does not extend
	// the base of the account) because credentials are created before the account exists and for
	// passkey credentials the ID doubles as the WebAuthn user handle which is fixed at registration.
	Base []string `json:"base"`
	// Provider is the internal provider type name or the name of the third party provider.
	Provider Provider `json:"provider"`
	// DisplayName is a user facing string, initially set automatically. For username/email it equals
	// the original (normalized but not mapped) credential value itself. Otherwise, user can rename it.
	// Unique per account per provider.
	DisplayName string `json:"displayName"`
	// Confirmed is relevant for e-mail addresses, otherwise empty. For confirmed
	// e-mail credentials it holds the mapped/canonical e-mail address; the empty
	// string means "not confirmed". This lets a single field answer both "is this
	// e-mail credential confirmed?" and "what is the canonical address it confirms?".
	Confirmed string `json:"confirmed,omitempty"`
}

// Ref returns the credential reference.
func (c *CredentialPublic) Ref() CredentialRef {
	return CredentialRef{ID: c.ID}
}

// CredentialRef represents a reference to a credential.
type CredentialRef struct {
	ID identifier.Identifier `json:"id"`
}

func credentialRefCmp(a CredentialRef, b CredentialRef) int {
	return bytes.Compare(a.ID[:], b.ID[:])
}

// Credential represents a credential issued by a credential provider.
type Credential struct {
	CredentialPublic

	// ProviderID is the ID bound to the credential provider.
	ProviderID string `json:"providerId,omitempty"`

	// Data is the raw credential data.
	Data json.RawMessage `json:"data"`
}

// Equal returns true if the two credentials are equal.
func (c *Credential) Equal(c2 *Credential) bool {
	if c == nil && c2 == nil {
		return true
	}
	if c == nil || c2 == nil {
		return false
	}
	return c.ProviderID == c2.ProviderID && c.Provider == c2.Provider && bytes.Equal(c.Data, c2.Data)
}

// AccountRef is a reference to an account.
//
// Account IDs are internal and must never be exposed over the API because that would
// allow linking identities to accounts.
type AccountRef struct {
	ID identifier.Identifier `json:"id"`
}

// Account represents an account which consists of an identifier and a set of credentials.
type Account struct {
	ID identifier.Identifier
	// Base is the slice of strings from which the document ID is derived.
	Base []string

	Credentials map[Provider][]Credential
}

// HasCredential returns true if the account has a credential for the given provider and provider ID.
func (a *Account) HasCredential(provider Provider, providerID string) bool {
	return a.GetCredential(provider, providerID) != nil
}

// UpdateCredentials updates the credentials for the account.
//
// It matches existing credentials based on provider ID, except for password
// credentials which are matched based on public ID.
//
// Password credentials can only be updated but not added using this method.
func (a *Account) UpdateCredentials(credentials []Credential) errors.E {
	for _, credential := range credentials {
		updated := false
		for i, c := range a.Credentials[credential.Provider] {
			if credential.Provider == ProviderPassword {
				// Password credentials do not use provider ID.
				if c.ID == credential.ID {
					credential.Base = c.Base
					a.Credentials[credential.Provider][i] = credential
					updated = true
					break
				}
			} else if c.ProviderID == credential.ProviderID {
				// It is useful to retain the old public ID (and with it its base).
				// TODO: We should make sure that any other credential does not have the same public ID.
				credential.ID = c.ID
				credential.Base = c.Base
				a.Credentials[credential.Provider][i] = credential
				updated = true
				break
			}
		}
		if !updated {
			if credential.Provider == ProviderPassword {
				// This is to catch logic errors where UpdateCredentials is used to add the password.
				// We do not allow adding passwords because they do not have provider ID and we cannot
				// really compare them for equality (without knowing the password) so it could happen
				// that same password is added multiple times.
				return errors.New("password credential can be only updated but not added")
			}
			a.Credentials[credential.Provider] = append(a.Credentials[credential.Provider], credential)
		}
	}

	return nil
}

// GetCredential returns the credential for the given provider and provider ID.
func (a *Account) GetCredential(provider Provider, providerID string) *Credential {
	// Password credentials do not use provider ID.
	if provider == ProviderPassword || providerID == "" {
		return nil
	}

	for _, credential := range a.Credentials[provider] {
		if credential.ProviderID == providerID {
			return &credential
		}
	}
	return nil
}

// getCredentialByID finds a credential by ID across providers, excluding ProviderCode.
func (a *Account) getCredentialByID(credentialID identifier.Identifier) (*Credential, Provider, int) {
	for provider := range a.Credentials {
		// Code provider credentials are never exposed over the API.
		if provider == ProviderCode {
			continue
		}
		for i, credential := range a.Credentials[provider] {
			if credential.ID == credentialID {
				return &credential, provider, i
			}
		}
	}

	return nil, "", -1
}

// HasCredentialDisplayName returns true if displayName is already in use by a credential for the provider in the account.
func (a *Account) HasCredentialDisplayName(provider Provider, displayName string) bool {
	credentials, ok := a.Credentials[provider]
	if !ok {
		return false
	}

	for _, credential := range credentials {
		if credential.DisplayName == displayName {
			return true
		}
	}

	return false
}

// HasEmailAddress returns true if mappedEmail is already confirmed in the account.
// The caller is expected to pass the mapped/canonical form.
func (a *Account) HasEmailAddress(mappedEmail string) bool {
	return slices.Contains(a.GetEmailAddresses(), mappedEmail)
}

// GetEmailAddresses returns confirmed e-mail addresses (mapped/canonical form) of the account.
func (a *Account) GetEmailAddresses() []string {
	mappedEmails := make([]string, 0, len(a.Credentials[ProviderEmail]))
	for _, credential := range a.Credentials[ProviderEmail] {
		if credential.Confirmed == "" {
			continue
		}
		// The mapped/canonical e-mail address is stored in ProviderID.
		mappedEmails = append(mappedEmails, credential.ProviderID)
	}

	return mappedEmails
}

func (s *Service) getAccount(_ context.Context, id identifier.Identifier) (*Account, errors.E) {
	s.accounts.RLock()
	defer s.accounts.RUnlock()

	data, ok := s.accounts.Get(id)
	if !ok {
		return nil, errors.WithDetails(ErrAccountNotFound, "id", id)
	}
	var account Account
	errE := x.UnmarshalWithoutUnknownFields(data, &account)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, errE
	}
	return &account, nil
}

func (s *Service) getAccountByCredential(_ context.Context, provider Provider, providerID string) (*Account, errors.E) {
	s.accounts.RLock()
	defer s.accounts.RUnlock()

	for id, data := range s.accounts.All() {
		var account Account
		errE := x.UnmarshalWithoutUnknownFields(data, &account)
		if errE != nil {
			errors.Details(errE)["id"] = id
			return nil, errE
		}
		credential := account.GetCredential(provider, providerID)
		if credential == nil {
			continue
		}
		if provider == ProviderEmail && credential.Confirmed == "" {
			continue
		}
		return &account, nil
	}

	return nil, errors.WithDetails(ErrAccountNotFound, "provider", provider, "providerID", providerID)
}

func (s *Service) setAccount(_ context.Context, account *Account) errors.E {
	data, errE := x.MarshalWithoutEscapeHTML(account)
	if errE != nil {
		errors.Details(errE)["id"] = account.ID
		return errE
	}

	s.accounts.Lock()
	defer s.accounts.Unlock()

	return s.accounts.Set(account.ID, data)
}
