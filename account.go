package charon

import (
	"bytes"
	"context"
	"encoding/json"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

var ErrAccountNotFound = errors.Base("account not found")

// Provider is the credential provider name.
type Provider string

// Credential represents a credential issued by a credential provider.
type Credential struct {
	ID         identifier.Identifier
	ProviderID string
	Provider   Provider
	Data       json.RawMessage
}

// Equal returns true if the two credentials are equal.
func (c1 *Credential) Equal(c2 *Credential) bool {
	if c1 == nil && c2 == nil {
		return true
	}
	if c1 == nil || c2 == nil {
		return false
	}
	return c1.ProviderID == c2.ProviderID && c1.Provider == c2.Provider && bytes.Equal(c1.Data, c2.Data)
}

// AccountRef is a reference to an account.
type AccountRef struct {
	ID identifier.Identifier `json:"-"`
}

// Account represents an account which consists of an identifier and a set of credentials.
type Account struct {
	ID identifier.Identifier

	Credentials map[Provider][]Credential
}

// HasCredential returns true if the account has a credential for the given provider and credential ID.
func (a *Account) HasCredential(provider Provider, providerID string) bool {
	return a.GetCredential(provider, providerID) != nil
}

// UpdateCredentials updates the credentials for the account.
func (a *Account) UpdateCredentials(credentials []Credential) {
	for _, credential := range credentials {
		updated := false
		for i, c := range a.Credentials[credential.Provider] {
			if c.ProviderID == credential.ProviderID {
				a.Credentials[credential.Provider][i] = credential
				updated = true
				break
			}
		}
		if !updated {
			a.Credentials[credential.Provider] = append(a.Credentials[credential.Provider], credential)
		}
	}
}

// GetCredential returns the credential for the given provider and credential ID.
func (a *Account) GetCredential(provider Provider, providerID string) *Credential {
	for _, credential := range a.Credentials[provider] {
		if credential.ProviderID == providerID {
			return &credential
		}
	}
	return nil
}

// GetEmailAddresses returns the email addresses of the account.
func (a *Account) GetEmailAddresses() ([]string, errors.E) {
	emails := []string{}
	for _, credential := range a.Credentials[ProviderEmail] {
		var c emailCredential
		errE := x.Unmarshal(credential.Data, &c)
		if errE != nil {
			return nil, errE
		}
		emails = append(emails, c.Email)
	}
	return emails, nil
}

func (s *Service) getAccount(_ context.Context, id identifier.Identifier) (*Account, errors.E) {
	s.accountsMu.RLock()
	defer s.accountsMu.RUnlock()

	data, ok := s.accounts[id]
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

func (s *Service) getAccountByCredential(ctx context.Context, provider Provider, providerID string) (*Account, errors.E) {
	s.accountsMu.RLock()
	defer s.accountsMu.RUnlock()

	for id := range s.accounts {
		account, errE := s.getAccount(ctx, id)
		if errE != nil {
			return nil, errE
		}

		if account.HasCredential(provider, providerID) {
			return account, nil
		}
	}

	return nil, errors.WithDetails(ErrAccountNotFound, "provider", provider, "providerID", providerID)
}

func (s *Service) setAccount(_ context.Context, account *Account) errors.E {
	data, errE := x.MarshalWithoutEscapeHTML(account)
	if errE != nil {
		errors.Details(errE)["id"] = account.ID
		return errE
	}

	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()

	s.accounts[account.ID] = data
	return nil
}
