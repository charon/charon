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

type Provider string

type Credential struct {
	ID       string
	Provider Provider
	Data     json.RawMessage
}

func (c1 *Credential) Equal(c2 *Credential) bool {
	if c1 == nil && c2 == nil {
		return true
	}
	if c1 == nil || c2 == nil {
		return false
	}
	return c1.ID == c2.ID && c1.Provider == c2.Provider && bytes.Equal(c1.Data, c2.Data)
}

type Account struct {
	ID identifier.Identifier

	Credentials map[Provider][]Credential
}

func (a *Account) HasCredential(provider Provider, credentialID string) bool {
	return a.GetCredential(provider, credentialID) != nil
}

func (a *Account) UpdateCredentials(credentials []Credential) {
	for _, credential := range credentials {
		for i, c := range a.Credentials[credential.Provider] {
			if c.ID == credential.ID {
				a.Credentials[credential.Provider][i] = credential
				break
			}
		}
	}
}

func (a *Account) GetCredential(provider Provider, credentialID string) *Credential {
	for _, credential := range a.Credentials[provider] {
		if credential.ID == credentialID {
			return &credential
		}
	}
	return nil
}

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

func (s *Service) getAccountByCredential(ctx context.Context, provider Provider, credentialID string) (*Account, errors.E) {
	s.accountsMu.RLock()
	defer s.accountsMu.RUnlock()

	for id := range s.accounts {
		account, errE := s.getAccount(ctx, id)
		if errE != nil {
			return nil, errE
		}

		if account.HasCredential(provider, credentialID) {
			return account, nil
		}
	}

	return nil, errors.WithDetails(ErrAccountNotFound, "provider", provider, "credentialID", credentialID)
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
