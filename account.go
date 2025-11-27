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
type AccountRef struct {
	ID identifier.Identifier `json:"-"`
}

// Account represents an account which consists of an identifier and a set of credentials.
type Account struct {
	ID identifier.Identifier

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
					a.Credentials[credential.Provider][i] = credential
					updated = true
					break
				}
			} else if c.ProviderID == credential.ProviderID {
				// It is useful to retain the old public ID.
				// TODO: We should make sure that any other credential does not have the same public ID.
				credential.ID = c.ID
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

// HasCredentialDisplayName returns true if displayName is already in use by a credential for the provider in the account.
func (a *Account) HasCredentialDisplayName(provider Provider, displayName string) (bool, errors.E) {
	credentials, ok := a.Credentials[provider]
	if !ok {
		return false, nil
	}

	for _, credential := range credentials {
		if credential.DisplayName == displayName {
			return true, nil
		}
	}

	return false, nil
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

		credential := account.GetCredential(provider, providerID)
		if credential == nil {
			continue
		}
		if provider == ProviderEmail {
			if !credential.Verified {
				continue
			}
		}
		return account, nil
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
