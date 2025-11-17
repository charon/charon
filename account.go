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
	ID         identifier.Identifier `json:"id"`
	ProviderID string                `json:"providerId,omitempty"`
	Provider   Provider              `json:"provider"`
	Data       json.RawMessage       `json:"data"`
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
func (a *Account) UpdateCredentials(credentials []Credential) {
	for _, credential := range credentials {
		updated := false
		for i, c := range a.Credentials[credential.Provider] {
			if c.ProviderID == credential.ProviderID {
				credential.ID = c.ID
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

// GetCredential returns the credential for the given provider and provider ID.
func (a *Account) GetCredential(provider Provider, providerID string) *Credential {
	for _, credential := range a.Credentials[provider] {
		if credential.ProviderID == providerID {
			return &credential
		}
	}
	return nil
}

// HasCredentialLabel returns true if existing label was already found for provider in account.
func (a *Account) HasCredentialLabel(provider Provider, label string) (bool, errors.E) {
	credentials, ok := a.Credentials[provider]
	if !ok {
		return false, nil
	}

	switch provider {
	case ProviderEmail, ProviderUsername, ProviderCode:
		return false, errors.New("provider does not support labels")
	case ProviderPassword:
		for _, credential := range credentials {
			var pc passwordCredential
			errE := x.Unmarshal(credential.Data, &pc)
			if errE != nil {
				return false, errE
			}
			if pc.Label == label {
				return true, nil
			}
		}
	case ProviderPasskey:
		for _, credential := range credentials {
			var pk passkeyCredential
			errE := x.Unmarshal(credential.Data, &pk)
			if errE != nil {
				return false, errE
			}
			if pk.Label == label {
				return true, nil
			}
		}
	default:
		return false, errors.New("third party provider does not support labels")
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

		if !account.HasCredential(provider, providerID) {
			continue
		}
		if provider == ProviderEmail {
			credential := account.GetCredential(provider, providerID)
			if credential == nil {
				// This should not happen, account.HasCredential returned true.
				return nil, errors.WithDetails(ErrAccountNotFound, "provider", provider, "providerID", providerID)
			}
			var ec emailCredential
			errE := x.Unmarshal(credential.Data, &ec)
			if errE != nil {
				return nil, errE
			}
			if !ec.Verified {
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

// DisplayName contains logic for determining DisplayName of credential.
func (c *Credential) DisplayName() (string, errors.E) {
	switch c.Provider {
	case ProviderEmail:
		var ec emailCredential
		errE := x.Unmarshal(c.Data, &ec)
		if errE != nil {
			return "", errE
		}
		return ec.Email, nil
	case ProviderUsername:
		var uc usernameCredential
		errE := x.Unmarshal(c.Data, &uc)
		if errE != nil {
			return "", errE
		}
		return uc.Username, nil
	case ProviderCode:
		return "", errors.New("not allowed")
	case ProviderPassword:
		var pc passwordCredential
		errE := x.Unmarshal(c.Data, &pc)
		if errE != nil {
			return "", errE
		}
		return pc.Label, nil
	case ProviderPasskey:
		var pkc passkeyCredential
		errE := x.Unmarshal(c.Data, &pkc)
		if errE != nil {
			return "", errE
		}
		return pkc.Label, nil
	default:
		var token map[string]interface{}
		errE := x.Unmarshal(c.Data, &token)
		if errE == nil {
			return findFirstString(token, "username", "preferred_username", "email", "eMailAddress", "emailAddress", "email_address"), nil
		}
	}
	return "", errors.New("displayName provider not found")
}

// ToCredentialInfo converts the credential to a CredentialInfo used for display.
func (c *Credential) ToCredentialInfo() (CredentialInfo, errors.E) {
	credentialInfo := CredentialInfo{
		ID:          c.ID,
		Provider:    c.Provider,
		DisplayName: "",
		Verified:    false,
	}

	displayName, errE := c.DisplayName()
	if errE != nil {
		return CredentialInfo{}, errE
	}
	credentialInfo.DisplayName = displayName

	if c.Provider == ProviderEmail {
		var ec emailCredential
		errE := x.Unmarshal(c.Data, &ec)
		if errE != nil {
			return CredentialInfo{}, errE
		}
		credentialInfo.Verified = ec.Verified
	}

	return credentialInfo, nil
}
