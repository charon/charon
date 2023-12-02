package charon

import (
	"context"
	"encoding/json"
	"sync"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
)

var ErrAccountNotFound = errors.Base("account not found")

var (
	accounts   = make(map[identifier.Identifier][]byte) //nolint:gochecknoglobals
	accountsMu = sync.RWMutex{}                         //nolint:gochecknoglobals
)

type Credential struct {
	ID       string
	Provider string
	Data     json.RawMessage
}

type Account struct {
	ID identifier.Identifier

	Credentials map[string][]Credential
}

func (a *Account) HasCredential(provider, credentialID string) bool {
	return a.GetCredential(provider, credentialID) != nil
}

func (a *Account) UpdateCredential(provider, credentialID string, jsonData []byte) {
	for i, credential := range a.Credentials[provider] {
		if credential.ID == credentialID {
			a.Credentials[provider][i] = Credential{
				ID:       credentialID,
				Provider: provider,
				Data:     jsonData,
			}
			break
		}
	}
}

func (a *Account) GetCredential(provider, credentialID string) *Credential {
	for _, credential := range a.Credentials[provider] {
		if credential.ID == credentialID {
			return &credential
		}
	}
	return nil
}

func GetAccount(ctx context.Context, id identifier.Identifier) (*Account, errors.E) { //nolint:revive
	accountsMu.RLock()
	defer accountsMu.RUnlock()

	data, ok := accounts[id]
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

func GetAccountByCredential(ctx context.Context, provider, credentialID string) (*Account, errors.E) {
	accountsMu.RLock()
	defer accountsMu.RUnlock()

	for id := range accounts {
		account, errE := GetAccount(ctx, id)
		if errE != nil {
			return nil, errE
		}

		if account.HasCredential(provider, credentialID) {
			return account, nil
		}
	}

	return nil, errors.WithDetails(ErrAccountNotFound, "provider", provider, "credentialID", credentialID)
}

func SetAccount(ctx context.Context, account *Account) errors.E { //nolint:revive
	data, errE := x.MarshalWithoutEscapeHTML(account)
	if errE != nil {
		errors.Details(errE)["id"] = account.ID
		return errE
	}

	accountsMu.Lock()
	defer accountsMu.Unlock()

	accounts[account.ID] = data
	return nil
}
