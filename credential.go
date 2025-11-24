package charon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/go-webauthn/webauthn/webauthn"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

// Credential addition error codes.
const (
	// ErrorCodeCredentialInUse means credential (username) is in use by another account.
	ErrorCodeCredentialInUse ErrorCode = "credentialInUse" //nolint:gosec
	// ErrorCodeAlreadyPresent AlreadyPresent means credential (email, username, password) is already on this account.
	ErrorCodeAlreadyPresent         ErrorCode = "alreadyPresent"
	ErrorCodeCredentialLabelInUse   ErrorCode = "credentialLabelInUse"
	ErrorCodeCredentialLabelMissing ErrorCode = "credentialLabelMissing" //nolint:gosec
)

const credentialAddSessionExpiration = time.Hour * 24

var (
	credentialSessions   = make(map[identifier.Identifier]json.RawMessage) //nolint:gochecknoglobals
	credentialSessionsMu sync.RWMutex                                      //nolint:gochecknoglobals
)

// CredentialInfo represents public information about a credential.
type CredentialInfo struct {
	ID          identifier.Identifier `json:"id"`
	Provider    Provider              `json:"provider"`
	DisplayName string                `json:"displayName,omitempty"`
	Verified    bool                  `json:"verified,omitempty"`
}

// CredentialInfoRef represents a reference to a credential.
type CredentialInfoRef struct {
	ID identifier.Identifier `json:"id"`
}

// CredentialAddResponse represents the response for credential addition operations.
type CredentialAddResponse struct {
	SessionID    *identifier.Identifier    `json:"sessionId,omitempty"`
	CredentialID *identifier.Identifier    `json:"credentialId,omitempty"`
	Passkey      *AuthFlowResponsePasskey  `json:"passkey,omitempty"`
	Password     *AuthFlowResponsePassword `json:"password,omitempty"`
	Error        ErrorCode                 `json:"error,omitempty"`
}

// CredentialAddCredentialWithLabelStartRequest represents the request body for the CredentialAddPasswordStartPost and
// CredentialAddPasskeyStartPost.
type CredentialAddCredentialWithLabelStartRequest struct {
	Label string `json:"label"`
}

// CredentialAddPasswordCompleteRequest represents the request body for the CredentialAddPasswordCompletePost handler.
type CredentialAddPasswordCompleteRequest struct {
	AuthFlowPasswordCompleteRequest

	SessionID identifier.Identifier `json:"sessionId"`
}

// CredentialAddPasskeyCompleteRequest represents the request body for the CredentialAddPasskeyCompletePost handler.
type CredentialAddPasskeyCompleteRequest struct {
	AuthFlowPasskeyCreateCompleteRequest

	SessionID identifier.Identifier `json:"sessionId"`
}

type credentialAddSession struct {
	ID        identifier.Identifier
	CreatedAt time.Time
	Passkey   *webauthn.SessionData
	Password  *flowPassword
	Label     string
}

// Expired returns true if the credential add session has expired.
func (s credentialAddSession) Expired() bool {
	return time.Now().After(s.CreatedAt.Add(credentialAddSessionExpiration))
}

// This function does not check for duplicates. Duplicate checking
// should be done by the caller before calling this function.
func (s *Service) addCredentialToAccount(
	ctx context.Context, account *Account, providerKey Provider, providerID string, jsonData json.RawMessage,
) (identifier.Identifier, errors.E) {
	newCredential := Credential{
		ID:         identifier.New(),
		ProviderID: providerID,
		Provider:   providerKey,
		Data:       jsonData,
	}

	if account.Credentials == nil {
		account.Credentials = make(map[Provider][]Credential)
	}

	account.Credentials[providerKey] = append(account.Credentials[providerKey], newCredential)

	errE := s.setAccount(ctx, account)
	if errE != nil {
		return identifier.Identifier{}, errE
	}

	return newCredential.ID, nil
}

func storeCredentialSession(session credentialAddSession) errors.E {
	sessionData, errE := x.MarshalWithoutEscapeHTML(session)
	if errE != nil {
		return errE
	}

	credentialSessionsMu.Lock()
	defer credentialSessionsMu.Unlock()
	credentialSessions[session.ID] = sessionData

	return nil
}

func getAndDeleteCredentialSession(sessionID identifier.Identifier) (*credentialAddSession, errors.E) {
	credentialSessionsMu.Lock()
	defer credentialSessionsMu.Unlock()

	sessionData, ok := credentialSessions[sessionID]
	delete(credentialSessions, sessionID)

	if !ok {
		return nil, errors.WithDetails(errSessionNotFound, "id", sessionID)
	}

	var cas credentialAddSession
	errE := x.UnmarshalWithoutUnknownFields(sessionData, &cas)
	if errE != nil {
		errors.Details(errE)["id"] = sessionID
		return nil, errE
	}

	if cas.Expired() {
		return nil, errors.WithDetails(errSessionNotFound, "id", sessionID)
	}

	return &cas, nil
}

// CredentialList is the frontend handler for getting credentials.
func (s *Service) CredentialList(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

// CredentialListGet is the API handler for listing credentials, GET request.
func (s *Service) CredentialListGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	accountID := mustGetAccountID(ctx)
	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	var result []CredentialInfoRef
	for _, credentials := range account.Credentials {
		for _, credential := range credentials {
			credentialInfo, errE := credential.ToCredentialInfo()
			if errE != nil {
				continue
			}
			result = append(result, CredentialInfoRef{ID: credentialInfo.ID})
		}
	}

	s.WriteJSON(w, req, result, nil)
}

// CredentialGet is the frontend handler for getting the credential.
func (s *Service) CredentialGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

// CredentialGetGet is the API handler for getting the credential, GET request.
func (s *Service) CredentialGetGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	accountID := mustGetAccountID(ctx)
	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	credentialID, errE := identifier.MaybeString(params["id"])
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	for _, credentials := range account.Credentials {
		for _, c := range credentials {
			if c.ID == credentialID {
				info, errE := c.ToCredentialInfo()
				if errE != nil {
					s.InternalServerErrorWithError(w, req, errE)
					return
				}
				s.WriteJSON(w, req, info, nil)
				return
			}
		}
	}

	s.NotFound(w, req)
}

// CredentialAdd is the frontend handler for adding a credential to account.
func (s *Service) CredentialAdd(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

// CredentialAddEmailPost is the API handler for adding an e-mail credential to account, POST request.
func (s *Service) CredentialAddEmailPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	var request emailCredential
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	preservedEmail, mappedEmail, errE := validateEmailOrUsername(request.Email, emailOrUsernameCheckEmail)
	if errE != nil {
		var ve *validationError
		if errors.As(errE, &ve) {
			s.WriteJSON(w, req, CredentialAddResponse{
				SessionID:    nil,
				CredentialID: nil,
				Passkey:      nil,
				Password:     nil,
				Error:        ve.Code,
			}, nil)
			return
		}
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	accountID := mustGetAccountID(ctx)
	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// TODO: This is not race safe, needs improvement once we have storage that supports transactions.
	if account.HasCredential(ProviderEmail, mappedEmail) {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeAlreadyPresent,
		}, nil)
		return
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(emailCredential{Email: preservedEmail, Verified: false})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	credentialID, errE := s.addCredentialToAccount(ctx, account, ProviderEmail, mappedEmail, jsonData)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, CredentialAddResponse{
		SessionID:    nil,
		CredentialID: &credentialID,
		Passkey:      nil,
		Password:     nil,
		Error:        "",
	}, nil)
}

// CredentialAddUsernamePost is the API handler for adding a username credential to account, POST request.
func (s *Service) CredentialAddUsernamePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	request := usernameCredential{}
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	preservedUsername, mappedUsername, errE := validateEmailOrUsername(request.Username, emailOrUsernameCheckUsername)
	if errE != nil {
		var ve *validationError
		if errors.As(errE, &ve) {
			s.WriteJSON(w, req, CredentialAddResponse{
				SessionID:    nil,
				CredentialID: nil,
				Passkey:      nil,
				Password:     nil,
				Error:        ve.Code,
			}, nil)
			return
		}
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	accountID := mustGetAccountID(ctx)
	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if account.HasCredential(ProviderUsername, mappedUsername) {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeAlreadyPresent,
		}, nil)
		return
	}

	// TODO: This is not race safe, needs improvement once we have storage that supports transactions.
	existingAccount, errE := s.getAccountByCredential(ctx, ProviderUsername, mappedUsername)
	if errE == nil && existingAccount.ID != accountID {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialInUse,
		}, nil)
		return
	} else if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(usernameCredential{Username: preservedUsername})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	credentialID, errE := s.addCredentialToAccount(ctx, account, ProviderUsername, mappedUsername, jsonData)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	s.WriteJSON(w, req, CredentialAddResponse{
		SessionID:    nil,
		CredentialID: &credentialID,
		Passkey:      nil,
		Password:     nil,
		Error:        "",
	}, nil)
}

// CredentialAddPasswordStartPost is the API handler to start the password credential step, POST request.
func (s *Service) CredentialAddPasswordStartPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	var request CredentialAddCredentialWithLabelStartRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	requestLabel := strings.TrimSpace(request.Label)
	if requestLabel == "" {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialLabelMissing,
		}, nil)
		return
	}

	accountID := mustGetAccountID(ctx)
	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// Check if password label is already in use on this account.
	// TODO: This is not race safe, needs improvement once we have storage that supports transactions.
	hasLabel, errE := account.HasCredentialLabel(ProviderPassword, requestLabel)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	if hasLabel {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialLabelInUse,
		}, nil)
		return
	}

	privateKeyBytes, publicKeyBytes, nonce, overhead, errE := generatePasswordEncryptionKeys()
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	session := credentialAddSession{
		ID: identifier.New(),
		Password: &flowPassword{
			PrivateKey: privateKeyBytes,
			Nonce:      nonce,
		},
		Passkey:   nil,
		CreatedAt: time.Now(),
		Label:     requestLabel,
	}

	errE = storeCredentialSession(session)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	response := CredentialAddResponse{
		SessionID:    &session.ID,
		CredentialID: nil,
		Passkey:      nil,
		Password:     newPasswordEncryptionResponse(publicKeyBytes, nonce, overhead),
		Error:        "",
	}

	s.WriteJSON(w, req, response, nil)
}

// CredentialAddPasswordCompletePost is the API handler to complete the password credential step, POST request.
func (s *Service) CredentialAddPasswordCompletePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	var request CredentialAddPasswordCompleteRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	cas, errE := getAndDeleteCredentialSession(request.SessionID)
	if errE != nil {
		if errors.Is(errSessionNotFound, errE) {
			s.BadRequestWithError(w, req, errE)
			return
		}
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if cas.Password == nil {
		s.BadRequestWithError(w, req, errors.New("invalid session type"))
		return
	}

	plainPassword, errE := decryptEncryptedPassword(
		cas.Password.PrivateKey, request.PublicKey, cas.Password.Nonce, request.Password,
	)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	plainPassword, errE = normalizePassword(plainPassword)
	if errE != nil {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeInvalidPassword,
		}, nil)
		return
	}

	if len(plainPassword) < passwordMinLength {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeShortPassword,
		}, nil)
		return
	}

	hashedPassword, err := argon2id.CreateHash(plainPassword, &argon2idParams)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	accountID := mustGetAccountID(ctx)
	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// TODO: This is not race safe, needs improvement once we have storage that supports transactions.
	hasLabel, errE := account.HasCredentialLabel(ProviderPassword, cas.Label)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	if hasLabel {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialLabelInUse,
		}, nil)
		return
	}

	// TODO: This is not race safe, needs improvement once we have storage that supports transactions.
	for _, credential := range account.Credentials[ProviderPassword] {
		var pc passwordCredential
		errE = x.Unmarshal(credential.Data, &pc)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		// Check if password is already in use on this account.
		match, err := argon2id.ComparePasswordAndHash(plainPassword, pc.Hash)
		if err != nil {
			s.InternalServerErrorWithError(w, req, errors.WithStack(err))
			return
		}
		if match {
			// TODO: If options are different, migrate the password to new options.
			s.WriteJSON(w, req, CredentialAddResponse{
				SessionID:    nil,
				CredentialID: nil,
				Passkey:      nil,
				Password:     nil,
				Error:        ErrorCodeAlreadyPresent,
			}, nil)
			return
		}
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(passwordCredential{
		Hash:  hashedPassword,
		Label: cas.Label,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	providerID := ""
	credentialID, errE := s.addCredentialToAccount(ctx, account, ProviderPassword, providerID, jsonData)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, CredentialAddResponse{
		SessionID:    nil,
		CredentialID: &credentialID,
		Passkey:      nil,
		Password:     nil,
		Error:        "",
	}, nil)
}

// CredentialAddPasskeyStartPost is the API handler to start the passkey credential step, POST request.
func (s *Service) CredentialAddPasskeyStartPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	var request CredentialAddCredentialWithLabelStartRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	requestLabel := strings.TrimSpace(request.Label)
	if requestLabel == "" {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialLabelMissing,
		}, nil)
		return
	}

	accountID := mustGetAccountID(ctx)
	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// Check if passkey label is already in use on this account.
	// TODO: This is not race safe, needs improvement once we have storage that supports transactions.
	hasLabel, errE := account.HasCredentialLabel(ProviderPasskey, requestLabel)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	if hasLabel {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialLabelInUse,
		}, nil)
		return
	}

	userID := identifier.New()
	options, sessionData, errE := beginPasskeyRegistration(s.passkeyProvider(), userID, requestLabel)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	session := credentialAddSession{
		ID:        identifier.New(),
		Password:  nil,
		Passkey:   sessionData,
		CreatedAt: time.Now(),
		Label:     requestLabel,
	}

	errE = storeCredentialSession(session)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, CredentialAddResponse{
		SessionID:    &session.ID,
		CredentialID: nil,
		Passkey: &AuthFlowResponsePasskey{
			CreateOptions: options,
			GetOptions:    nil,
		},
		Password: nil,
		Error:    "",
	}, nil)
}

// CredentialAddPasskeyCompletePost is the API handler to complete the passkey credential step, POST request.
func (s *Service) CredentialAddPasskeyCompletePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	var request CredentialAddPasskeyCompleteRequest
	errE := x.DecodeJSON(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	cas, errE := getAndDeleteCredentialSession(request.SessionID)
	if errE != nil {
		if errors.Is(errSessionNotFound, errE) {
			s.BadRequestWithError(w, req, errE)
			return
		}
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if cas.Passkey == nil {
		s.BadRequestWithError(w, req, errors.New("invalid session type"))
		return
	}

	credential, providerID, errE := s.completePasskeyRegistration(request.CreateResponse, cas.Label, cas.Passkey)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(credential)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	accountID := mustGetAccountID(ctx)
	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// TODO: This is not race safe, needs improvement once we have storage that supports transactions.
	hasLabel, errE := account.HasCredentialLabel(ProviderPasskey, cas.Label)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	if hasLabel {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialLabelInUse,
		}, nil)
		return
	}

	credentialID, errE := s.addCredentialToAccount(ctx, account, ProviderPasskey, providerID, jsonData)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, CredentialAddResponse{
		SessionID:    nil,
		CredentialID: &credentialID,
		Passkey:      nil,
		Password:     nil,
		Error:        "",
	}, nil)
}

// CredentialRemovePost is the API handler for removing credential, POST request.
func (s *Service) CredentialRemovePost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	var ea emptyRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &ea)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	accountID := mustGetAccountID(ctx)
	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	var foundProvider Provider
	foundIndex := -1

	credentialID, errE := identifier.MaybeString(params["id"])
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

FoundCredential:
	for provider, credentials := range account.Credentials {
		for i, credential := range credentials {
			if credential.ID == credentialID {
				foundProvider = provider
				foundIndex = i
				break FoundCredential
			}
		}
	}

	if foundIndex == -1 {
		s.NotFound(w, req)
		return
	}

	account.Credentials[foundProvider] = slices.Delete(account.Credentials[foundProvider], foundIndex, foundIndex+1)

	if len(account.Credentials[foundProvider]) == 0 {
		delete(account.Credentials, foundProvider)
	}

	errE = s.setAccount(ctx, account)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, []byte(`{"success":true}`), nil)
}
