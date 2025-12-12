package charon

import (
	"bytes"
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
	"github.com/rs/zerolog"
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
	ErrorCodeAlreadyPresent               ErrorCode = "alreadyPresent"
	ErrorCodeCredentialDisplayNameInUse   ErrorCode = "credentialDisplayNameInUse"   //nolint:gosec
	ErrorCodeCredentialDisplayNameMissing ErrorCode = "credentialDisplayNameMissing" //nolint:gosec
)

const credentialAddSessionExpiration = time.Hour * 24

var (
	credentialSessions   = make(map[identifier.Identifier]json.RawMessage) //nolint:gochecknoglobals
	credentialSessionsMu sync.RWMutex                                      //nolint:gochecknoglobals
)

// CredentialPublic represents public information about a credential.
type CredentialPublic struct {
	// ID is a public-facing ID used to identify the credential in public API.
	ID identifier.Identifier `json:"id"`
	// Provider is the internal provider type name or the name of the third party provider.
	Provider Provider `json:"provider"`
	// DisplayName is a user facing string, initially set automatically. For username/email it equals
	// the original (normalized but not mapped) credential value itself. Otherwise, user can rename it.
	// Unique per account per provider.
	DisplayName string `json:"displayName"`
	// Verified bool is relevant for e-mail addresses, otherwise false.
	Verified bool `json:"verified,omitempty"`
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

// CredentialAddEmailRequest represents the request body for the CredentialAddEmail handler.
type CredentialAddEmailRequest struct {
	Email string `json:"email"`
}

// CredentialAddUsernameRequest represents the request body for the CredentialAddUsername handler.
type CredentialAddUsernameRequest struct {
	Username string `json:"username"`
}

// CredentialAddResponse represents the response for credential addition operations.
type CredentialAddResponse struct {
	SessionID    *identifier.Identifier    `json:"sessionId,omitempty"`
	CredentialID *identifier.Identifier    `json:"credentialId,omitempty"`
	Passkey      *AuthFlowResponsePasskey  `json:"passkey,omitempty"`
	Password     *AuthFlowResponsePassword `json:"password,omitempty"`
	Error        ErrorCode                 `json:"error,omitempty"`
}

// CredentialAddCredentialStartRequest represents the request body for the CredentialAddPasswordStartPost and
// CredentialAddPasskeyStartPost.
type CredentialAddCredentialStartRequest struct {
	DisplayName string `json:"displayName"`
}

// CredentialRenameRequest represents the request body for the CredentialRename handler.
type CredentialRenameRequest struct {
	DisplayName string `json:"displayName"`
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
	ID          identifier.Identifier
	CreatedAt   time.Time
	Passkey     *webauthn.SessionData
	Password    *flowPassword
	DisplayName string
}

// Expired returns true if the credential add session has expired.
func (s credentialAddSession) Expired() bool {
	return time.Now().After(s.CreatedAt.Add(credentialAddSessionExpiration))
}

// CredentialResponse represents the response body for credential update operations.
type CredentialResponse struct {
	Error   ErrorCode `json:"error,omitempty"`
	Success bool      `json:"success,omitempty"`

	// Signal is omitted for non-passkey providers or on an error.
	Signal *CredentialSignalData `json:"signal,omitempty"`
}

// CredentialSignalData represents the payload for WebAuthn credential signalCurrentUserDetails - client-side renaming.
type CredentialSignalData struct {
	RPID        string `json:"rpId"`
	UserID      []byte `json:"userId"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// This function does not check for duplicates. Duplicate checking
// should be done by the caller before calling this function.
func (s *Service) addCredentialToAccount(
	ctx context.Context, account *Account, providerKey Provider, providerID string, jsonData json.RawMessage, displayName string, credentialID *identifier.Identifier,
) (identifier.Identifier, errors.E) {
	var id identifier.Identifier
	if credentialID != nil {
		id = *credentialID
	} else {
		id = identifier.New()
	}

	newCredential := Credential{
		CredentialPublic: CredentialPublic{
			ID:          id,
			Provider:    providerKey,
			DisplayName: displayName,
			// Verified is set to false for all providers, including e-mail. E-mail verification is a separate procedure.
			Verified: false,
		},
		ProviderID: providerID,
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

	var result []CredentialRef
	for _, credentials := range account.Credentials {
		for _, credential := range credentials {
			// Code provider credentials are never exposed over the API.
			if credential.Provider == ProviderCode {
				continue
			}
			result = append(result, credential.Ref())
		}
	}

	slices.SortFunc(result, credentialRefCmp)
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
		for _, credential := range credentials {
			// Code provider credentials are never exposed over the API.
			if credential.Provider == ProviderCode {
				continue
			}
			if credential.ID == credentialID {
				s.WriteJSON(w, req, credential.CredentialPublic, nil)
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

	var request CredentialAddEmailRequest
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

	jsonData, errE := x.MarshalWithoutEscapeHTML(emailCredential{})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// We store not-mapped e-mail address as a display name.
	credentialID, errE := s.addCredentialToAccount(ctx, account, ProviderEmail, mappedEmail, jsonData, preservedEmail, nil)
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

	var request CredentialAddUsernameRequest
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

	jsonData, errE := x.MarshalWithoutEscapeHTML(usernameCredential{})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// We store not-mapped username as a display name.
	credentialID, errE := s.addCredentialToAccount(ctx, account, ProviderUsername, mappedUsername, jsonData, preservedUsername, nil)
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

	var request CredentialAddCredentialStartRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	displayName := strings.TrimSpace(request.DisplayName)
	if displayName == "" {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialDisplayNameMissing,
		}, nil)
		return
	}

	accountID := mustGetAccountID(ctx)
	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// Check if passwords display name is already in use on this account.
	// TODO: This is not race safe, needs improvement once we have storage that supports transactions.
	hasDisplayName := account.HasCredentialDisplayName(ProviderPassword, displayName)
	if hasDisplayName {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialDisplayNameInUse,
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
		Passkey:     nil,
		CreatedAt:   time.Now(),
		DisplayName: displayName,
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
	hasDisplayName := account.HasCredentialDisplayName(ProviderPassword, cas.DisplayName)
	if hasDisplayName {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialDisplayNameInUse,
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
		Hash: hashedPassword,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	credentialID, errE := s.addCredentialToAccount(ctx, account, ProviderPassword, "", jsonData, cas.DisplayName, nil)
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

	var request CredentialAddCredentialStartRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	displayName := strings.TrimSpace(request.DisplayName)
	if displayName == "" {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialDisplayNameMissing,
		}, nil)
		return
	}

	accountID := mustGetAccountID(ctx)
	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// Check if passkeys display name is already in use on this account.
	// TODO: This is not race safe, needs improvement once we have storage that supports transactions.
	hasDisplayName := account.HasCredentialDisplayName(ProviderPasskey, displayName)
	if hasDisplayName {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialDisplayNameInUse,
		}, nil)
		return
	}

	userID := identifier.New()
	options, sessionData, errE := beginPasskeyRegistration(s.passkeyProvider(), userID, displayName)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	session := credentialAddSession{
		ID:          identifier.New(),
		Password:    nil,
		Passkey:     sessionData,
		CreatedAt:   time.Now(),
		DisplayName: displayName,
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

	credential, providerID, errE := s.completePasskeyRegistration(request.CreateResponse, cas.DisplayName, cas.Passkey)
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
	hasDisplayName := account.HasCredentialDisplayName(ProviderPasskey, cas.DisplayName)
	if hasDisplayName {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    nil,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialDisplayNameInUse,
		}, nil)
		return
	}

	// We store user ID as credential ID for passkey provider.
	credentialID, errE := s.addCredentialToAccount(ctx, account, ProviderPasskey, providerID, jsonData, cas.DisplayName, &credential.userID)
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

	s.WriteJSON(w, req, CredentialResponse{
		Error:   "",
		Success: true,
		Signal:  nil,
	}, nil)
}

// CredentialRenamePost is the API handler for updating credentials displayName, POST request.
func (s *Service) CredentialRenamePost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	var request CredentialRenameRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	requestDisplayName := strings.TrimSpace(request.DisplayName)
	if requestDisplayName == "" {
		s.WriteJSON(w, req, CredentialResponse{
			Error:   ErrorCodeCredentialDisplayNameMissing,
			Success: false,
			Signal:  nil,
		}, nil)
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

	var foundProvider Provider
	foundIndex := -1

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

	if foundProvider == ProviderEmail || foundProvider == ProviderUsername || foundProvider == ProviderCode {
		// We do not allow changing display names of e-mail or username credentials.
		// We store not-mapped e-mail address or username as a display name.
		// Code provider credentials are never exposed over the API.
		errE = errors.New("invalid credential type")
		errors.Details(errE)["provider"] = foundProvider
		errors.Details(errE)["id"] = credentialID
		s.BadRequestWithError(w, req, errE)
		return
	}

	// Checking that the display name is not already in use by another credential for this provider.
	for i, credential := range account.Credentials[foundProvider] {
		if credential.DisplayName == requestDisplayName {
			if i == foundIndex {
				// The display name is already in use by this credential.
				// Nothing to do.
				s.WriteJSON(w, req, CredentialResponse{
					Error:   "",
					Success: true,
					Signal:  nil,
				}, nil)
				return
			}
			s.WriteJSON(w, req, CredentialResponse{
				Error:   ErrorCodeCredentialDisplayNameInUse,
				Success: false,
				Signal:  nil,
			}, nil)
			return
		}
	}

	account.Credentials[foundProvider][foundIndex].DisplayName = requestDisplayName

	errE = s.setAccount(ctx, account)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	var signalData *CredentialSignalData
	if foundProvider == ProviderPasskey {
		signalData, errE = s.getPasskeySignalData(account.Credentials[foundProvider][foundIndex], requestDisplayName)
		// This is an internal server error, but dashboard rename was successful, so we log and continue.
		if errE != nil {
			zerolog.Ctx(ctx).Warn().Err(errE).Msg("failed to prepare passkey signal data")
		}
	}

	s.WriteJSON(w, req, CredentialResponse{
		Error:   "",
		Success: true,
		Signal:  signalData,
	}, nil)
}
