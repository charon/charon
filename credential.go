package charon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/alexedwards/argon2id"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

// Credential addition error codes.
const (
	// ErrorCodeCredentialInUse means credential (username, verified email) is in use by another account.
	ErrorCodeCredentialInUse ErrorCode = "credentialInUse" //nolint:gosec
	// ErrorCodeAlreadyPresent AlreadyPresent means credential (email, username, password) is already on this account.
	ErrorCodeAlreadyPresent               ErrorCode = "alreadyPresent"
	ErrorCodeCredentialDisplayNameInUse   ErrorCode = "credentialDisplayNameInUse"   //nolint:gosec
	ErrorCodeCredentialDisplayNameMissing ErrorCode = "credentialDisplayNameMissing" //nolint:gosec
)

const credentialAddSessionExpiration = flowExpiration

var (
	credentialSessions   = map[identifier.Identifier]json.RawMessage{} //nolint:gochecknoglobals
	credentialSessionsMu sync.RWMutex                                  //nolint:gochecknoglobals
)

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
	Signal *SignalPasskey `json:"signal,omitempty"`
}

// SignalPasskey contains WebAuthn Signal API data for passkey credentials.
type SignalPasskey struct {
	// Update is used for signalCurrentUserDetails - client-side renaming.
	Update *SignalCurrentUserDetails `json:"update,omitempty"`
	// Remove is used for signalUnknownCredential - client-side removal.
	Remove *SignalUnknownCredential `json:"remove,omitempty"`
}

// SignalCurrentUserDetails represents the payload for WebAuthn credential signalCurrentUserDetails - client-side renaming.
type SignalCurrentUserDetails struct {
	RPID        string                    `json:"rpId"`
	UserID      protocol.URLEncodedBase64 `json:"userId"`
	Name        string                    `json:"name"`
	DisplayName string                    `json:"displayName"`
}

// SignalUnknownCredential represents the payload for WebAuthn credential signalUnknownCredential - client-side removal.
type SignalUnknownCredential struct {
	RPID         string                    `json:"rpId"`
	CredentialID protocol.URLEncodedBase64 `json:"credentialId"`
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
			Confirmed: false,
		},
		ProviderID: providerID,
		Data:       jsonData,
	}

	if account.Credentials == nil {
		account.Credentials = map[Provider][]Credential{}
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

// CredentialListGet is the frontend handler for getting credentials.
func (s *Service) CredentialListGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

// CredentialListGetAPI is the API handler for listing credentials, GET request.
func (s *Service) CredentialListGetAPI(w http.ResponseWriter, req *http.Request, _ waf.Params) {
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

// CredentialGetGetAPI is the API handler for getting the credential, GET request.
func (s *Service) CredentialGetGetAPI(w http.ResponseWriter, req *http.Request, params waf.Params) {
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

// CredentialAddGet is the frontend handler for adding a credential to account.
func (s *Service) CredentialAddGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

// CredentialAddEmailPostAPI is the API handler for adding an e-mail credential to account, POST request.
func (s *Service) CredentialAddEmailPostAPI(w http.ResponseWriter, req *http.Request, _ waf.Params) {
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

// CredentialAddUsernamePostAPI is the API handler for adding a username credential to account, POST request.
func (s *Service) CredentialAddUsernamePostAPI(w http.ResponseWriter, req *http.Request, _ waf.Params) {
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

// CredentialAddPasswordStartPostAPI is the API handler to start the password credential step, POST request.
func (s *Service) CredentialAddPasswordStartPostAPI(w http.ResponseWriter, req *http.Request, _ waf.Params) {
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
	if account.HasCredentialDisplayName(ProviderPassword, displayName) {
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

// CredentialAddPasswordCompletePostAPI is the API handler to complete the password credential step, POST request.
func (s *Service) CredentialAddPasswordCompletePostAPI(w http.ResponseWriter, req *http.Request, _ waf.Params) {
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
	if account.HasCredentialDisplayName(ProviderPassword, cas.DisplayName) {
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

// CredentialAddPasskeyStartPostAPI is the API handler to start the passkey credential step, POST request.
func (s *Service) CredentialAddPasskeyStartPostAPI(w http.ResponseWriter, req *http.Request, _ waf.Params) {
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
	if account.HasCredentialDisplayName(ProviderPasskey, displayName) {
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
	options, sessionData, errE := beginPasskeyRegistration(s.passkeyProvider(), userID, displayName, s.title)
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

// CredentialAddPasskeyCompletePostAPI is the API handler to complete the passkey credential step, POST request.
func (s *Service) CredentialAddPasskeyCompletePostAPI(w http.ResponseWriter, req *http.Request, _ waf.Params) {
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

	credential, providerID, errE := s.completePasskeyRegistration(request.CreateResponse, cas.DisplayName, s.title, cas.Passkey)
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
	if account.HasCredentialDisplayName(ProviderPasskey, cas.DisplayName) {
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

// CredentialRemovePostAPI is the API handler for removing credential, POST request.
func (s *Service) CredentialRemovePostAPI(w http.ResponseWriter, req *http.Request, params waf.Params) {
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

	credentialID, errE := identifier.MaybeString(params["id"])
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	_, foundProvider, foundIndex := account.getCredentialByID(credentialID)
	if foundIndex == -1 {
		s.NotFound(w, req)
		return
	}

	account.Credentials[foundProvider] = slices.Delete(account.Credentials[foundProvider], foundIndex, foundIndex+1)

	if len(account.Credentials[foundProvider]) == 0 {
		delete(account.Credentials, foundProvider)
	}

	var signalUnknown *SignalUnknownCredential
	if foundProvider == ProviderPasskey {
		credentialIDBytes, err := base64.RawURLEncoding.DecodeString(foundProviderID)
		if err != nil {
			s.InternalServerErrorWithError(w, req, errors.WithStack(err))
			return
		}
		signalUnknown = s.getPasskeySignalUnknownCredentialData(credentialIDBytes)
	}

	errE = s.setAccount(ctx, account)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, CredentialResponse{
		Error:   "",
		Success: true,
		Signal:  newCredentialSignalResponse(nil, signalUnknown),
	}, nil)
}

// CredentialRenamePostAPI is the API handler for updating credentials displayName, POST request.
func (s *Service) CredentialRenamePostAPI(w http.ResponseWriter, req *http.Request, params waf.Params) {
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

	_, foundProvider, foundIndex := account.getCredentialByID(credentialID)

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

	var signalUpdate *SignalCurrentUserDetails
	if foundProvider == ProviderPasskey {
		signalUpdate, errE = s.getPasskeySignalCurrentUserDetailsData(account.Credentials[foundProvider][foundIndex], requestDisplayName, s.title)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
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
					Signal:  newCredentialSignalResponse(signalUpdate, nil),
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

	s.WriteJSON(w, req, CredentialResponse{
		Error:   "",
		Success: true,
		Signal:  newCredentialSignalResponse(signalUpdate, nil),
	}, nil)
}

func newCredentialSignalResponse(update *SignalCurrentUserDetails, remove *SignalUnknownCredential) *SignalPasskey {
	if update == nil && remove == nil {
		return nil
	}
	return &SignalPasskey{Update: update, Remove: remove}
}

// ErrorCode values.
const (
	ErrorCodeVerificationFailed ErrorCode = "verificationFailed"
)

const (
	credentialVerifyCodeExpiration = 10 * time.Minute
	maxVerifyAttempts              = 5
)

type codeCredential struct {
	Code          string    `json:"code"`
	CreatedAt     time.Time `json:"createdAt"`
	WrongAttempts int       `json:"wrongAttempts"`
}

func (c codeCredential) Expired() bool {
	return time.Now().After(c.CreatedAt.Add(credentialVerifyCodeExpiration))
}

func (c codeCredential) MaxAttemptsReached() bool {
	return c.WrongAttempts >= maxVerifyAttempts
}

// AccountVerifiedEmailsResponse represents the response for getting verified emails.
type AccountVerifiedEmailsResponse struct {
	Emails        []string `json:"emails"`
	HasUnverified bool     `json:"hasUnverified"`
}

// CredentialVerifyEmailCompleteRequest represents the request to complete email verification.
type CredentialVerifyEmailCompleteRequest struct {
	Code string `json:"code"`
}

// cleanupCodeCredentials removes expired or max-attempts-reached code credentials.
// Returns true if any codes remain for that credential.
func (a *Account) cleanupCodeCredentials(emailCredentialID string) (bool, errors.E) {
	if a.Credentials[ProviderCode] == nil {
		return false, nil
	}

	hasRemaining := false
	filtered := a.Credentials[ProviderCode][:0]
	for _, credential := range a.Credentials[ProviderCode] {
		var data codeCredential
		errE := x.UnmarshalWithoutUnknownFields(credential.Data, &data)
		if errE != nil {
			errors.Details(errE)["id"] = credential.ID
			errors.Details(errE)["providerID"] = credential.ProviderID
			return false, errE
		}
		// Cleanup all codeCredentials, not only for current emailCredentialID.
		if data.Expired() || data.MaxAttemptsReached() {
			continue
		}
		filtered = append(filtered, credential)
		if credential.ProviderID == emailCredentialID {
			hasRemaining = true
		}
	}
	a.Credentials[ProviderCode] = filtered

	if len(a.Credentials[ProviderCode]) == 0 {
		delete(a.Credentials, ProviderCode)
	}

	return hasRemaining, nil
}

// removeCodeCredentials removes all code credentials for the given email credential ID.
func (a *Account) removeCodeCredentials(emailCredentialID string) {
	if a.Credentials[ProviderCode] == nil {
		return
	}

	filtered := a.Credentials[ProviderCode][:0]
	for _, credential := range a.Credentials[ProviderCode] {
		if credential.ProviderID != emailCredentialID {
			filtered = append(filtered, credential)
		}
	}
	a.Credentials[ProviderCode] = filtered

	if len(a.Credentials[ProviderCode]) == 0 {
		delete(a.Credentials, ProviderCode)
	}
}

// findCodeCredential tries to find a code credential matching the given email credential ID and code.
func (a *Account) findCodeCredential(emailCredentialID string, code string) (*Credential, errors.E) {
	for _, credential := range a.Credentials[ProviderCode] {
		var data codeCredential
		errE := x.UnmarshalWithoutUnknownFields(credential.Data, &data)
		if errE != nil {
			errors.Details(errE)["id"] = credential.ID
			errors.Details(errE)["providerID"] = credential.ProviderID
			return nil, errE
		}
		if credential.ProviderID == emailCredentialID && data.Code == code {
			return &credential, nil
		}
	}
	// Code credential was not found.
	return nil, nil //nolint:nilnil
}

// incrementCodeCredentialAttempts increments wrong attempts
// on all code credentials for the given email credential ID.
func (a *Account) incrementCodeCredentialAttempts(emailCredentialID string) errors.E {
	for i, credential := range a.Credentials[ProviderCode] {
		if credential.ProviderID != emailCredentialID {
			continue
		}

		var data codeCredential
		errE := x.UnmarshalWithoutUnknownFields(credential.Data, &data)
		if errE != nil {
			errors.Details(errE)["id"] = credential.ID
			errors.Details(errE)["providerID"] = credential.ProviderID
			return errE
		}
		data.WrongAttempts++
		jsonData, errE := x.MarshalWithoutEscapeHTML(data)
		if errE != nil {
			errors.Details(errE)["id"] = credential.ID
			errors.Details(errE)["providerID"] = credential.ProviderID
			return errE
		}
		a.Credentials[ProviderCode][i].Data = jsonData
	}
	return nil
}

// CredentialVerifyEmail is the frontend handler for email verification.
func (s *Service) CredentialVerifyEmail(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

// CredentialVerifyEmailPost is the API handler for starting email verification, POST request.
func (s *Service) CredentialVerifyEmailPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	credentialID, errE := identifier.MaybeString(params["id"])
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

	var foundCredential Credential
	foundIndex := -1

FoundCredential:
	for i, credential := range account.Credentials[ProviderEmail] {
		// ProviderCode has the same credentialID as ProviderEmail.
		if credential.ID == credentialID {
			foundCredential = credential
			foundIndex = i
			break FoundCredential
		}
	}

	if foundIndex == -1 {
		s.NotFound(w, req)
		return
	}

	if foundCredential.Confirmed {
		// Nothing to do, already verified.
		s.WriteJSON(w, req, CredentialResponse{
			Error:   "",
			Success: true,
			Signal:  nil,
		}, nil)
		return
	}

	_, errE = account.cleanupCodeCredentials(credentialID.String())
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	code, errE := getRandomCode()
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	codeData := codeCredential{
		Code:          code,
		CreatedAt:     time.Now(),
		WrongAttempts: 0,
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(codeData)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	newCodeCredential := Credential{
		CredentialPublic: CredentialPublic{
			ID:       identifier.New(),
			Provider: ProviderCode,
			// Store e-mail value.
			DisplayName: foundCredential.DisplayName,
			Verified:    false,
		},
		// Store e-mail credentials ID.
		ProviderID: foundCredential.ID.String(),
		Data:       jsonData,
	}

	if account.Credentials == nil {
		account.Credentials = make(map[Provider][]Credential)
	}
	account.Credentials[ProviderCode] = append(account.Credentials[ProviderCode], newCodeCredential)
	errE = s.setAccount(ctx, account)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	path, errE := s.Reverse("CredentialVerifyEmail", waf.Params{"id": credentialID.String()}, nil)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	url := fmt.Sprintf("%s%s#code=%s", s.codeProvider().origin, path, code)

	errE = s.sendMail(ctx, credentialID, []string{foundCredential.DisplayName}, codeProviderSubject, codeProviderTemplateCompiled, map[string]string{
		"code": code,
		"url":  url,
	})
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

// CredentialVerifyEmailCompletePost is the API handler for completing email verification, POST request.
func (s *Service) CredentialVerifyEmailCompletePost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	credentialID, errE := identifier.MaybeString(params["id"])
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	var request CredentialVerifyEmailCompleteRequest
	errE = x.DecodeJSONWithoutUnknownFields(req.Body, &request)
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

	hasRemaining, errE := account.cleanupCodeCredentials(credentialID.String())
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if !hasRemaining {
		errE = s.setAccount(ctx, account)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		s.WriteJSON(w, req, CredentialResponse{
			Error:   ErrorCodeVerificationFailed,
			Success: false,
			Signal:  nil,
		}, nil)
		return
	}

	// We clean the provided code of all whitespace (not just at the beginning and end) before we check it.
	code := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, request.Code)

	credential, errE := account.findCodeCredential(credentialID.String(), code)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	if credential == nil {
		errE = account.incrementCodeCredentialAttempts(credentialID.String())
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		hasRemaining, errE = account.cleanupCodeCredentials(credentialID.String())
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		errE = s.setAccount(ctx, account)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		if !hasRemaining {
			s.WriteJSON(w, req, CredentialResponse{
				Error:   ErrorCodeVerificationFailed,
				Success: false,
				Signal:  nil,
			}, nil)
			return
		}

		s.WriteJSON(w, req, CredentialResponse{
			Error:   ErrorCodeInvalidCode,
			Success: false,
			Signal:  nil,
		}, nil)
		return
	}

	foundCredential, _, foundIndex := account.getCredentialByID(credentialID)
	if foundIndex == -1 {
		s.NotFound(w, req)
		return
	}

	// Verify email in code credential matches the found email credential (defensive check).
	if account.Credentials[ProviderEmail][foundIndex].ID.String() != credential.ProviderID {
		errE := errors.New("email mismatch between code credential and email credential")
		errors.Details(errE)["id"] = credential.ID
		errors.Details(errE)["codeEmail"] = credential.DisplayName
		errors.Details(errE)["credentialEmail"] = account.Credentials[ProviderEmail][foundIndex].DisplayName
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// TODO: This is not race safe, needs improvement once we have storage that supports transactions.
	accountWithVerifiedEmail, errE := s.getAccountByCredential(ctx, ProviderEmail, foundCredential.ProviderID)
	if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if accountWithVerifiedEmail != nil {
		// e-mail is already verified, remove all codeCredentials.
		account.removeCodeCredentials(credentialID.String())
		errE = s.setAccount(ctx, account)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		// e-mail is verified on the same account, no-op.
		if accountWithVerifiedEmail.ID == accountID {
			s.WriteJSON(w, req, CredentialResponse{
				Error:   "",
				Success: true,
				Signal:  nil,
			}, nil)
			return
		}
		// Email is verified on a different account.
		s.WriteJSON(w, req, CredentialResponse{
			// TODO: Offer user to merge accounts.
			Error:   ErrorCodeCredentialInUse,
			Success: false,
			Signal:  nil,
		}, nil)
		return
	}

	account.Credentials[ProviderEmail][foundIndex].Verified = true
	account.removeCodeCredentials(credentialID.String())

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

// CredentialVerifiedEmailsGet is the API handler for getting verified email addresses of the account, GET request.
func (s *Service) CredentialVerifiedEmailsGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
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

	verifiedEmails := account.GetEmailAddresses(true)
	allEmails := account.GetEmailAddresses(false)
	hasUnverified := len(allEmails) > len(verifiedEmails)

	s.WriteJSON(w, req, AccountVerifiedEmailsResponse{
		Emails:        verifiedEmails,
		HasUnverified: hasUnverified,
	}, nil)
}

// getCredentialByID finds a credential by ID across providers, excluding ProviderCode.
func (a *Account) getCredentialByID(credentialID identifier.Identifier) (*Credential, Provider, int) {
	for provider, credentials := range a.Credentials {
		// Skip internal ProviderCode credentials.
		if provider == ProviderCode {
			continue
		}
		for i, credential := range credentials {
			if credential.ID == credentialID {
				return &credentials[i], provider, i
			}
		}
	}

	return nil, "", -1
}
