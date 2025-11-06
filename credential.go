package charon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

// Credential (username) already used by another account.
const ErrorCodeCredentialAlreadyUsed ErrorCode = "credentialAlreadyUsed" //nolint:gosec
const ErrorCodePasskeyBoundToOtherAccount ErrorCode = "passkeyBoundToOtherAccount"

const credentialAddSessionExpiration = time.Hour * 24

var (
	credentialSessions   = make(map[identifier.Identifier]json.RawMessage) //nolint:gochecknoglobals
	credentialSessionsMu sync.RWMutex                                      //nolint:gochecknoglobals
)

// CredentialAddEmailRequest represents data of email credential addition request.
type CredentialAddEmailRequest struct {
	Email string `json:"email"`
}

// CredentialAddUsernameRequest represents data of username credential addition request.
type CredentialAddUsernameRequest struct {
	Username string `json:"username"`
}

// CredentialInfo represents information about a credential.
type CredentialInfo struct {
	ID          identifier.Identifier `json:"id"`
	Provider    Provider              `json:"provider"`
	DisplayName string                `json:"displayName"`
	Label       string                `json:"label,omitempty"`
}

// CredentialInfoRef represents a reference to a credential.
type CredentialInfoRef struct {
	ID identifier.Identifier `json:"id"`
}

// CredentialAddResponse represents the response for credential addition operations.
type CredentialAddResponse struct {
	SessionID    identifier.Identifier     `json:"sessionId"`
	CredentialID *identifier.Identifier    `json:"credentialId,omitempty"`
	Passkey      *AuthFlowResponsePasskey  `json:"passkey,omitempty"`
	Password     *AuthFlowResponsePassword `json:"password,omitempty"`
	Error        ErrorCode                 `json:"error,omitempty"`
}

type credentialAddPasswordCompleteRequest struct {
	AuthFlowPasswordCompleteRequest

	SessionID identifier.Identifier `json:"sessionId"`
	Label     string                `json:"label,omitempty"`
}

type credentialAddPasskeyCompleteRequest struct {
	SessionID      identifier.Identifier               `json:"sessionId"`
	CreateResponse protocol.CredentialCreationResponse `json:"createResponse"`
	Label          string                              `json:"label"`
}

type credentialAddSession struct {
	ID        identifier.Identifier
	Password  *flowPassword
	Passkey   *webauthn.SessionData
	CreatedAt time.Time
}

func (s credentialAddSession) Expired() bool {
	return time.Now().After(s.CreatedAt.Add(credentialAddSessionExpiration))
}

func validateEmail(value string) ErrorCode {
	if len(value) < emailOrUsernameMinLength {
		return ErrorCodeShortEmailOrUsername
	}
	if !strings.Contains(value, "@") {
		return ErrorCodeInvalidEmailOrUsername
	}
	return ""
}

func validateUsername(value string) ErrorCode {
	if strings.Contains(value, "@") {
		return ErrorCodeInvalidEmailOrUsername
	}
	if len(value) < emailOrUsernameMinLength {
		return ErrorCodeShortEmailOrUsername
	}
	return ""
}

func (s *Service) getCredentialInfo(provider Provider, credential Credential) (CredentialInfo, errors.E) {
	var displayName string
	var label string

	switch provider {
	case ProviderEmail:
		var ec emailCredential
		errE := x.Unmarshal(credential.Data, &ec)
		if errE != nil {
			return CredentialInfo{}, errE
		}
		displayName = ec.Email
	case ProviderUsername:
		var uc usernameCredential
		errE := x.Unmarshal(credential.Data, &uc)
		if errE != nil {
			return CredentialInfo{}, errE
		}
		displayName = uc.Username
	case ProviderPassword:
		var pc passwordCredential
		errE := x.Unmarshal(credential.Data, &pc)
		if errE != nil {
			return CredentialInfo{}, errE
		}
		label = pc.Label
	case ProviderPasskey:
		var pkc passkeyCredential
		errE := x.Unmarshal(credential.Data, &pkc)
		if errE != nil {
			return CredentialInfo{}, errE
		}
		label = pkc.Label
	case ProviderCode:
		return CredentialInfo{}, errors.New("code provider should not be returned")
	default:
		providerName := string(provider)
		if p, ok := s.oidcProviders()[provider]; ok {
			providerName = p.Name
		} else if p, ok := s.samlProviders()[provider]; ok {
			providerName = p.Name
		}

		displayName = providerName

		var token map[string]interface{}
		errE := x.Unmarshal(credential.Data, &token)
		if errE == nil {
			email := findFirstString(token, "email", "eMailAddress", "emailAddress", "email_address")
			if email != "" {
				displayName = email
			}
		}
	}

	return CredentialInfo{
		ID:          credential.ID,
		Provider:    provider,
		DisplayName: displayName,
		Label:       label,
	}, nil
}

func (s *Service) addCredentialToAccount(ctx context.Context, accountID identifier.Identifier, providerKey Provider,
	providerID string, jsonData json.RawMessage,
) (identifier.Identifier, errors.E) {
	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		return identifier.Identifier{}, errE
	}

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

	errE = s.setAccount(ctx, account)
	if errE != nil {
		return identifier.Identifier{}, errE
	}

	return newCredential.ID, nil
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
			result = append(result, CredentialInfoRef{ID: credential.ID})
		}
	}

	s.WriteJSON(w, req, result, nil)
}

// CredentialGet is the frontend handler for getting credentials.
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
	credentialIDStr := params["id"]
	credentialID := identifier.String(credentialIDStr)

	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	for provider, credentials := range account.Credentials {
		for _, credential := range credentials {
			if credential.ID == credentialID {
				info, errE := s.getCredentialInfo(provider, credential)
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

// CredentialAdd is the frontend handler for adding a credential.
func (s *Service) CredentialAdd(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func validateCredentialSession(cas *credentialAddSession, expectedType string) errors.E {
	if cas.Expired() {
		return errors.WithDetails(errSessionNotFound, "expired")
	}

	switch expectedType {
	case "password":
		if cas.Password == nil {
			return errors.New("invalid session type")
		}
	case "passkey":
		if cas.Passkey == nil {
			return errors.New("invalid session type")
		}
	}

	return nil
}

// CredentialAddEmailPost is the API handler for adding a credential to account, POST request.
func (s *Service) CredentialAddEmailPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	accountID := mustGetAccountID(ctx)
	request := CredentialAddEmailRequest{}

	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	preservedEmail, errE := normalizeUsernameCasePreserved(request.Email)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	if errorCode := validateEmail(preservedEmail); errorCode != "" {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    identifier.Identifier{},
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        errorCode,
		}, nil)
		return
	}

	mappedEmail, errE := normalizeUsernameCaseMapped(preservedEmail)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	for _, credential := range account.Credentials[ProviderEmail] {
		if credential.ProviderID == mappedEmail {
			s.WriteJSON(w, req, CredentialAddResponse{
				SessionID:    identifier.Identifier{},
				CredentialID: &credential.ID,
				Passkey:      nil,
				Password:     nil,
				Error:        "",
			}, nil)
			return
		}
	}
	jsonData, errE := x.MarshalWithoutEscapeHTML(CredentialAddEmailRequest{Email: preservedEmail})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	credentialID, errE := s.addCredentialToAccount(ctx, accountID, ProviderEmail, mappedEmail, jsonData)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, CredentialAddResponse{
		SessionID:    identifier.Identifier{},
		CredentialID: &credentialID,
		Passkey:      nil,
		Password:     nil,
		Error:        "",
	}, nil)
}

// CredentialAddUsernamePost is the API handler for adding a credential to account, POST request.
func (s *Service) CredentialAddUsernamePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	accountID := mustGetAccountID(ctx)

	request := CredentialAddUsernameRequest{}
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}
	preservedUsername, errE := normalizeUsernameCasePreserved(request.Username)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if errorCode := validateUsername(preservedUsername); errorCode != "" {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    identifier.Identifier{},
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        errorCode,
		}, nil)
		return
	}

	mappedUsername, errE := normalizeUsernameCaseMapped(preservedUsername)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	for _, credential := range account.Credentials[ProviderUsername] {
		if credential.ProviderID == mappedUsername {
			s.WriteJSON(w, req, CredentialAddResponse{
				SessionID:    identifier.Identifier{},
				CredentialID: &credential.ID,
				Passkey:      nil,
				Password:     nil,
				Error:        "",
			}, nil)
			return
		}
	}

	// TODO: This is not race safe, needs improvement once we have storage that supports transactions.
	existingAccount, errE := s.getAccountByCredential(ctx, ProviderUsername, mappedUsername)
	if errE == nil && existingAccount.ID != accountID {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    identifier.Identifier{},
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialAlreadyUsed,
		}, nil)
		return
	} else if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(CredentialAddUsernameRequest{Username: preservedUsername})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	credentialID, errE := s.addCredentialToAccount(ctx, accountID, ProviderUsername, mappedUsername, jsonData)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	s.WriteJSON(w, req, CredentialAddResponse{
		SessionID:    identifier.Identifier{},
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

	privateKeyBytes, publicKeyBytes, nonce, overhead, errE := generatePasswordEncryptionKeys()
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
	}

	session := credentialAddSession{
		ID: identifier.New(),
		Password: &flowPassword{
			PrivateKey: privateKeyBytes,
			Nonce:      nonce,
		},
		Passkey:   nil,
		CreatedAt: time.Now(),
	}
	sessionData, errE := x.MarshalWithoutEscapeHTML(session)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	sessionID := session.ID
	credentialSessionsMu.Lock()
	credentialSessions[sessionID] = sessionData
	credentialSessionsMu.Unlock()

	response := CredentialAddResponse{
		SessionID:    sessionID,
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

	accountID := mustGetAccountID(ctx)

	var request credentialAddPasswordCompleteRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}
	var cas *credentialAddSession
	cas, errE = getAndDeleteCredentialSession(request.SessionID)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = validateCredentialSession(cas, "password")
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}
	plainPassword, internalServerErrE, badRequestErrE := decryptPasswordECDHAESGCM(cas.Password.PrivateKey, request.PublicKey, cas.Password.Nonce, request.Password)
	if internalServerErrE != nil {
		s.BadRequestWithError(w, req, internalServerErrE)
		return
	}
	if badRequestErrE != nil {
		s.InternalServerErrorWithError(w, req, badRequestErrE)
	}

	plainPassword, errE = normalizePassword(plainPassword)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if len(plainPassword) < passwordMinLength {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    cas.ID,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeShortPassword,
		}, nil)
		return
	}

	hashedPassword, err := argon2id.CreateHash(string(plainPassword), &argon2idParams)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	for _, credential := range account.Credentials[ProviderPassword] {
		var pc passwordCredential
		errE = x.Unmarshal(credential.Data, &pc)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		exists, err := argon2id.ComparePasswordAndHash(string(plainPassword), pc.Hash)
		if err != nil {
			s.InternalServerErrorWithError(w, req, errors.WithStack(err))
			return
		}

		if exists {
			s.WriteJSON(w, req, CredentialAddResponse{
				SessionID:    cas.ID,
				CredentialID: &credential.ID,
				Passkey:      nil,
				Password:     nil,
				Error:        "",
			}, nil)
			return
		}
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(passwordCredential{
		Hash:  hashedPassword,
		Label: request.Label,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	providerID := identifier.New().String()
	credentialID, errE := s.addCredentialToAccount(ctx, accountID, ProviderPassword, providerID, jsonData)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, CredentialAddResponse{
		SessionID:    cas.ID,
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

	userID := identifier.New()
	options, sessionData, err := s.passkeyProvider().BeginRegistration(
		passkeyCredential{
			ID:         userID,
			Label:      "",
			Credential: nil,
		},
		webauthn.WithExtensions(protocol.AuthenticationExtensions{
			"credentialProtectionPolicy":        "userVerificationOptional",
			"enforceCredentialProtectionPolicy": false,
		}),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: "",
			RequireResidentKey:      protocol.ResidentKeyRequired(),
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			UserVerification:        protocol.VerificationRequired,
		}),
		withPreferredCredentialAlgorithms([]webauthncose.COSEAlgorithmIdentifier{
			webauthncose.AlgEdDSA,
			webauthncose.AlgES256,
			webauthncose.AlgRS256,
		}),
	)
	if err != nil {
		s.InternalServerErrorWithError(w, req, withWebauthnError(err))
		return
	}

	session := credentialAddSession{
		ID:        identifier.New(),
		Password:  nil,
		Passkey:   sessionData,
		CreatedAt: time.Now(),
	}
	sessionDataBytes, errE := x.MarshalWithoutEscapeHTML(session)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	sessionID := session.ID
	credentialSessionsMu.Lock()
	credentialSessions[sessionID] = sessionDataBytes
	credentialSessionsMu.Unlock()

	s.WriteJSON(w, req, CredentialAddResponse{
		SessionID:    sessionID,
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

	accountID := mustGetAccountID(ctx)

	var request credentialAddPasskeyCompleteRequest
	errE := x.DecodeJSON(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	var cas *credentialAddSession
	cas, errE = getAndDeleteCredentialSession(request.SessionID)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = validateCredentialSession(cas, "passkey")
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	parsedResponse, err := request.CreateResponse.Parse()
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	userID := identifier.Data([16]byte(cas.Passkey.UserID))
	label := strings.TrimSpace(request.Label)
	if label == "" {
		label = userID.String()
	}

	credential := passkeyCredential{
		ID:         userID,
		Label:      label,
		Credential: nil,
	}

	credential.Credential, err = s.passkeyProvider().CreateCredential(credential, *cas.Passkey, parsedResponse)
	if err != nil {
		s.BadRequestWithError(w, req, withWebauthnError(err))
		return
	}

	providerID := base64.RawURLEncoding.EncodeToString(credential.Credential.ID)

	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	for _, cred := range account.Credentials[ProviderPasskey] {
		if cred.ProviderID == providerID {
			s.WriteJSON(w, req, CredentialAddResponse{
				SessionID:    cas.ID,
				CredentialID: &cred.ID,
				Passkey:      nil,
				Password:     nil,
				Error:        "",
			}, nil)
			return
		}
	}

	if credential.Credential.Authenticator.CloneWarning {
		zerolog.Ctx(ctx).Warn().Str("credential", providerID).Msg("authenticator may be cloned")
	}

	existingAccount, errE := s.getAccountByCredential(ctx, ProviderPasskey, providerID)
	if errE == nil && existingAccount.ID != accountID {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    cas.ID,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodePasskeyBoundToOtherAccount,
		}, nil)
		return
	} else if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(credential)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	credentialID, errE := s.addCredentialToAccount(ctx, accountID, ProviderPasskey, providerID, jsonData)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, CredentialAddResponse{
		SessionID:    cas.ID,
		CredentialID: &credentialID,
		Passkey:      nil,
		Password:     nil,
		Error:        "",
	}, nil)
}

func getAndDeleteCredentialSession(sessionID identifier.Identifier) (*credentialAddSession, errors.E) {
	credentialSessionsMu.Lock()
	sessionData, ok := credentialSessions[sessionID]
	if ok {
		delete(credentialSessions, sessionID)
	}
	credentialSessionsMu.Unlock()

	if !ok {
		return nil, errors.WithDetails(errSessionNotFound, "sessionID", sessionID)
	}

	var cas credentialAddSession
	errE := x.UnmarshalWithoutUnknownFields(sessionData, &cas)
	if errE != nil {
		errors.Details(errE)["sessionID"] = sessionID
		return nil, errE
	}

	return &cas, nil
}

// CredentialRemovePost is the API handler for removing credential, POST request.
func (s *Service) CredentialRemovePost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}
	accountID := mustGetAccountID(ctx)
	credentialIDStr := params["id"]
	credentialID := identifier.String(credentialIDStr)

	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	var foundProvider Provider
	foundIndex := -1

	for provider, credentials := range account.Credentials {
		for i, credential := range credentials {
			if credential.ID == credentialID {
				foundProvider = provider
				foundIndex = i
				break
			}
		}
		if foundIndex != -1 {
			break
		}
	}

	if foundIndex == -1 {
		s.NotFound(w, req)
		return
	}

	account.Credentials[foundProvider] = append(
		account.Credentials[foundProvider][:foundIndex],
		account.Credentials[foundProvider][foundIndex+1:]...,
	)

	if len(account.Credentials[foundProvider]) == 0 {
		delete(account.Credentials, foundProvider)
	}

	errE = s.setAccount(ctx, account)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, map[string]interface{}{
		"success": true,
	}, nil)
}
