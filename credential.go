package charon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"slices"
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

// Credential addition error codes.
const (
	ErrorCodeCredentialInUse        ErrorCode = "credentialInUse" //nolint:gosec
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
	SessionID    *identifier.Identifier    `json:"sessionId"`
	CredentialID *identifier.Identifier    `json:"credentialId,omitempty"`
	Passkey      *AuthFlowResponsePasskey  `json:"passkey,omitempty"`
	Password     *AuthFlowResponsePassword `json:"password,omitempty"`
	Error        ErrorCode                 `json:"error,omitempty"`
}

// CredentialAddPasswordCompleteRequest represents the request body for the CredentialAddPasswordCompletePost handler.
type CredentialAddPasswordCompleteRequest struct {
	AuthFlowPasswordCompleteRequest

	SessionID identifier.Identifier `json:"sessionId"`
	Label     string                `json:"label"`
}

// CredentialAddPasskeyCompleteRequest represents the request body for the CredentialAddPasskeyCompletePost handler.
type CredentialAddPasskeyCompleteRequest struct {
	AuthFlowPasskeyCreateCompleteRequest

	SessionID identifier.Identifier `json:"sessionId"`
	Label     string                `json:"label"`
}

// CredentialAddSession represents session data for adding credential.
type CredentialAddSession struct {
	ID        identifier.Identifier
	CreatedAt time.Time
	Passkey   *webauthn.SessionData
	Password  *flowPassword
}

// Expired returns true if the credential add session has expired.
func (s CredentialAddSession) Expired() bool {
	return time.Now().After(s.CreatedAt.Add(credentialAddSessionExpiration))
}

func (s *Service) addCredentialToAccount(
	ctx context.Context, accountID identifier.Identifier, providerKey Provider, providerID string,
	jsonData json.RawMessage,
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

func validateCredentialSession(cas *CredentialAddSession, expectedType string) errors.E {
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

// CredentialAddEmailPost is the API handler for adding an e-mail credential to account, POST request.
func (s *Service) CredentialAddEmailPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req)
	if ctx == nil {
		return
	}

	accountID := mustGetAccountID(ctx)

	var request emailCredential
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	preservedEmail, mappedEmail, errorCode, errE := normalizeEmailOrUsername(request.Email, EmailOrUsernameCheckEmail)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	if errorCode != "" {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    &identifier.Identifier{},
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        errorCode,
		}, nil)
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
				SessionID:    &identifier.Identifier{},
				CredentialID: &credential.ID,
				Passkey:      nil,
				Password:     nil,
				Error:        "",
			}, nil)
			return
		}
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(emailCredential{Email: preservedEmail, Verified: false})
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
		SessionID:    &identifier.Identifier{},
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

	accountID := mustGetAccountID(ctx)

	request := usernameCredential{}
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	preservedUsername, mappedUsername, errorCode, errE := normalizeEmailOrUsername(request.Username, EmailOrUsernameCheckUsername)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	if errorCode != "" {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    &identifier.Identifier{},
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        errorCode,
		}, nil)
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
				SessionID:    &identifier.Identifier{},
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
			SessionID:    &identifier.Identifier{},
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

	jsonData, errE := x.MarshalWithoutEscapeHTML(usernameCredential{preservedUsername})
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
		SessionID:    &identifier.Identifier{},
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

	session := CredentialAddSession{
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

	credentialSessionsMu.Lock()
	credentialSessions[session.ID] = sessionData
	credentialSessionsMu.Unlock()

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

	accountID := mustGetAccountID(ctx)

	var request CredentialAddPasswordCompleteRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}
	var cas *CredentialAddSession
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
	plainPassword, errE := decryptEncryptedPassword(cas.Password.PrivateKey, request.PublicKey, cas.Password.Nonce, request.Password)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
	}

	plainPassword, errE = normalizePassword(plainPassword)
	if errE != nil {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    &cas.ID,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeInvalidPassword,
		}, nil)
		return
	}

	if len(plainPassword) < passwordMinLength {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    &cas.ID,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeShortPassword,
		}, nil)
		return
	}

	requestLabel := strings.TrimSpace(request.Label)
	if requestLabel == "" {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    &cas.ID,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialLabelMissing,
		}, nil)
	}

	hashedPassword, err := argon2id.CreateHash(plainPassword, &argon2idParams)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// We check if the same password is already set and if the label is already in use.
	for _, credential := range account.Credentials[ProviderPassword] {
		var pc passwordCredential
		errE = x.Unmarshal(credential.Data, &pc)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		match, err := argon2id.ComparePasswordAndHash(plainPassword, pc.Hash)
		if err != nil {
			s.InternalServerErrorWithError(w, req, errors.WithStack(err))
			return
		}

		if match {
			// TODO: If options are different, migrate the password to new options.
			s.WriteJSON(w, req, CredentialAddResponse{
				SessionID:    &cas.ID,
				CredentialID: &credential.ID,
				Passkey:      nil,
				Password:     nil,
				Error:        "",
			}, nil)
			return
		}

		if requestLabel == pc.Label {
			s.WriteJSON(w, req, CredentialAddResponse{
				SessionID:    &cas.ID,
				CredentialID: nil,
				Passkey:      nil,
				Password:     nil,
				Error:        ErrorCodeCredentialLabelInUse,
			}, nil)
			return
		}
	}

	// Password is not already set.
	jsonData, errE := x.MarshalWithoutEscapeHTML(passwordCredential{
		Hash:  hashedPassword,
		Label: requestLabel,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	providerID := ""
	credentialID, errE := s.addCredentialToAccount(ctx, accountID, ProviderPassword, providerID, jsonData)
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

	userID := identifier.New()
	options, sessionData, err := s.passkeyProvider().BeginRegistration(
		passkeyCredential{
			ID:         userID,
			Label:      userID.String(),
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

	session := CredentialAddSession{
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
	credentialSessionsMu.Lock()
	credentialSessions[session.ID] = sessionDataBytes
	credentialSessionsMu.Unlock()

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

	accountID := mustGetAccountID(ctx)

	var request CredentialAddPasskeyCompleteRequest
	errE := x.DecodeJSON(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	cas, errE := getAndDeleteCredentialSession(request.SessionID)
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

	pkCredential := passkeyCredential{
		ID:         userID,
		Label:      label,
		Credential: nil,
	}

	pkCredential.Credential, err = s.passkeyProvider().CreateCredential(pkCredential, *cas.Passkey, parsedResponse)
	if err != nil {
		s.BadRequestWithError(w, req, withWebauthnError(err))
		return
	}

	providerID := base64.RawURLEncoding.EncodeToString(pkCredential.Credential.ID)

	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	requestLabel := strings.TrimSpace(request.Label)
	if requestLabel == "" {
		s.WriteJSON(w, req, CredentialAddResponse{
			SessionID:    &cas.ID,
			CredentialID: nil,
			Passkey:      nil,
			Password:     nil,
			Error:        ErrorCodeCredentialLabelMissing,
		}, nil)
	}
	for _, credential := range account.Credentials[ProviderPasskey] {
		var pkc passkeyCredential
		errE = x.Unmarshal(credential.Data, &pkc)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		if requestLabel == strings.TrimSpace(pkc.Label) {
			s.WriteJSON(w, req, CredentialAddResponse{
				SessionID:    &cas.ID,
				CredentialID: nil,
				Passkey:      nil,
				Password:     nil,
				Error:        ErrorCodeCredentialLabelInUse,
			}, nil)
			return
		}
	}

	if pkCredential.Credential.Authenticator.CloneWarning {
		zerolog.Ctx(ctx).Warn().Str("credential", providerID).Msg("authenticator may be cloned")
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(pkCredential)
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
		SessionID:    nil,
		CredentialID: &credentialID,
		Passkey:      nil,
		Password:     nil,
		Error:        "",
	}, nil)
}

func getAndDeleteCredentialSession(sessionID identifier.Identifier) (*CredentialAddSession, errors.E) {
	credentialSessionsMu.Lock()
	sessionData, ok := credentialSessions[sessionID]
	if ok {
		delete(credentialSessions, sessionID)
	}
	credentialSessionsMu.Unlock()

	if !ok {
		return nil, errors.WithDetails(errSessionNotFound, "sessionID", sessionID)
	}

	var cas CredentialAddSession
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
