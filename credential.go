package charon

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

// ErrorCode values.
const (
	ErrorCodeCredentialAlreadyExists ErrorCode = "credentialAlreadyExists" //nolint:gosec
	ErrorCodeCredentialAlreadyUsed   ErrorCode = "credentialAlreadyUsed"   //nolint:gosec
)

const defaultPasswordTimeout = 60 * time.Second

var (
	credentialSessions   = make(map[identifier.Identifier]json.RawMessage) //nolint:gochecknoglobals
	credentialSessionsMu sync.RWMutex                                      //nolint:gochecknoglobals
)

type credentialInfo struct {
	ID          string   `json:"id"`
	Provider    Provider `json:"provider"`
	DisplayName string   `json:"displayName"`
	Label       string   `json:"label,omitempty"`
}

type credentialAddPasswordStartResponse struct {
	PublicKey      []byte                                 `json:"publicKey"`
	SessionKey     string                                 `json:"sessionKey"`
	DeriveOptions  AuthFlowResponsePasswordDeriveOptions  `json:"deriveOptions"`
	EncryptOptions AuthFlowResponsePasswordEncryptOptions `json:"encryptOptions"`
}

type credentialAddPasswordCompleteRequest struct {
	PublicKey  []byte `json:"publicKey"`
	SessionKey string `json:"sessionKey"`
	Password   []byte `json:"password"`
	Label      string `json:"label,omitempty"`
}

type credentialAddPasskeyStartResponse struct {
	SessionKey    string                       `json:"sessionKey"`
	CreateOptions *protocol.CredentialCreation `json:"createOptions"`
}

type credentialAddPasskeyCompleteRequest struct {
	SessionKey     string                              `json:"sessionKey"`
	CreateResponse protocol.CredentialCreationResponse `json:"createResponse"`
}

type credentialAddSession struct {
	Type       string
	PrivateKey []byte
	Nonce      []byte
	Passkey    *webauthn.SessionData
	CreatedAt  time.Time
}

type addPasswordCredential struct {
	Hash  string `json:"hash"`
	Label string `json:"label"`
}

func (s *Service) credentialError(w http.ResponseWriter, req *http.Request, errorCode ErrorCode) {
	ctx := req.Context()

	errE := errors.New("credential error")
	errors.Details(errE)["code"] = errorCode
	s.WithError(ctx, errE)

	response := map[string]interface{}{
		"success": false,
		"error":   errorCode,
	}

	encoded := s.PrepareJSON(w, req, response, nil)
	if encoded == nil {
		return
	}

	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(encoded)
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

func (s *Service) getCredentialInfo(provider Provider, credential Credential, index int) (credentialInfo, errors.E) {
	var displayName string
	var label string

	switch provider {
	case ProviderEmail:
		var ec emailCredential
		errE := x.Unmarshal(credential.Data, &ec)
		if errE != nil {
			return credentialInfo{}, errE
		}
		displayName = ec.Email
	case ProviderUsername:
		var uc usernameCredential
		errE := x.Unmarshal(credential.Data, &uc)
		if errE != nil {
			return credentialInfo{}, errE
		}
		displayName = uc.Username
	case ProviderPassword:
		var pc addPasswordCredential
		errE := x.Unmarshal(credential.Data, &pc)
		if errE != nil {
			return credentialInfo{}, errE
		}
		label = pc.Label
		if label == "" {
			label = "default password"
		}
		displayName = "Password"
	case ProviderPasskey:
		displayName = fmt.Sprintf("Passkey #%d", index+1)
	case ProviderCode:
		return credentialInfo{}, errors.New("code provider should not be returned")
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

	return credentialInfo{
		ID:          credential.ID,
		Provider:    provider,
		DisplayName: displayName,
		Label:       label,
	}, nil
}

func (s *Service) addCredentialToAccount(ctx context.Context, accountID identifier.Identifier, providerKey Provider,
	credentialID string, jsonData json.RawMessage,
) errors.E {
	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		return errE
	}
	if credentials, exists := account.Credentials[providerKey]; exists {
		for _, cred := range credentials {
			if cred.ID == credentialID {
				return errors.New("credential already exists")
			}
		}
	}
	newCredential := Credential{
		ID:       credentialID,
		Provider: providerKey,
		Data:     jsonData,
	}

	if account.Credentials == nil {
		account.Credentials = make(map[Provider][]Credential)
	}

	account.Credentials[providerKey] = append(account.Credentials[providerKey], newCredential)

	errE = s.setAccount(ctx, account)
	if errE != nil {
		return errE
	}

	return nil
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
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	err := req.ParseForm()
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}
	ctx := s.requireAuthenticatedForIdentity(w, req)
	if ctx == nil {
		return
	}

	accountID := mustGetAccountID(ctx)

	log := zerolog.Ctx(ctx)
	log.Info().Str("accountID", accountID.String()).Msg("getting credentials for account")

	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	total := 0
	for _, creds := range account.Credentials {
		total += len(creds)
	}
	result := make([]credentialInfo, 0, total)

	for provider, credentials := range account.Credentials {
		for i, credential := range credentials {
			info, errE := s.getCredentialInfo(provider, credential, i)
			if errE != nil {
				s.InternalServerErrorWithError(w, req, errE)
				return
			}
			result = append(result, info)
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
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	err := req.ParseForm()
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}
	ctx := s.requireAuthenticatedForIdentity(w, req)
	if ctx == nil {
		return
	}

	accountID := mustGetAccountID(ctx)
	credentialID := params["id"]

	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	for provider, credentials := range account.Credentials {
		for i, credential := range credentials {
			if credential.ID == credentialID {
				info, errE := s.getCredentialInfo(provider, credential, i)
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

func (s *Service) addSimpleCredential(
	ctx context.Context,
	w http.ResponseWriter,
	req *http.Request,
	accountID identifier.Identifier,
	provider Provider,
	value string,
	validateFunc func(string) ErrorCode,
) {
	preservedValue, errE := normalizeUsernameCasePreserved(value)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if errorCode := validateFunc(preservedValue); errorCode != "" {
		s.credentialError(w, req, errorCode)
		return
	}

	mappedValue, errE := normalizeUsernameCaseMapped(preservedValue)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	existingAccount, errE := s.getAccountByCredential(ctx, provider, mappedValue)
	if errE == nil && existingAccount.ID != accountID {
		s.credentialError(w, req, ErrorCodeCredentialAlreadyUsed)
		return
	} else if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	var jsonData []byte
	if provider == ProviderEmail {
		jsonData, errE = x.MarshalWithoutEscapeHTML(emailCredential{Email: preservedValue})
	} else {
		jsonData, errE = x.MarshalWithoutEscapeHTML(usernameCredential{Username: preservedValue})
	}
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	errE = s.addCredentialToAccount(ctx, accountID, provider, mappedValue, jsonData)
	if errE != nil {
		s.credentialError(w, req, ErrorCodeCredentialAlreadyExists)
		return
	}

	s.WriteJSON(w, req, map[string]interface{}{
		"success": true,
		"id":      mappedValue,
	}, nil)
}

func validateCredentialSession(cas *credentialAddSession, expectedType string, timeout time.Duration) errors.E {
	if time.Since(cas.CreatedAt) > timeout {
		return errors.WithDetails(errSessionNotFound, "expired")
	}

	switch expectedType {
	case "password":
		if cas.Type != "password" || cas.PrivateKey == nil || cas.Nonce == nil {
			return errors.New("invalid session type")
		}
	case "passkey":
		if cas.Type != "passkey" || cas.Passkey == nil {
			return errors.New("invalid session type")
		}
	}

	return nil
}

// CredentialAddEmailPost is the API handler for adding a credential to account, POST request.
func (s *Service) CredentialAddEmailPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.requireAuthenticatedForIdentity(w, req)
	if ctx == nil {
		return
	}

	accountID := mustGetAccountID(ctx)

	var request struct {
		Email string `json:"email"`
	}

	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}
	s.addSimpleCredential(ctx, w, req, accountID, ProviderEmail, request.Email, validateEmail)
}

// CredentialAddUsernamePost is the API handler for adding a credential to account, POST request.
func (s *Service) CredentialAddUsernamePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.requireAuthenticatedForIdentity(w, req)
	if ctx == nil {
		return
	}

	accountID := mustGetAccountID(ctx)

	var request struct {
		Username string `json:"username"`
	}
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &request)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	s.addSimpleCredential(ctx, w, req, accountID, ProviderUsername, request.Username, validateUsername)
}

// CredentialAddPasswordStartPost is the API handler to start the password credential step, POST request.
func (s *Service) CredentialAddPasswordStartPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.requireAuthenticatedForIdentity(w, req)
	if ctx == nil {
		return
	}

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	block, err := aes.NewCipher(make([]byte, secretSize))
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	nonce := make([]byte, aesgcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	session := credentialAddSession{
		Type:       "password",
		PrivateKey: privateKey.Bytes(),
		Nonce:      nonce,
		Passkey:    nil,
		CreatedAt:  time.Now(),
	}
	sessionData, errE := x.MarshalWithoutEscapeHTML(session)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	sessionKey := identifier.New()
	credentialSessionsMu.Lock()
	credentialSessions[sessionKey] = sessionData
	credentialSessionsMu.Unlock()

	response := credentialAddPasswordStartResponse{
		PublicKey:  privateKey.PublicKey().Bytes(),
		SessionKey: sessionKey.String(),
		DeriveOptions: AuthFlowResponsePasswordDeriveOptions{
			Name:       "ECDH",
			NamedCurve: "P-256",
		},
		EncryptOptions: AuthFlowResponsePasswordEncryptOptions{
			Name:      "AES-GCM",
			Nonce:     nonce,
			TagLength: 8 * aesgcm.Overhead(), //nolint:mnd
			Length:    8 * secretSize,        //nolint:mnd
		},
	}

	s.WriteJSON(w, req, response, nil)
}

// CredentialAddPasswordCompletePost is the API handler to complete the password credential step, POST request.
func (s *Service) CredentialAddPasswordCompletePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.requireAuthenticatedForIdentity(w, req)
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
	cas, errE = getAndDeleteCredentialSession(request.SessionKey)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = validateCredentialSession(cas, "password", defaultPasswordTimeout)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	privateKey, err := ecdh.P256().NewPrivateKey(cas.PrivateKey)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	remotePublicKey, err := ecdh.P256().NewPublicKey(request.PublicKey)
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	secret, err := privateKey.ECDH(remotePublicKey)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	plainPassword, err := aesgcm.Open(nil, cas.Nonce, request.Password, nil)
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	plainPassword, errE = normalizePassword(plainPassword)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if len(plainPassword) < passwordMinLength {
		s.credentialError(w, req, ErrorCodeShortPassword)
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
		var pc addPasswordCredential
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
			s.credentialError(w, req, ErrorCodeCredentialAlreadyUsed)
			return
		}
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(addPasswordCredential{
		Hash:  hashedPassword,
		Label: request.Label,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	credentialID := identifier.New().String()
	errE = s.addCredentialToAccount(ctx, accountID, ProviderPassword, credentialID, jsonData)
	if errE != nil {
		s.credentialError(w, req, ErrorCodeCredentialAlreadyExists)
		return
	}

	s.WriteJSON(w, req, map[string]interface{}{
		"success": true,
		"id":      credentialID,
	}, nil)
}

func getAndDeleteCredentialSession(sessionKey string) (*credentialAddSession, errors.E) {
	sessionKeyID := identifier.String(sessionKey)

	credentialSessionsMu.Lock()
	sessionData, ok := credentialSessions[sessionKeyID]
	if ok {
		delete(credentialSessions, sessionKeyID)
	}
	credentialSessionsMu.Unlock()

	if !ok {
		return nil, errors.WithDetails(errSessionNotFound, "sessionKeyID", sessionKeyID)
	}

	var cas credentialAddSession
	errE := x.UnmarshalWithoutUnknownFields(sessionData, &cas)
	if errE != nil {
		errors.Details(errE)["sessionKeyID"] = sessionKeyID
		return nil, errE
	}

	return &cas, nil
}

// CredentialAddPasskeyStartPost is the API handler to start the passkey credential step, POST request.
func (s *Service) CredentialAddPasskeyStartPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.requireAuthenticatedForIdentity(w, req)
	if ctx == nil {
		return
	}

	accountID := mustGetAccountID(ctx)

	account, errE := s.getAccount(ctx, accountID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	existingCredentials := []webauthn.Credential{}
	for _, credential := range account.Credentials[ProviderPasskey] {
		var c webauthn.Credential
		errE = x.Unmarshal(credential.Data, &c)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		existingCredentials = append(existingCredentials, c)
	}

	user := &charonUser{
		Credentials: existingCredentials,
	}

	options, sessionData, err := s.passkeyProvider().BeginRegistration(
		user,
		webauthn.WithExtensions(protocol.AuthenticationExtensions{
			"credentialProtectionPolicy": "userVerificationOptional",
		}),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: "",
			RequireResidentKey:      protocol.ResidentKeyRequired(),
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			UserVerification:        protocol.VerificationDiscouraged,
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
		Type:       "passkey",
		PrivateKey: nil,
		Nonce:      nil,
		Passkey:    sessionData,
		CreatedAt:  time.Now(),
	}
	sessionDataBytes, errE := x.MarshalWithoutEscapeHTML(session)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	sessionKey := identifier.New()
	credentialSessionsMu.Lock()
	credentialSessions[sessionKey] = sessionDataBytes
	credentialSessionsMu.Unlock()

	s.WriteJSON(w, req, credentialAddPasskeyStartResponse{
		SessionKey:    sessionKey.String(),
		CreateOptions: options,
	}, nil)
}

// CredentialAddPasskeyCompletePost is the API handler to complete the passkey credential step, POST request.
func (s *Service) CredentialAddPasskeyCompletePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.requireAuthenticatedForIdentity(w, req)
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
	cas, errE = getAndDeleteCredentialSession(request.SessionKey)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = validateCredentialSession(cas, "passkey", defaultPasskeyTimeout)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	parsedResponse, err := request.CreateResponse.Parse()
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	credential, err := s.passkeyProvider().CreateCredential(&charonUser{nil}, *cas.Passkey, parsedResponse)
	if err != nil {
		s.BadRequestWithError(w, req, withWebauthnError(err))
		return
	}

	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)

	if credential.Authenticator.CloneWarning {
		zerolog.Ctx(ctx).Warn().Str("credential", credentialID).Msg("authenticator may be cloned")
	}

	existingAccount, errE := s.getAccountByCredential(ctx, ProviderPasskey, credentialID)
	if errE == nil && existingAccount.ID != accountID {
		s.credentialError(w, req, ErrorCodeCredentialAlreadyUsed)
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

	errE = s.addCredentialToAccount(ctx, accountID, ProviderPasskey, credentialID, jsonData)
	if errE != nil {
		s.credentialError(w, req, ErrorCodeCredentialAlreadyExists)
		return
	}

	s.WriteJSON(w, req, map[string]interface{}{
		"success": true,
		"id":      credentialID,
	}, nil)
}

// CredentialRemovePost is the API handler for removing credential, POST request.
func (s *Service) CredentialRemovePost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.requireAuthenticatedForIdentity(w, req)
	if ctx == nil {
		return
	}
	accountID := mustGetAccountID(ctx)
	credentialID := params["id"]

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
