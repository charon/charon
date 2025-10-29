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
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
	"golang.org/x/oauth2"
)

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
	preservedEmail, errE := normalizeUsernameCasePreserved(request.Email)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	if len(preservedEmail) < emailOrUsernameMinLength {
		s.BadRequestWithError(w, req, errors.New("email too short"))
		return
	}

	if !strings.Contains(preservedEmail, "@") {
		s.BadRequestWithError(w, req, errors.New("invalid email address"))
		return
	}

	mappedEmail, errE := normalizeUsernameCaseMapped(preservedEmail)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	existingAccount, errE := s.getAccountByCredential(ctx, ProviderEmail, mappedEmail)
	if errE == nil && existingAccount.ID != accountID {
		s.BadRequestWithError(w, req, errors.New("email already in use"))
		return
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(emailCredential{
		Email: preservedEmail,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	errE = s.addCredentialToAccount(ctx, accountID, ProviderEmail, mappedEmail, jsonData)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, map[string]interface{}{
		"success": true,
		"id":      mappedEmail,
	}, nil)
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

	preservedUsername, errE := normalizeUsernameCasePreserved(request.Username)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if strings.Contains(preservedUsername, "@") {
		s.BadRequestWithError(w, req, errors.New("username cannot contain @"))
		return
	}

	mappedUsername, errE := normalizeUsernameCaseMapped(preservedUsername)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	existingAccount, errE := s.getAccountByCredential(ctx, ProviderUsername, mappedUsername)
	if errE == nil && existingAccount.ID != accountID {
		s.BadRequestWithError(w, req, errors.New("username already in use"))
		return
	} else if errE != nil && !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(usernameCredential{
		Username: preservedUsername,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	errE = s.addCredentialToAccount(ctx, accountID, ProviderUsername, mappedUsername, jsonData)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, map[string]interface{}{
		"success": true,
		"id":      mappedUsername,
	}, nil)
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
	sessionKeyID := identifier.String(request.SessionKey)

	credentialSessionsMu.Lock()
	sessionData, ok := credentialSessions[sessionKeyID]
	if ok {
		delete(credentialSessions, sessionKeyID)
	}
	credentialSessionsMu.Unlock()

	if !ok {
		s.BadRequestWithError(w, req, errors.WithDetails(errSessionNotFound, "sessionKeyID", sessionKeyID))
		return
	}

	var session credentialAddSession
	errE = x.UnmarshalWithoutUnknownFields(sessionData, &session)
	if errE != nil {
		errors.Details(errE)["sessionKeyID"] = sessionKeyID
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if time.Since(session.CreatedAt) > (defaultPasskeyTimeout) {
		s.BadRequestWithError(w, req, errors.WithDetails(errSessionNotFound, "expired"))
		return
	}

	if session.Type != "password" || session.PrivateKey == nil || session.Nonce == nil {
		s.BadRequestWithError(w, req, errors.New("invalid session type"))
		return
	}

	privateKey, err := ecdh.P256().NewPrivateKey(session.PrivateKey)
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

	plainPassword, err := aesgcm.Open(nil, session.Nonce, request.Password, nil)
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
		s.BadRequestWithError(w, req, errors.New(string(ErrorCodeShortPassword)))
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
			s.BadRequestWithError(w, req, errors.New("password already used on this account"))
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
		s.BadRequestWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, map[string]interface{}{
		"success": true,
		"id":      credentialID,
	}, nil)
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

	sessionKeyID := identifier.String(request.SessionKey)

	credentialSessionsMu.Lock()
	sessionData, ok := credentialSessions[sessionKeyID]
	if ok {
		delete(credentialSessions, sessionKeyID)
	}
	credentialSessionsMu.Unlock()

	if !ok {
		s.BadRequestWithError(w, req, errors.WithDetails(errSessionNotFound, "sessionKeyID", sessionKeyID))
		return
	}

	var session credentialAddSession
	errE = x.UnmarshalWithoutUnknownFields(sessionData, &session)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if time.Since(session.CreatedAt) > (defaultPasskeyTimeout) {
		s.BadRequestWithError(w, req, errors.WithDetails(errSessionNotFound, "expired"))
		return
	}

	if session.Type != "passkey" || session.Passkey == nil {
		s.BadRequestWithError(w, req, errors.New("invalid session type"))
		return
	}

	parsedResponse, err := request.CreateResponse.Parse()
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	credential, err := s.passkeyProvider().CreateCredential(&charonUser{nil}, *session.Passkey, parsedResponse)
	if err != nil {
		s.BadRequestWithError(w, req, withWebauthnError(err))
		return
	}

	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)

	if credential.Authenticator.CloneWarning {
		zerolog.Ctx(ctx).Warn().Str("credential", credentialID).Msg("authenticator may be cloned")
	}

	existingAccount, errE := s.getAccountByCredential(ctx, ProviderPasskey, credentialID)
	if errE == nil && existingAccount != nil {
		s.BadRequestWithError(w, req, errors.New("passkey already registered to this account"))
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
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, map[string]interface{}{
		"success": true,
		"id":      credentialID,
	}, nil)
}

// CredentialAddThirdPartyProviderStartPost is the API handler for starting the third-party credential step, POST request.
func (s *Service) CredentialAddThirdPartyProviderStartPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.requireAuthenticatedForIdentity(w, req)
	if ctx == nil {
		return
	}

	sessionID := mustGetSessionID(ctx)
	providerKey := Provider(params["provider"])

	flow := &flow{
		ID:        identifier.New(),
		CreatedAt: time.Now().UTC(),
		Completed: []Completed{},
		AuthTime:  nil,

		OrganizationID: identifier.Identifier{},
		AppID:          identifier.Identifier{},

		SessionID: &sessionID,
		Identity:  nil,

		OIDCAuthorizeRequest: nil,

		AuthAttempts:    0,
		Providers:       []Provider{providerKey},
		EmailOrUsername: "",
		OIDCProvider:    nil,
		SAMLProvider:    nil,
		Passkey:         nil,
		Password:        nil,
		Code:            nil,
	}
	var errE errors.E
	var location string

	if p, ok := s.oidcProviders()[providerKey]; ok {
		location, errE = s.handleCredentialAddOIDCStart(ctx, flow, p)
	}
	if p, ok := s.samlProviders()[providerKey]; ok {
		location, errE = s.handleCredentialAddSAMLStart(ctx, flow, p)
	}
	if location == "" {
		errE = errors.New("unknown provider")
		errors.Details(errE)["provider"] = providerKey
		s.NotFoundWithError(w, req, errE)
		return
	}

	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	var existingToken string
	for _, cookie := range req.Cookies() {
		if strings.HasPrefix(cookie.Name, sessionCookiePrefix) {
			ses, errE := s.getSessionFromCookieValue(ctx, cookie.Value)
			if errE == nil && ses.ID == sessionID {
				existingToken = cookie.Value
				break
			}
		}
	}

	if existingToken != "" {
		cookie := http.Cookie{
			Name:     sessionCookiePrefix + flow.ID.String(),
			Value:    existingToken,
			Path:     "/",
			Domain:   "",
			Expires:  time.Now().Add(sessionExpiration),
			MaxAge:   0,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, &cookie)
	}

	s.WriteJSON(w, req, map[string]interface{}{
		"location": location,
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

func (s *Service) handleCredentialAddSAMLStart(ctx context.Context, flow *flow, provider samlProvider) (string, errors.E) {
	handler := s.handlerSAMLStart(provider)
	authURL, errE := handler(flow)
	if errE != nil {
		return "", errE
	}

	errE = s.setFlow(ctx, flow)
	if errE != nil {
		return "", errE
	}
	return authURL, nil
}

func (s *Service) handleCredentialAddSAMLCallback(w http.ResponseWriter, req *http.Request, providerKey Provider, provider samlProvider) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	err := req.ParseForm()
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	flow := s.getActiveFlow(w, req, req.Form.Get("RelayState"))
	if flow == nil {
		return
	}

	flowSAML := *flow.SAMLProvider
	flow.SAMLProvider = nil
	errE := s.setFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if flow.SessionID == nil {
		s.InternalServerErrorWithError(w, req, errors.New("missing session ID for credential addition"))
		return
	}

	session, errE := s.getSession(ctx, *flow.SessionID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	accountID := session.AccountID

	log := s.Logger.With().
		Str("provider", string(providerKey)).
		Str("flow_id", flow.ID.String()).
		Str("account_id", accountID.String()).
		Logger()

	samlResponse := req.Form.Get("SAMLResponse")
	if samlResponse == "" {
		log.Warn().Msg("missing SAMLResponse in callback")
		s.BadRequestWithError(w, req, errors.New("missing SAMLResponse"))
		return
	}

	location, errE := s.Reverse("CredentialList", nil, nil)
	if errE != nil {
		log.Warn().Err(errE).Msg("reverse route failure")
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	assertionInfo, response, errE := retrieveAssertionInfoWithResponse(provider.Provider, samlResponse)
	if errE != nil {
		log.Warn().Err(errE).Msg("assertion retrieval failed")
		s.TemporaryRedirectGetMethod(w, req, location)
		return
	}

	errE = validateSAMLAssertion(assertionInfo)
	if errE != nil {
		log.Warn().Err(errE).Msg("saml assertion validation failed")
		s.TemporaryRedirectGetMethod(w, req, location)
		return
	}

	if response.InResponseTo != flowSAML.RequestID {
		log.Warn().Str("response_in_response_to", response.InResponseTo).
			Msg("saml response ID does not match request ID")
		s.TemporaryRedirectGetMethod(w, req, location)
		return
	}

	attributes, errE := getSAMLAttributes(assertionInfo, provider.Mapping)
	if errE != nil {
		log.Warn().Err(errE).Msg("getting SAML attributes failed")
		s.TemporaryRedirectGetMethod(w, req, location)
		return
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(attributes)
	if errE != nil {
		log.Warn().Err(errE).Msg("marshal error")
		s.TemporaryRedirectGetMethod(w, req, location)
		return
	}

	credentialID, errE := getSAMLCredentialID(assertionInfo, attributes, provider.Mapping.CredentialIDAttributes, samlResponse)
	if errE != nil {
		log.Warn().Err(errE).Msg("credentialID error")
		s.TemporaryRedirectGetMethod(w, req, location)
		return
	}

	errE = s.addCredentialToAccount(ctx, accountID, providerKey, credentialID, jsonData)
	if errE != nil {
		log.Warn().Err(errE).Msg("failed to add SAML credential")
		s.BadRequestWithError(w, req, errE)
		return
	}

	s.TemporaryRedirectGetMethod(w, req, location)
}

func (s *Service) handleCredentialAddOIDCStart(ctx context.Context, flow *flow, provider oidcProvider) (string, errors.E) {
	flow.OIDCProvider = &flowOIDCProvider{
		Verifier: "",
		Nonce:    identifier.New().String(),
	}

	opts := []oauth2.AuthCodeOption{}
	opts = append(opts, oidc.Nonce(flow.OIDCProvider.Nonce))

	if provider.SupportsPKCE {
		flow.OIDCProvider.Verifier = oauth2.GenerateVerifier()
		opts = append(opts, oauth2.S256ChallengeOption(flow.OIDCProvider.Verifier))
	}

	errE := s.setFlow(ctx, flow)
	if errE != nil {
		return "", errE
	}

	return provider.Config.AuthCodeURL(flow.ID.String(), opts...), nil
}

func (s *Service) handleCredentialAddOIDCCallback(w http.ResponseWriter, req *http.Request, providerKey Provider, provider oidcProvider) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	err := req.ParseForm()
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	flow := s.getActiveFlow(w, req, req.Form.Get("state"))
	if flow == nil {
		return
	}

	if flow.OIDCProvider == nil {
		s.BadRequestWithError(w, req, errors.New("OIDC provider not started"))
		return
	}

	flowOIDC := *flow.OIDCProvider

	// We reset flow.OIDCProvider to nil always after this point, even if there is a failure,
	// so that nonce cannot be reused.
	flow.OIDCProvider = nil
	errE := s.setFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	if flow.SessionID == nil {
		s.InternalServerErrorWithError(w, req, errors.New("missing session ID for credential addition"))
		return
	}

	ses, errE := s.getSession(ctx, *flow.SessionID)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	accountID := ses.AccountID

	log := s.Logger.With().
		Str("provider", string(providerKey)).
		Str("flow_id", flow.ID.String()).
		Str("account_id", accountID.String()).
		Logger()

	location, errE := s.Reverse("CredentialList", nil, nil)
	if errE != nil {
		log.Warn().Err(errE).Msg("reverse route failure")
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	errorCode := req.Form.Get("error")
	errorDescription := req.Form.Get("error_description")
	if errorCode != "" || errorDescription != "" {
		log.Warn().Str("error_code", errorCode).Str("error_description", errorDescription).Msg("OIDC authorization error")
		s.TemporaryRedirectGetMethod(w, req, location)
		return
	}

	ctx = oidc.ClientContext(ctx, provider.Client)

	opts := []oauth2.AuthCodeOption{}
	if provider.SupportsPKCE {
		opts = append(opts, oauth2.VerifierOption(flowOIDC.Verifier))
	}

	oauth2Token, err := provider.Config.Exchange(ctx, req.Form.Get("code"), opts...)
	if err != nil {
		log.Warn().Err(err).Msg("token exchange failed")
		s.TemporaryRedirectGetMethod(w, req, location)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Warn().Msg("ID token missing")
		s.TemporaryRedirectGetMethod(w, req, location)
		return
	}

	idToken, err := provider.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Warn().Err(err).Msg("ID token verification failed")
		s.TemporaryRedirectGetMethod(w, req, location)
		return
	}

	if idToken.Nonce != flowOIDC.Nonce {
		log.Warn().Msg("nonce mismatch")
		s.TemporaryRedirectGetMethod(w, req, location)
		return
	}

	var jsonData json.RawMessage
	err = idToken.Claims(&jsonData)
	if err != nil {
		log.Warn().Err(err).Msg("claims extraction failed")
		s.TemporaryRedirectGetMethod(w, req, location)
		return
	}

	credentialID := idToken.Subject

	errE = s.addCredentialToAccount(ctx, accountID, providerKey, credentialID, jsonData)
	if errE != nil {
		log.Warn().Err(errE).Msg("failed to add OIDC credential")
		s.BadRequestWithError(w, req, errE)
		return
	}

	s.TemporaryRedirectGetMethod(w, req, location)
}
