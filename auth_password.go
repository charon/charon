package charon

import (
	"io"
	"net/http"
	"strings"

	"github.com/alexedwards/argon2id"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

const (
	// Values based on OWASP recommendations.
	// See: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html.
	argon2idMemory  = 19 * 1024
	argon2idTime    = 2
	argon2idThreads = 1

	// Size of the secret returned by P256.PrivateKey.ECDH() call.
	secretSize = 32

	saltSize = 16
	keySize  = 32

	emailOrUsernameMinLength = 3
	passwordMinLength        = 8
)

var argon2idParams = argon2id.Params{ //nolint:gochecknoglobals
	Memory:      argon2idMemory,
	Iterations:  argon2idTime,
	Parallelism: argon2idThreads,
	SaltLength:  saltSize,
	KeyLength:   keySize,
}

//nolint:revive
const (
	ProviderPassword Provider = "password"
	ProviderEmail    Provider = "email"
	ProviderUsername Provider = "username"
)

// AuthFlowResponsePasswordDeriveOptions represents options for deriving the key for encrypting the password.
type AuthFlowResponsePasswordDeriveOptions struct {
	Name       string `json:"name"`
	NamedCurve string `json:"namedCurve"`
}

// AuthFlowResponsePasswordEncryptOptions represents options for encrypting the password with the derived key.
type AuthFlowResponsePasswordEncryptOptions struct {
	Name      string `json:"name"`
	Nonce     []byte `json:"iv"`
	TagLength int    `json:"tagLength"`
	Length    int    `json:"length"`
}

// AuthFlowResponsePassword represents response data of the password provider step.
type AuthFlowResponsePassword struct {
	PublicKey      []byte                                 `json:"publicKey"`
	DeriveOptions  AuthFlowResponsePasswordDeriveOptions  `json:"deriveOptions"`
	EncryptOptions AuthFlowResponsePasswordEncryptOptions `json:"encryptOptions"`
}

type passwordCredential struct {
	Hash  string `json:"hash"`
	Label string `json:"label"`
}

type emailCredential struct {
	Email string `json:"email"`
}

type usernameCredential struct {
	Username string `json:"username"`
}

func (s *Service) normalizeEmailOrUsername(w http.ResponseWriter, req *http.Request, flow *flow, emailOrUsername string) string {
	preservedEmailOrUsername, errE := normalizeUsernameCasePreserved(emailOrUsername)
	if errE != nil {
		s.flowError(w, req, flow, ErrorCodeInvalidEmailOrUsername, errE)
		return ""
	}

	if len(preservedEmailOrUsername) < emailOrUsernameMinLength {
		s.flowError(w, req, flow, ErrorCodeShortEmailOrUsername, nil)
		return ""
	}

	return preservedEmailOrUsername
}

// AuthFlowPasswordStartRequest represents the request body for the AuthFlowPasswordStartPost handler.
type AuthFlowPasswordStartRequest struct {
	EmailOrUsername string `json:"emailOrUsername"`
}

// AuthFlowPasswordStartPost is the API handler to start the password provider step, POST request.
func (s *Service) AuthFlowPasswordStartPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	flow := s.getActiveFlowNoAuthStep(w, req, params["id"])
	if flow == nil {
		return
	}

	var passwordStart AuthFlowPasswordStartRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &passwordStart)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	preservedEmailOrUsername := s.normalizeEmailOrUsername(w, req, flow, passwordStart.EmailOrUsername)
	if preservedEmailOrUsername == "" {
		return
	}

	privateKeyBytes, publicKeyBytes, nonce, overhead, errE := generatePasswordEncryptionKeys()
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	flow.ClearAuthStep(preservedEmailOrUsername)
	// Currently we support only one factor.
	flow.Providers = []Provider{ProviderPassword}
	flow.Password = &flowPassword{
		PrivateKey: privateKeyBytes,
		Nonce:      nonce,
	}
	errE = s.setFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Completed:          flow.Completed,
		OrganizationID:     flow.OrganizationID,
		AppID:              flow.AppID,
		Providers:          flow.Providers,
		EmailOrUsername:    flow.EmailOrUsername,
		ThirdPartyProvider: nil,
		Passkey:            nil,
		Password:           newPasswordEncryptionResponse(publicKeyBytes, nonce, overhead),
		Error:              "",
	}, nil)
}

// AuthFlowPasswordCompleteRequest represents the request body for the AuthFlowPasswordCompletePost handler.
type AuthFlowPasswordCompleteRequest struct {
	PublicKey []byte `json:"publicKey"`
	Password  []byte `json:"password"`
}

// AuthFlowPasswordCompletePost is the API handler to complete the password provider step, POST request.
func (s *Service) AuthFlowPasswordCompletePost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	flow := s.getActiveFlowNoAuthStep(w, req, params["id"])
	if flow == nil {
		return
	}

	if flow.Password == nil {
		s.BadRequestWithError(w, req, errors.New("password not started"))
		return
	}

	var passwordComplete AuthFlowPasswordCompleteRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &passwordComplete)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	flowPassword := flow.Password

	// We reset flow.Password to nil always after this point, even if there is a failure,
	// so that password cannot be reused.
	flow.Password = nil
	errE = s.setFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	mappedEmailOrUsername, errE := normalizeUsernameCaseMapped(flow.EmailOrUsername)
	if errE != nil {
		// flowPassword.EmailOrUsername should already be normalized (but not mapped) so this should not error.
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	plainPassword, errE := decryptPasswordECDHAESGCM(
		flowPassword.PrivateKey,
		passwordComplete.PublicKey,
		flowPassword.Nonce,
		passwordComplete.Password)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
	}

	plainPassword, errE = normalizePassword(plainPassword)
	if errE != nil {
		s.flowError(w, req, flow, ErrorCodeInvalidPassword, errE)
		return
	}

	if len(plainPassword) < passwordMinLength {
		s.flowError(w, req, flow, ErrorCodeShortPassword, nil)
		return
	}

	// TODO: Use pepper by appending it to plainPassword.
	//       Support multiple and transition to the newest (first in the list) one.

	var account *Account
	if strings.Contains(mappedEmailOrUsername, "@") {
		account, errE = s.getAccountByCredential(ctx, ProviderEmail, mappedEmailOrUsername)
	} else {
		account, errE = s.getAccountByCredential(ctx, ProviderUsername, mappedEmailOrUsername)
	}

	if errE == nil {
		// Account already exist.
		for _, credential := range account.Credentials[ProviderPassword] {
			var pc passwordCredential
			errE := x.Unmarshal(credential.Data, &pc)
			if errE != nil {
				s.InternalServerErrorWithError(w, req, errE)
				return
			}

			match, options, err := argon2id.CheckHash(plainPassword, pc.Hash)
			if err != nil {
				s.InternalServerErrorWithError(w, req, errors.WithStack(err))
				return
			}

			if match {
				// Correct password.
				jsonData := credential.Data
				// If options are different, we migrate the password to new options.
				if *options != argon2idParams {
					hashedPassword, err := argon2id.CreateHash(plainPassword, &argon2idParams)
					if err != nil {
						s.InternalServerErrorWithError(w, req, errors.WithStack(err))
						return
					}
					jsonData, errE = x.MarshalWithoutEscapeHTML(passwordCredential{
						Hash:  hashedPassword,
						Label: "",
					})
					if errE != nil {
						s.InternalServerErrorWithError(w, req, errE)
						return
					}
				}
				s.completeAuthStep(w, req, true, flow, account, []Credential{{
					ID:         credential.ID,
					ProviderID: credential.ProviderID,
					Provider:   ProviderPassword,
					Data:       jsonData,
				}})
				return
			}
		}

		// Incorrect password. We do password recovery (if possible).
		if !s.increaseAuthAttempts(w, req, flow) {
			return
		}
		s.sendCodeForExistingAccount(w, req, flow, true, account, flow.EmailOrUsername, mappedEmailOrUsername)
		return
	} else if !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// Account does not exist.

	credentials := []Credential{}
	if strings.Contains(mappedEmailOrUsername, "@") {
		jsonData, errE := x.MarshalWithoutEscapeHTML(emailCredential{
			Email: flow.EmailOrUsername,
		})
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		credentials = append(credentials, Credential{
			ID:         identifier.New(),
			ProviderID: mappedEmailOrUsername,
			Provider:   ProviderEmail,
			Data:       jsonData,
		})
	} else {
		jsonData, errE := x.MarshalWithoutEscapeHTML(usernameCredential{
			Username: flow.EmailOrUsername,
		})
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		credentials = append(credentials, Credential{
			ID:         identifier.New(),
			ProviderID: mappedEmailOrUsername,
			Provider:   ProviderUsername,
			Data:       jsonData,
		})
	}

	hashedPassword, err := argon2id.CreateHash(plainPassword, &argon2idParams)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(passwordCredential{
		Hash:  hashedPassword,
		Label: "",
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	credentials = append(credentials, Credential{
		ID:         identifier.New(),
		ProviderID: identifier.New().String(),
		Provider:   ProviderPassword,
		Data:       jsonData,
	})

	if strings.Contains(mappedEmailOrUsername, "@") {
		// Account does not exist and we do have an e-mail address.
		// We send the code to verify the e-mail address.
		s.sendCode(w, req, flow, true, flow.EmailOrUsername, []string{flow.EmailOrUsername}, nil, credentials)
		return
	}

	// Account does not exist and we do not have an e-mail address.
	// We create a new username-only account.
	s.completeAuthStep(w, req, true, flow, nil, credentials)
}
