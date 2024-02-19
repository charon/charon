package charon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
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

const (
	PasswordProvider = "password"
	EmailProvider    = "email"
	UsernameProvider = "username"
)

type AuthFlowResponsePasswordDeriveOptions struct {
	Name       string `json:"name"`
	NamedCurve string `json:"namedCurve"`
}

type AuthFlowResponsePasswordEncryptOptions struct {
	Name      string `json:"name"`
	Nonce     []byte `json:"iv"`
	TagLength int    `json:"tagLength"`
	Length    int    `json:"length"`
}

type AuthFlowResponsePassword struct {
	PublicKey      []byte                                 `json:"publicKey"`
	DeriveOptions  AuthFlowResponsePasswordDeriveOptions  `json:"deriveOptions"`
	EncryptOptions AuthFlowResponsePasswordEncryptOptions `json:"encryptOptions"`
}

type passwordCredential struct {
	Hash string `json:"hash"`
}

type emailCredential struct {
	Email string `json:"email"`
}

type usernameCredential struct {
	Username string `json:"username"`
}

func (s *Service) normalizeEmailOrUsername(w http.ResponseWriter, req *http.Request, flow *Flow, emailOrUsername string) string {
	preservedEmailOrUsername, errE := normalizeUsernameCasePreserved(emailOrUsername)
	if errE != nil {
		s.flowError(w, req, flow, "invalidEmailOrUsername", errE)
		return ""
	}

	if len(preservedEmailOrUsername) < emailOrUsernameMinLength {
		s.flowError(w, req, flow, "shortEmailOrUsername", nil)
		return ""
	}

	return preservedEmailOrUsername
}

type AuthFlowPasswordStartRequest struct {
	EmailOrUsername string `json:"emailOrUsername"`
}

func (s *Service) AuthFlowPasswordStartPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	flow := s.GetActiveFlow(w, req, params["id"])
	if flow == nil {
		return
	}

	// Has auth step already been completed?
	if flow.Completed != "" {
		s.BadRequestWithError(w, req, errors.New("auth step already completed"))
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

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	// We create a dummy cipher so that we can obtain nonce size later on.
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

	flow.ClearAuthStep(preservedEmailOrUsername)
	flow.Provider = PasswordProvider
	flow.Password = &FlowPassword{
		PrivateKey: privateKey.Bytes(),
		Nonce:      nonce,
	}
	errE = SetFlow(req.Context(), flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Target:          flow.Target,
		Name:            flow.TargetName,
		Homepage:        flow.GetTargetHomepage(),
		OrganizationID:  flow.GetTargetOrganization(),
		Provider:        flow.Provider,
		EmailOrUsername: flow.EmailOrUsername,
		Error:           "",
		Completed:       "",
		Location:        nil,
		Passkey:         nil,
		Password: &AuthFlowResponsePassword{
			PublicKey: privateKey.PublicKey().Bytes(),
			DeriveOptions: AuthFlowResponsePasswordDeriveOptions{
				Name:       "ECDH",
				NamedCurve: "P-256",
			},
			EncryptOptions: AuthFlowResponsePasswordEncryptOptions{
				Name:      "AES-GCM",
				Nonce:     nonce,
				Length:    8 * secretSize,        //nolint:gomnd
				TagLength: 8 * aesgcm.Overhead(), //nolint:gomnd
			},
		},
	}, nil)
}

type AuthFlowPasswordCompleteRequest struct {
	PublicKey []byte `json:"publicKey"`
	Password  []byte `json:"password"`
}

func (s *Service) AuthFlowPasswordCompletePost(w http.ResponseWriter, req *http.Request, params waf.Params) { //nolint:maintidx
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	flow := s.GetActiveFlow(w, req, params["id"])
	if flow == nil {
		return
	}

	// Has auth step already been completed?
	if flow.Completed != "" {
		s.BadRequestWithError(w, req, errors.New("auth step already completed"))
		return
	}

	var passwordComplete AuthFlowPasswordCompleteRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &passwordComplete)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	ctx := req.Context()

	if flow.Password == nil {
		s.BadRequestWithError(w, req, errors.New("password not started"))
		return
	}

	flowPassword := flow.Password

	// We reset flow.Password to nil always after this point, even if there is a failure,
	// so that password cannot be reused.
	flow.Password = nil
	errE = SetFlow(ctx, flow)
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

	privateKey, err := ecdh.P256().NewPrivateKey(flowPassword.PrivateKey)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	remotePublicKey, err := ecdh.P256().NewPublicKey(passwordComplete.PublicKey)
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

	// TODO: Use memguard to protect plain password in memory.
	//       See: https://github.com/awnumar/memguard
	plainPassword, err := aesgcm.Open(nil, flowPassword.Nonce, passwordComplete.Password, nil)
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	plainPassword, errE = normalizePassword(plainPassword)
	if errE != nil {
		s.flowError(w, req, flow, "invalidPassword", errE)
		return
	}

	if len(plainPassword) < passwordMinLength {
		s.flowError(w, req, flow, "shortPassword", nil)
		return
	}

	// TODO: Use pepper by appending it to plainPassword.
	//       Support multiple and transition to the newest (first in the list) one.

	var account *Account
	if strings.Contains(mappedEmailOrUsername, "@") {
		account, errE = GetAccountByCredential(ctx, EmailProvider, mappedEmailOrUsername)
	} else {
		account, errE = GetAccountByCredential(ctx, UsernameProvider, mappedEmailOrUsername)
	}

	if errE == nil {
		// Account already exist.
		for _, credential := range account.Credentials[PasswordProvider] {
			var pc passwordCredential
			errE := x.Unmarshal(credential.Data, &pc) //nolint:govet
			if errE != nil {
				s.InternalServerErrorWithError(w, req, errE)
				return
			}

			// TODO: Use byte as input and not string.
			//       See: https://github.com/alexedwards/argon2id/issues/26
			match, options, err := argon2id.CheckHash(string(plainPassword), pc.Hash) //nolint:govet
			if err != nil {
				s.InternalServerErrorWithError(w, req, errors.WithStack(err))
				return
			}

			if match {
				// Correct password.
				jsonData := credential.Data
				// If options are different, we migrate the password to new options.
				if *options != argon2idParams {
					// TODO: Use byte as input and not string.
					//       See: https://github.com/alexedwards/argon2id/issues/26
					hashedPassword, err := argon2id.CreateHash(string(plainPassword), &argon2idParams)
					if err != nil {
						s.InternalServerErrorWithError(w, req, errors.WithStack(err))
						return
					}
					jsonData, errE = x.MarshalWithoutEscapeHTML(passwordCredential{
						Hash: hashedPassword,
					})
					if errE != nil {
						s.InternalServerErrorWithError(w, req, errE)
						return
					}
				}
				s.completeAuthStep(w, req, true, flow, account, []Credential{{
					ID:       credential.ID,
					Provider: PasswordProvider,
					Data:     jsonData,
				}})
				return
			}
		}

		// Incorrect password. We do password recovery (if possible).
		if !s.increaseAttempts(w, req, flow) {
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
		jsonData, errE := x.MarshalWithoutEscapeHTML(emailCredential{ //nolint:govet
			Email: flow.EmailOrUsername,
		})
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		credentials = append(credentials, Credential{
			ID:       mappedEmailOrUsername,
			Provider: EmailProvider,
			Data:     jsonData,
		})
	} else {
		jsonData, errE := x.MarshalWithoutEscapeHTML(usernameCredential{ //nolint:govet
			Username: flow.EmailOrUsername,
		})
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		credentials = append(credentials, Credential{
			ID:       mappedEmailOrUsername,
			Provider: UsernameProvider,
			Data:     jsonData,
		})
	}

	// TODO: Use byte as input and not string.
	//       See: https://github.com/alexedwards/argon2id/issues/26
	hashedPassword, err := argon2id.CreateHash(string(plainPassword), &argon2idParams)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(passwordCredential{
		Hash: hashedPassword,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	credentials = append(credentials, Credential{
		ID:       identifier.New().String(),
		Provider: PasswordProvider,
		Data:     jsonData,
	})

	if strings.Contains(mappedEmailOrUsername, "@") {
		// Account does not exist and we do have an e-mail address.
		// We send the code to verify the e-mail address.
		s.sendCode(w, req, flow, flow.EmailOrUsername, []string{flow.EmailOrUsername}, nil, credentials)
		return
	}

	// Account does not exist and we do not have an e-mail address.
	// We create a new username-only account.
	s.completeAuthStep(w, req, true, flow, nil, credentials)
}
