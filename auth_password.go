package charon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"net/http"
	"strings"

	"github.com/alexedwards/argon2id"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
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

type passwordCredential struct {
	Hash string `json:"hash"`
}

type emailCredential struct {
	Email string `json:"email"`
}

type usernameCredential struct {
	Username string `json:"username"`
}

func (s *Service) startPassword(w http.ResponseWriter, req *http.Request, flow *Flow) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	// TODO: What if flow.Password is already set?
	flow.Password = privateKey.Bytes()
	errE := SetFlow(req.Context(), flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
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

	s.WriteJSON(w, req, AuthFlowResponse{
		Location: nil,
		Passkey:  nil,
		Password: &AuthFlowResponsePassword{
			PublicKey: privateKey.PublicKey().Bytes(),
			DeriveOptions: AuthFlowResponsePasswordDeriveOptions{
				Name:       "ECDH",
				NamedCurve: "P-256",
			},
			EncryptOptions: AuthFlowResponsePasswordEncryptOptions{
				Name:      "AES-GCM",
				Length:    8 * secretSize, //nolint:gomnd
				NonceSize: aesgcm.NonceSize(),
				TagLength: 8 * aesgcm.Overhead(), //nolint:gomnd
			},
		},
		Code: false,
	}, nil)
}

func (s *Service) completePassword(w http.ResponseWriter, req *http.Request, flow *Flow, requestPassword *AuthFlowRequestPassword) { //nolint:maintidx
	ctx := req.Context()

	if flow.Password == nil {
		s.BadRequestWithError(w, req, errors.New("password not started"))
		return
	}

	flowPassword := flow.Password

	// We reset flow.Password to nil always after this point, even if there is a failure,
	// so that key cannot be reused.
	flow.Password = nil
	errE := SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	preservedEmailOrUsername, errE := normalizeUsernameCasePreserved(requestPassword.EmailOrUsername)
	if errE != nil {
		// TODO: Show reasonable error to the user (not the error message itself).
		s.BadRequestWithError(w, req, errE)
		return
	}
	mappedEmailOrUsername, errE := normalizeUsernameCaseMapped(requestPassword.EmailOrUsername)
	if errE != nil {
		// TODO: Show reasonable error to the user (not the error message itself).
		s.BadRequestWithError(w, req, errE)
		return
	}

	privateKey, err := ecdh.P256().NewPrivateKey(flowPassword)
	if err != nil {
		s.InternalServerErrorWithError(w, req, errors.WithStack(err))
		return
	}

	remotePublicKey, err := ecdh.P256().NewPublicKey(requestPassword.PublicKey)
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

	if len(requestPassword.Nonce) != aesgcm.NonceSize() {
		errE = errors.New("invalid nonce size")
		errors.Details(errE)["want"] = aesgcm.NonceSize()
		errors.Details(errE)["got"] = len(requestPassword.Nonce)
		s.BadRequestWithError(w, req, errE)
		return
	}

	plainPassword, err := aesgcm.Open(nil, requestPassword.Nonce, requestPassword.Password, nil)
	if err != nil {
		s.BadRequestWithError(w, req, errors.WithStack(err))
		return
	}

	plainPassword, errE = normalizePassword(plainPassword)
	if errE != nil {
		// TODO: Show reasonable error to the user (not the error message itself).
		s.BadRequestWithError(w, req, errE)
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
		s.sendCodeForExistingAccount(w, req, flow, account, mappedEmailOrUsername)
		return
	} else if !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// Account does not exist.

	credentials := []Credential{}
	if strings.Contains(mappedEmailOrUsername, "@") {
		jsonData, errE := x.MarshalWithoutEscapeHTML(emailCredential{ //nolint:govet
			Email: preservedEmailOrUsername,
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
			Username: preservedEmailOrUsername,
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
		Provider: PasskeyProvider,
		Data:     jsonData,
	})

	if strings.Contains(mappedEmailOrUsername, "@") {
		s.sendCodeForNewAccount(w, req, flow, preservedEmailOrUsername, credentials)
		return
	}

	// Account does not exist and we do not have an e-mail address.
	// We create a new username-only account.
	s.completeAuthStep(w, req, true, flow, nil, credentials)
}
