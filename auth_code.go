package charon

import (
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	tt "text/template"
	"unicode"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

//nolint:revive
const ProviderCode Provider = "code"

const (
	codeProviderSubject  = `Your code for Charon`
	codeProviderTemplate = `Hi!

Here is the code to complete your Charon sign-in or sign-up:

{{.code}}

You can also open:

{{.url}}
`
)

type codeProvider struct {
	origin string
}

func (p *codeProvider) URL(s *Service, flow *flow, code string) (string, errors.E) {
	path, errE := s.Reverse("AuthFlowGet", waf.Params{"id": flow.ID.String()}, nil)
	if errE != nil {
		return "", errE
	}
	return fmt.Sprintf("%s%s#code=%s", p.origin, path, code), nil
}

func initCodeProvider(config *Config, domain string) (func() *codeProvider, errors.E) {
	return initWithHost(config, domain, func(host string) *codeProvider {
		return &codeProvider{
			origin: "https://" + host,
		}
	})
}

var codeProviderTemplateCompiled = tt.Must(tt.New("CodeProviderTemplate").Parse(codeProviderTemplate)) //nolint:gochecknoglobals

var errMultipleCredentials = errors.Base("multiple credentials for the provider")

func getCredentialByProvider(credentials []Credential, provider Provider) (*Credential, errors.E) {
	var credential *Credential
	for _, c := range credentials {
		if c.Provider == provider {
			if credential != nil {
				// More than one credential for the provider, there should be at most one.
				return nil, errors.WithStack(errMultipleCredentials)
			}
			credential = &c
		}
	}
	return credential, nil
}

func emailCredentialsEqual(credentialsA, credentialsB []Credential) bool {
	emailCredentialA, errE := getCredentialByProvider(credentialsA, ProviderEmail)
	if errE != nil {
		// More than one e-mail credential, there should be at most one.
		return false
	}

	emailCredentialB, errE := getCredentialByProvider(credentialsB, ProviderEmail)
	if errE != nil {
		// More than one e-mail credential, there should be at most one.
		return false
	}

	// If credentialsA and credentialsB are nil, then also emailCredentialA
	// and emailCredentialB are nil and comparison returns true.
	return emailCredentialA.Equal(emailCredentialB)
}

func updateCredentialsByProvider(existingCredentials, newCredentials []Credential) ([]Credential, errors.E) {
	existingEmailCredential, errE := getCredentialByProvider(existingCredentials, ProviderEmail)
	if errE != nil {
		// More than one e-mail credential, there should be at most one.
		return nil, errE
	}

	newEmailCredential, errE := getCredentialByProvider(newCredentials, ProviderEmail)
	if errE != nil {
		// More than one e-mail credential, there should be at most one.
		return nil, errE
	}

	if !existingEmailCredential.Equal(newEmailCredential) {
		// This should have already been checked.
		return nil, errors.New("e-mail credentials not equal, but they should be")
	}

	if len(existingCredentials) > 2 || len(newCredentials) > 2 {
		// There should be at most two credentials (e-mail and password).
		return nil, errors.New("more than two credentials")
	}

	existingPasswordCredential, errE := getCredentialByProvider(existingCredentials, ProviderPassword)
	if errE != nil {
		// More than one password credential, there should be at most one.
		return nil, errE
	}

	newPasswordCredential, errE := getCredentialByProvider(newCredentials, ProviderPassword)
	if errE != nil {
		// More than one password credential, there should be at most one.
		return nil, errE
	}

	var updatedCredentials []Credential
	// E-mail credential is copied over.
	if newEmailCredential != nil {
		// It does not matter if we use newEmailCredential or existingEmailCredential
		// because they are equal at this point.
		updatedCredentials = append(updatedCredentials, *newEmailCredential)
	}

	// New password credential is preferred over the existing one (which might not exist).
	if newPasswordCredential != nil {
		updatedCredentials = append(updatedCredentials, *newPasswordCredential)
	} else if existingPasswordCredential != nil {
		updatedCredentials = append(updatedCredentials, *existingPasswordCredential)
	}

	return updatedCredentials, nil
}

func (s *Service) sendCodeForExistingAccount(
	w http.ResponseWriter, req *http.Request, flow *flow, passwordFlow bool,
	account *Account, preservedEmailOrUsername, mappedEmailOrUsername string,
) {
	var emails []string
	if strings.Contains(mappedEmailOrUsername, "@") {
		// We know that such credential must exist on this account because
		// we found this account using mappedEmailOrUsername.
		credential := account.GetCredential(ProviderEmail, mappedEmailOrUsername)
		var ec emailCredential
		errE := x.Unmarshal(credential.Data, &ec)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		emails = []string{ec.Email}
	} else {
		// mappedEmailOrUsername is an username. Let's see if there are any
		// e-mails associated with the account.
		var errE errors.E
		emails, errE = account.GetEmailAddresses()
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		if len(emails) == 0 {
			var code ErrorCode
			if passwordFlow {
				code = ErrorCodeWrongPassword
			} else {
				code = ErrorCodeNoEmails
			}
			s.flowError(w, req, flow, code, nil)
			return
		}
	}

	s.sendCode(w, req, flow, passwordFlow, preservedEmailOrUsername, emails, &account.ID, nil)
}

func (s *Service) sendCode(
	w http.ResponseWriter, req *http.Request, flow *flow, passwordFlow bool,
	preservedEmailOrUsername string, emails []string, accountID *identifier.Identifier, credentials []Credential,
) {
	if len(emails) == 0 {
		// Internal error: this method should no be called without e-mail addresses.
		panic(errors.New("no email addresses"))
	}
	if accountID == nil && credentials == nil || accountID != nil && credentials != nil {
		// Internal error: this should never happen.
		panic(errors.New("accountID and credentials both nil or both not"))
	}

	code, errE := getRandomCode()
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// In an ideal world, the user should be able to use any code they find in their e-mails for the flow ID they are currently on.
	// But in practice that might be misused, e.g., a user starts the code provider with e-mail foo@example.com, get a code for it,
	// then request another code with e-mail bar@example.com, and then provide a code from foo@example.com to validate bar@example.com,
	// without really having access to bar@example.com. To prevent that, we clear code provider state if flow.EmailOrUsername changes.
	// This means that if user starts with bar@example.com, tries foo@example.com, and then go back to bar@example.com, all inside
	// the same flow, code(s) from the first bar@example.com attempt will not work anymore. That is probably fine and rare.
	flow.ClearAuthStep(preservedEmailOrUsername)
	if passwordFlow {
		flow.Providers = append(flow.Providers, ProviderCode)
	} else {
		flow.Providers = []Provider{ProviderCode}
	}
	// Or flow.Code was never set or it was cleared by flow.Clear because flow.EmailOrUsername changed.
	// Or account ID has changed (this is an edge case and sanity check because flow.Clear should already
	// set flow.Code to nil if flow.EmailOrUsername changed and it is very rare that account for unchanged
	// flow.EmailOrUsername would change between calls, but it can and we check).
	// Or new e-mail credentials do not match existing e-mail credentials. In the common case that code is requested
	// again for non-existent password-provided account, new request has only e-mail credential while existing
	// credentials have also password. In that case we want to keep existing code provider state and add a new code to it.
	// But we want to do that only if new e-mail credential matches the existing e-mail credential. That should
	// generally be true if flow.EmailOrUsername has not changed (and if it did, flow.Clear would already clear
	// flow.Code), but we want to be sure and do a sanity check here.
	if flow.Code == nil || !pointerEqual(flow.Code.AccountID, accountID) || !emailCredentialsEqual(flow.Code.Credentials, credentials) {
		// flow.EmailOrUsername is set already in flow.Clear, even the first time,
		// but we want to be sure so we set it again here.
		flow.EmailOrUsername = preservedEmailOrUsername
		flow.Code = &flowCode{
			Codes:       []string{},
			AccountID:   accountID,
			Credentials: credentials,
		}
	} else if credentials != nil {
		// It could happen that the user first initiated the code provider by not providing a password but then decided to go back and add a password
		// which then (for non-existent accounts) continue into the code provider, so we want to update credentials with the password.
		flow.Code.Credentials, errE = updateCredentialsByProvider(flow.Code.Credentials, credentials)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
	}
	flow.Code.Codes = append(flow.Code.Codes, code)
	errE = s.setFlow(req.Context(), flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	url, errE := s.codeProvider().URL(s, flow, code)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	errE = s.sendMail(req.Context(), flow, emails, codeProviderSubject, codeProviderTemplateCompiled, map[string]string{
		"code": code,
		"url":  url,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, AuthFlowResponse{
		Completed:          flow.Completed,
		OrganizationID:     flow.OrganizationID,
		AppID:              flow.AppID,
		Providers:          flow.Providers,
		EmailOrUsername:    preservedEmailOrUsername,
		ThirdPartyProvider: nil,
		Passkey:            nil,
		Password:           nil,
		Error:              "",
	}, nil)
}

// AuthFlowCodeStartRequest represents the request body for the AuthFlowCodeStartPost handler.
type AuthFlowCodeStartRequest struct {
	EmailOrUsername string `json:"emailOrUsername"`
}

// AuthFlowCodeStartPost is the API handler to start the code provider step, POST request.
func (s *Service) AuthFlowCodeStartPost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	flow := s.getActiveFlowNoAuthStep(w, req, params["id"])
	if flow == nil {
		return
	}

	var codeStart AuthFlowCodeStartRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &codeStart)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	preservedEmailOrUsername := s.normalizeEmailOrUsername(w, req, flow, codeStart.EmailOrUsername)
	if preservedEmailOrUsername == "" {
		return
	}
	mappedEmailOrUsername, errE := normalizeUsernameCaseMapped(preservedEmailOrUsername)
	if errE != nil {
		// preservedEmailOrUsername should already be normalized (but not mapped) so this should not error.
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	var account *Account
	if strings.Contains(mappedEmailOrUsername, "@") {
		account, errE = s.getAccountByCredential(ctx, ProviderEmail, mappedEmailOrUsername)
	} else {
		account, errE = s.getAccountByCredential(ctx, ProviderUsername, mappedEmailOrUsername)
	}

	if errE == nil {
		// Account already exist.
		s.sendCodeForExistingAccount(w, req, flow, false, account, preservedEmailOrUsername, mappedEmailOrUsername)
		return
	} else if !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// Account does not exist.

	// We can send a code only if we have an e-mail address.
	if !strings.Contains(mappedEmailOrUsername, "@") {
		s.flowError(w, req, flow, ErrorCodeNoAccount, nil)
		return
	}

	jsonData, errE := x.MarshalWithoutEscapeHTML(emailCredential{
		Email: preservedEmailOrUsername,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}
	credentials := []Credential{{
		ID:       mappedEmailOrUsername,
		Provider: ProviderEmail,
		Data:     jsonData,
	}}

	// Account does not exist but we have an e-mail address.
	// We attempt to create a new account with an e-mail address only.
	s.sendCode(w, req, flow, false, preservedEmailOrUsername, []string{preservedEmailOrUsername}, nil, credentials)
}

// AuthFlowCodeCompleteRequest represents the request body for the AuthFlowCodeCompletePost handler.
type AuthFlowCodeCompleteRequest struct {
	Code string `json:"code"`
}

// AuthFlowCodeCompletePost is the API handler to complete the code provider step, POST request.
func (s *Service) AuthFlowCodeCompletePost(w http.ResponseWriter, req *http.Request, params waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := req.Context()

	flow := s.getActiveFlowNoAuthStep(w, req, params["id"])
	if flow == nil {
		return
	}

	if flow.Code == nil {
		s.BadRequestWithError(w, req, errors.New("code not started"))
		return
	}

	var codeComplete AuthFlowCodeCompleteRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &codeComplete)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	// We clean the provided code of all whitespace (not just at the beginning and end) before we check it.
	code := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, codeComplete.Code)

	if !slices.Contains(flow.Code.Codes, code) {
		if !s.increaseAuthAttempts(w, req, flow) {
			return
		}
		s.flowError(w, req, flow, ErrorCodeInvalidCode, nil)
		return
	}

	var account *Account
	if flow.Code.AccountID != nil {
		var errE errors.E
		account, errE = s.getAccount(ctx, *flow.Code.AccountID)
		if errE != nil {
			// We return internal server error even on ErrAccountNotFound. It is unlikely that
			// the account got deleted in meantime so there might be some logic error. In any
			// case it does not matter too much which error we return.
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
	}

	s.completeAuthStep(w, req, true, flow, account, flow.Code.Credentials)
}
