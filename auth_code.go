package charon

import (
	"net/http"
	"strings"
	"unicode"

	"github.com/rs/zerolog/hlog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

const CodeProvider Provider = "code"

type AuthFlowRequestCodeStart struct {
	EmailOrUsername string `json:"emailOrUsername"`
}

type AuthFlowRequestCodeComplete struct {
	Code string `json:"code"`
}

type AuthFlowRequestCode struct {
	Start    *AuthFlowRequestCodeStart    `json:"start,omitempty"`
	Complete *AuthFlowRequestCodeComplete `json:"complete,omitempty"`
}

type AuthFlowResponseCode struct {
	EmailOrUsername string `json:"emailOrUsername"`
}

func (s *Service) sendCodeForExistingAccount(
	w http.ResponseWriter, req *http.Request, flow *Flow,
	account *Account, preservedEmailOrUsername, mappedEmailOrUsername string,
) {
	var emails []string
	if strings.Contains(mappedEmailOrUsername, "@") {
		// We know that such credential must exist on this account because
		// we found this account using mappedEmailOrUsername.
		credential := account.GetCredential(EmailProvider, mappedEmailOrUsername)
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
	}

	s.sendCode(w, req, flow, preservedEmailOrUsername, emails, &account.ID, nil)
}

func (s *Service) sendCodeForNewAccount(w http.ResponseWriter, req *http.Request, flow *Flow, preservedEmailOrUsername string, credentials []Credential) {
	var emails []string
	if strings.Contains(preservedEmailOrUsername, "@") {
		emails = []string{preservedEmailOrUsername}
	}

	s.sendCode(w, req, flow, preservedEmailOrUsername, emails, nil, credentials)
}

func (s *Service) sendCode(
	w http.ResponseWriter, req *http.Request, flow *Flow,
	preservedEmailOrUsername string, emails []string, accountID *identifier.Identifier, credentials []Credential,
) {
	if len(emails) == 0 {
		// User provided an invalid password and there are no e-mails available, or code request for
		// account without e-mails available, or code request for account which does not exist.
		// TODO: Return a better response?
		waf.Error(w, req, http.StatusUnauthorized)
		return
	}

	code, errE := getRandomCode()
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// TODO: This makes only the latest code work. Should we allow previous codes as well?
	flow.Reset()
	flow.Code = &FlowCode{
		EmailOrUsername: preservedEmailOrUsername,
		Code:            code,
		Account:         accountID,
		Credentials:     credentials,
	}
	errE = SetFlow(req.Context(), flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// TODO: Send e-mails.
	hlog.FromRequest(req).Info().Str("code", code).Strs("emails", emails).Msg("sending code")

	s.WriteJSON(w, req, AuthFlowResponse{
		Error:    "",
		Location: nil,
		Passkey:  nil,
		Password: nil,
		Code: &AuthFlowResponseCode{
			EmailOrUsername: preservedEmailOrUsername,
		},
	}, nil)
}

func (s *Service) startCode(w http.ResponseWriter, req *http.Request, flow *Flow, codeStart *AuthFlowRequestCodeStart) {
	ctx := req.Context()

	preservedEmailOrUsername, errE := normalizeUsernameCasePreserved(codeStart.EmailOrUsername)
	if errE != nil {
		// TODO: Improve message (check if username or e-mail).
		s.flowError(w, req, http.StatusBadRequest, "Invalid Charon username or your e-mail address.", errE)
		return
	}
	mappedEmailOrUsername, errE := normalizeUsernameCaseMapped(preservedEmailOrUsername)
	if errE != nil {
		// preservedEmailOrUsername should already be normalized (but not mapped)
		// so this should not error.
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	var account *Account
	if strings.Contains(mappedEmailOrUsername, "@") {
		account, errE = GetAccountByCredential(ctx, EmailProvider, mappedEmailOrUsername)
	} else {
		account, errE = GetAccountByCredential(ctx, UsernameProvider, mappedEmailOrUsername)
	}

	if errE == nil {
		// Account already exist.
		s.sendCodeForExistingAccount(w, req, flow, account, preservedEmailOrUsername, mappedEmailOrUsername)
		return
	} else if !errors.Is(errE, ErrAccountNotFound) {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// Account does not exist.

	// We have to create a credential only for the e-mail case.
	// sendCodeForNewAccount will error out on the username case.
	var credentials []Credential
	if strings.Contains(mappedEmailOrUsername, "@") {
		jsonData, errE := x.MarshalWithoutEscapeHTML(emailCredential{
			Email: preservedEmailOrUsername,
		})
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		credentials = []Credential{{
			ID:       mappedEmailOrUsername,
			Provider: EmailProvider,
			Data:     jsonData,
		}}
	}

	// Account does not exist but we might have an e-mail address.
	// We attempt to create a new account with an e-mail address only.
	// We call sendCodeForNewAccount always and leave to sendCodeForNewAccount
	// to error out if we have just an username and not an e-mail address.
	s.sendCodeForNewAccount(w, req, flow, preservedEmailOrUsername, credentials)
}

func (s *Service) completeCode(w http.ResponseWriter, req *http.Request, flow *Flow, codeComplete *AuthFlowRequestCodeComplete) {
	ctx := req.Context()

	if flow.Code == nil {
		s.BadRequestWithError(w, req, errors.New("code not started"))
		return
	}

	flowCode := flow.Code

	// We reset flow.Code to nil always after this point, even if there is a failure,
	// so that code cannot be reused.
	flow.Code = nil
	errE := SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// We clean the provided code of all whitespace before we check it.
	code := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, codeComplete.Code)

	if flowCode.Code != code {
		// TODO: Return a better response?
		waf.Error(w, req, http.StatusUnauthorized)
		return
	}

	var account *Account
	if flowCode.Account != nil {
		account, errE = GetAccount(ctx, *flowCode.Account)
		if errE != nil {
			// We return internal server error even on ErrAccountNotFound. It is unlikely that
			// the account got deleted in meantime so there might be some logic error. In any
			// case it does not matter to much which error we return.
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
	}

	s.completeAuthStep(w, req, true, flow, account, flowCode.Credentials)
}
