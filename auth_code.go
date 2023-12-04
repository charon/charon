package charon

import (
	"net/http"
	"strings"

	"github.com/rs/zerolog/hlog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

func (s *Service) sendCodeForExistingAccount(w http.ResponseWriter, req *http.Request, flow *Flow, account *Account, mappedEmailOrUsername string) {
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

	if len(emails) == 0 {
		// User provided an invalid password and there are no e-mails available.
		// TODO: Return a better response?
		waf.Error(w, req, http.StatusUnauthorized)
		return
	}

	s.sendCode(w, req, flow, emails, &account.ID, nil)
}

func (s *Service) sendCodeForNewAccount(w http.ResponseWriter, req *http.Request, flow *Flow, preservedEmail string, credentials []Credential) {
	if !strings.Contains(preservedEmail, "@") {
		panic(errors.New("preservedEmail is not an e-mail address"))
	}

	emails := []string{preservedEmail}

	s.sendCode(w, req, flow, emails, nil, credentials)
}

func (s *Service) sendCode(w http.ResponseWriter, req *http.Request, flow *Flow, emails []string, accountID *identifier.Identifier, credentials []Credential) {
	code, errE := getRandomCode()
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// TODO: What if flow.Code is already set?
	flow.Code = &FlowCode{
		Code:        code,
		Account:     accountID,
		Credentials: credentials,
	}
	errE = SetFlow(req.Context(), flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	// TODO: Send e-mails.
	hlog.FromRequest(req).Info().Str("code", code).Strs("emails", emails).Msg("sending code")

	s.WriteJSON(w, req, AuthFlowResponse{
		Location: nil,
		Passkey:  nil,
		Password: nil,
		Code:     true,
	}, nil)
}
