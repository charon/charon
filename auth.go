package charon

import (
	"net/http"
	"time"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

func (s *Service) completeAuthStep(w http.ResponseWriter, req *http.Request, flow *Flow, provider, credentialID string, jsonData []byte) {
	ctx := req.Context()

	account, errE := GetAccountByCredential(ctx, provider, credentialID)
	if errors.Is(errE, ErrAccountNotFound) {
		// Sign-up. Create new account.
		account = &Account{
			ID: identifier.New(),
			Credentials: map[string][]Credential{
				provider: {{
					ID:       credentialID,
					Provider: provider,
					Data:     jsonData,
				}},
			},
		}
		errE = SetAccount(ctx, account)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	} else {
		// Sign-in. Update credential for an existing account.
		account.UpdateCredential(provider, credentialID, jsonData)
		errE = SetAccount(ctx, account)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
	}

	sessionID := identifier.New()
	errE = SetSession(ctx, &Session{
		ID:      sessionID,
		Account: account.ID,
	})
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	flow.Session = &sessionID
	flow.OIDC = nil
	flow.Passkey = nil

	errE = SetFlow(ctx, flow)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	cookie := http.Cookie{ //nolint:exhaustruct
		Name:     SessionCookieName,
		Value:    sessionID.String(),
		Path:     "/",
		Domain:   "",
		Expires:  time.Now().Add(7 * 24 * time.Hour),
		MaxAge:   0,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	s.TemporaryRedirectGetMethod(w, req, flow.Target)
}

func (s *Service) Auth(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if !s.RequireActiveFlow(w, req, false) {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}
