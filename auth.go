package charon

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/waf"
)

// AuthSignoutRequest represents the request body for the AuthSignoutPost handler.
type AuthSignoutRequest struct {
	Location string `json:"location"`
}

// AuthSignoutResponse represents the response body for the AuthSignoutPost handler.
type AuthSignoutResponse struct {
	Location string `json:"location"`
}

// TODO: Allow specifying that a) provider who signed the user in should be signed out as well b) all providers user is known with is signed out as well.

// TODO: Revoke all access tokens associated with any sessions associated with available cookies.

// AuthSignoutPost is the API handler for sign-out, POST request.
func (s *Service) AuthSignoutPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()              //nolint:errcheck
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	var authSignoutRequest AuthSignoutRequest
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &authSignoutRequest)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	location, errE := validRedirectLocation(s, authSignoutRequest.Location)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	ctx := req.Context()

	// We clear all session cookies for all flows.
	for _, cookie := range req.Cookies() {
		if strings.HasPrefix(cookie.Name, sessionCookiePrefix) {
			// We create a new cookie based on the existing one, but set MaxAge to -1 to clear it.
			deleteCookie := &http.Cookie{ //nolint:exhaustruct
				Name:     cookie.Name,
				Value:    "",
				Path:     "/", // Host cookies have to have path set to "/".
				Domain:   "",
				Expires:  time.Time{},
				MaxAge:   -1,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}
			http.SetCookie(w, deleteCookie)
			session, errE := s.getSessionFromCookieValue(ctx, cookie.Value)
			if errE != nil {
				continue
			}
			errE = s.disableSession(ctx, session.ID)
			if errE != nil {
				s.InternalServerErrorWithError(w, req, errE)
				return
			}
		}
	}

	token := getBearerToken(req)
	if token != "" {
		// TODO: This should all (revocation and activity logging) work also when access token provided is for some other app, not only for Charon Dashboard.

		co := s.charonOrganization()

		// Log sign-out activity.
		identityID, accountID, sessionID, errE := s.getIdentityFromRequest(w, req, co.AppID.String())
		if errE == nil {
			c := s.withAccountID(ctx, accountID)
			c = s.withIdentityID(c, identityID)
			c = s.withSessionID(c, sessionID)
			errE = s.logActivity(c, ActivitySignOut, nil, nil, nil, nil, nil, nil, nil, OrganizationRef{ID: co.ID})
			if errE != nil {
				s.InternalServerErrorWithError(w, req, errE)
				return
			}
		}

		// OIDC GetClient requires ctx with serviceContextKey set.
		ctx = context.WithValue(ctx, serviceContextKey, s)
		oidc := s.oidc()

		revoke, errE := s.ReverseAPI("OIDCRevoke", nil, nil)
		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, revoke, strings.NewReader(url.Values{
			"client_id":       {co.ClientID.String()},
			"token":           {token},
			"token_type_hint": {"access_token"},
		}.Encode()))
		if err != nil {
			s.InternalServerErrorWithError(w, req, errors.WithStack(err))
			return
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		err = oidc.NewRevocationRequest(ctx, r)
		if err != nil {
			s.InternalServerErrorWithError(w, req, errors.WithStack(err))
			return
		}
	}

	s.WriteJSON(w, req, AuthSignoutResponse{
		Location: location,
	}, nil)
}
