package charon

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"slices"
	"sync"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

var (
	ErrIdentityNotFound         = errors.Base("identity not found")
	ErrIdentityAlreadyExists    = errors.Base("identity already exists")
	ErrIdentityUnauthorized     = errors.Base("identity change unauthorized")
	ErrIdentityValidationFailed = errors.Base("identity validation failed")
)

var (
	identities   = make(map[identifier.Identifier][]byte) //nolint:gochecknoglobals
	identitiesMu = sync.RWMutex{}                         //nolint:gochecknoglobals
)

type Identity struct {
	ID *identifier.Identifier `json:"id"`

	Username   string `json:"username"`
	Email      string `json:"email"`
	GivenName  string `json:"givenName"`
	FullName   string `json:"fullName"`
	PictureURL string `json:"pictureUrl"`

	Description string `json:"description"`

	Admins []AccountRef `json:"admins,omitempty"`
}

type IdentityRef struct {
	ID identifier.Identifier `json:"id"`
}

func (i *Identity) Validate(ctx context.Context, existing *Identity) errors.E { 
	if existing == nil {
		if i.ID != nil {
			errE := errors.New("ID provided for new document")
			errors.Details(errE)["id"] = *i.ID
			return errE
		}
		id := identifier.New()
		i.ID = &id
	} else if i.ID == nil {
		// This should not really happen because we fetch existing based on i.ID.
		return errors.New("ID missing for existing document")
	} else if existing.ID == nil {
		// This should not really happen because we always store documents with ID.
		return errors.New("ID missing for existing document")
	} else if *i.ID != *existing.ID {
		// This should not really happen because we fetch existing based on i.ID.
		errE := errors.New("payload ID does not match existing ID")
		errors.Details(errE)["payload"] = *i.ID
		errors.Details(errE)["existing"] = *existing.ID
		return errE
	}

	if i.Username != "" {
		username, errE := normalizeUsernameCasePreserved(i.Username)
		if errE != nil {
			errE = errors.WithMessage(errE, "username")
			errors.Details(errE)["username"] = i.Username
			return errE
		}

		if len(username) < emailOrUsernameMinLength {
			errE := errors.New("username too short")
			errors.Details(errE)["username"] = i.Username
			return errE
		}

		i.Username = username
	}

	// TODO: E-mails should be possible to be only those which have been validated.

	if i.Email != "" {
		email, errE := normalizeUsernameCasePreserved(i.Email)
		if errE != nil {
			errE = errors.WithMessage(errE, "e-mail")
			errors.Details(errE)["email"] = i.Email
			return errE
		}

		if len(email) < emailOrUsernameMinLength {
			errE := errors.New("e-mail too short")
			errors.Details(errE)["email"] = i.Email
			return errE
		}

		i.Email = email
	}

	// TODO: Normalize GivenName and FullName.

	if i.PictureURL != "" {
		errE := validateURI(ctx, i.PictureURL)
		if errE != nil {
			return errors.WithMessage(errE, "picture URL")
		}
	}

	account := mustGetAccount(ctx)
	accountRef := AccountRef{account}
	if !slices.Contains(i.Admins, accountRef) {
		i.Admins = append(i.Admins, accountRef)
	}

	// We sort and remove duplicates.
	slices.SortFunc(i.Admins, func(a AccountRef, b AccountRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	i.Admins = slices.Compact(i.Admins)

	return nil
}

func GetIdentity(ctx context.Context, id identifier.Identifier) (*Identity, errors.E) { 
	identitiesMu.RLock()
	defer identitiesMu.RUnlock()

	data, ok := identities[id]
	if !ok {
		return nil, errors.WithDetails(ErrIdentityNotFound, "id", id)
	}
	var identity Identity
	errE := x.UnmarshalWithoutUnknownFields(data, &identity)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, errE
	}
	account := mustGetAccount(ctx)
	if !slices.Contains(identity.Admins, AccountRef{account}) {
		return nil, errors.WithDetails(ErrIdentityUnauthorized, "id", id)
	}
	return &identity, nil
}

func CreateIdentity(ctx context.Context, identity *Identity) errors.E {
	errE := identity.Validate(ctx, nil)
	if errE != nil {
		return errors.WrapWith(errE, ErrIdentityValidationFailed)
	}

	data, errE := x.MarshalWithoutEscapeHTML(identity)
	if errE != nil {
		return errE
	}

	identitiesMu.Lock()
	defer identitiesMu.Unlock()

	identities[*identity.ID] = data
	return nil
}

func UpdateIdentity(ctx context.Context, identity *Identity) errors.E {
	identitiesMu.Lock()
	defer identitiesMu.Unlock()

	if identity.ID == nil {
		return errors.WithMessage(ErrIdentityValidationFailed, "ID is missing")
	}

	existingData, ok := identities[*identity.ID]
	if !ok {
		return errors.WithDetails(ErrIdentityNotFound, "id", *identity.ID)
	}

	var existingIdentity Identity
	errE := x.UnmarshalWithoutUnknownFields(existingData, &existingIdentity)
	if errE != nil {
		errors.Details(errE)["id"] = *identity.ID
		return errE
	}

	account := mustGetAccount(ctx)
	if !slices.Contains(existingIdentity.Admins, AccountRef{account}) {
		return errors.WithDetails(ErrIdentityUnauthorized, "id", *identity.ID)
	}

	errE = identity.Validate(ctx, &existingIdentity)
	if errE != nil {
		return errors.WrapWith(errE, ErrIdentityValidationFailed)
	}

	data, errE := x.MarshalWithoutEscapeHTML(identity)
	if errE != nil {
		errors.Details(errE)["id"] = *identity.ID
		return errE
	}

	identities[*identity.ID] = data
	return nil
}

func (s *Service) IdentityGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) IdentityCreate(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false) == nil {
		return
	}

	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) IdentityList(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func getIdentityFromID(ctx context.Context, value string) (*Identity, errors.E) {
	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrIdentityNotFound)
	}

	return GetIdentity(ctx, id)
}

func (s *Service) returnIdentityRef(_ context.Context, w http.ResponseWriter, req *http.Request, identity *Identity) {
	s.WriteJSON(w, req, IdentityRef{ID: *identity.ID}, nil)
}

func (s *Service) IdentityGetGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true)
	if ctx == nil {
		return
	}

	identity, errE := getIdentityFromID(ctx, params["id"])
	if errors.Is(errE, ErrIdentityUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errors.Is(errE, ErrIdentityNotFound) {
		s.NotFound(w, req)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, identity, map[string]interface{}{
		"can_update": true,
	})
}

func (s *Service) IdentityListGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true)
	if ctx == nil {
		return
	}

	account := mustGetAccount(ctx)

	result := []IdentityRef{}

	identitiesMu.RLock()
	defer identitiesMu.RUnlock()

	for id, data := range identities {
		var identity Identity
		errE := x.UnmarshalWithoutUnknownFields(data, &identity)
		if errE != nil {
			errors.Details(errE)["id"] = id
			s.InternalServerErrorWithError(w, req, errE)
			return
		}

		if slices.Contains(identity.Admins, AccountRef{account}) {
			result = append(result, IdentityRef{ID: id})
		}
	}

	slices.SortFunc(result, func(a IdentityRef, b IdentityRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) IdentityUpdatePost(w http.ResponseWriter, req *http.Request, params waf.Params) { //nolint:dupl
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true)
	if ctx == nil {
		return
	}

	var identity Identity
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &identity)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	// If identity.ID == nil, UpdateIdentity returns an error.
	if identity.ID != nil && params["id"] != identity.ID.String() {
		errE = errors.New("params ID does not match payload ID")
		errors.Details(errE)["params"] = params["id"]
		errors.Details(errE)["payload"] = *identity.ID
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = UpdateIdentity(ctx, &identity)
	if errors.Is(errE, ErrIdentityUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errors.Is(errE, ErrIdentityNotFound) {
		s.NotFound(w, req)
		return
	} else if errors.Is(errE, ErrIdentityValidationFailed) {
		s.BadRequestWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnIdentityRef(ctx, w, req, &identity)
}

func (s *Service) IdentityCreatePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true)
	if ctx == nil {
		return
	}

	var identity Identity
	errE := x.DecodeJSONWithoutUnknownFields(req.Body, &identity)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if identity.ID != nil {
		s.BadRequestWithError(w, req, errors.New("payload contains ID"))
		return
	}

	errE = CreateIdentity(ctx, &identity)
	if errors.Is(errE, ErrIdentityValidationFailed) {
		s.BadRequestWithError(w, req, errE)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnIdentityRef(ctx, w, req, &identity)
}
