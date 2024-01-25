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
	ErrApplicationNotFound      = errors.Base("application not found")
	ErrApplicationAlreadyExists = errors.Base("application already exists")
	ErrApplicationUnauthorized  = errors.Base("application change unauthorized")
)

var (
	applications   = make(map[identifier.Identifier][]byte) //nolint:gochecknoglobals
	applicationsMu = sync.RWMutex{}                         //nolint:gochecknoglobals
)

type Application struct {
	ID *identifier.Identifier `json:"id"`

	Admins []identifier.Identifier `json:"admins"`

	Name         string `json:"name"`
	RedirectPath string `json:"redirectPath"`
}

type ApplicationRef struct {
	ID identifier.Identifier `json:"id"`
}

func (a *Application) Validate(ctx context.Context) errors.E {
	if a.ID == nil {
		id := identifier.New()
		a.ID = &id
	}

	account := mustGetAccount(ctx)
	if !slices.Contains(a.Admins, account) {
		a.Admins = append(a.Admins, account)
	}

	return nil
}

func GetApplication(ctx context.Context, id identifier.Identifier) (*Application, errors.E) { //nolint:revive
	applicationsMu.RLock()
	defer applicationsMu.RUnlock()

	data, ok := applications[id]
	if !ok {
		return nil, errors.WithDetails(ErrApplicationNotFound, "id", id)
	}
	var application Application
	errE := x.UnmarshalWithoutUnknownFields(data, &application)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, errE
	}
	return &application, nil
}

func CreateApplication(ctx context.Context, application *Application) errors.E {
	errE := application.Validate(ctx)
	if errE != nil {
		return errE
	}

	data, errE := x.MarshalWithoutEscapeHTML(application)
	if errE != nil {
		return errE
	}

	applicationsMu.Lock()
	defer applicationsMu.Unlock()

	applications[*application.ID] = data
	return nil
}

func UpdateApplication(ctx context.Context, application *Application) errors.E {
	errE := application.Validate(ctx)
	if errE != nil {
		return errE
	}

	data, errE := x.MarshalWithoutEscapeHTML(application)
	if errE != nil {
		errors.Details(errE)["id"] = *application.ID
		return errE
	}

	applicationsMu.Lock()
	defer applicationsMu.Unlock()

	existingData, ok := applications[*application.ID]
	if !ok {
		return errors.WithDetails(ErrApplicationNotFound, "id", *application.ID)
	}

	var existingApplication Application
	errE = x.UnmarshalWithoutUnknownFields(existingData, &existingApplication)
	if errE != nil {
		errors.Details(errE)["id"] = *application.ID
		return errE
	}

	account := mustGetAccount(ctx)
	if !slices.Contains(existingApplication.Admins, account) {
		return errors.WithDetails(ErrApplicationUnauthorized, "id", *application.ID)
	}

	applications[*application.ID] = data
	return nil
}

func (s *Service) Application(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false, "Charon Dashboard") == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) ApplicationCreate(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false, "Charon Dashboard") == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) Applications(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false, "Charon Dashboard") == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func getApplicationFromID(ctx context.Context, value string) (*Application, errors.E) {
	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrApplicationNotFound)
	}

	return GetApplication(ctx, id)
}

func (s *Service) returnApplication(ctx context.Context, w http.ResponseWriter, req *http.Request, application *Application) {
	account := mustGetAccount(ctx)

	s.WriteJSON(w, req, application, map[string]interface{}{
		"can_update": slices.Contains(application.Admins, account),
	})
}

func (s *Service) returnApplicationRef(_ context.Context, w http.ResponseWriter, req *http.Request, application *Application) {
	s.WriteJSON(w, req, ApplicationRef{ID: *application.ID}, nil)
}

func (s *Service) ApplicationGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	application, errE := getApplicationFromID(ctx, params["id"])
	if errors.Is(errE, ErrApplicationNotFound) {
		s.NotFound(w, req)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnApplication(ctx, w, req, application)
}

func (s *Service) ApplicationsGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	result := []ApplicationRef{}

	applicationsMu.RLock()
	defer applicationsMu.RUnlock()

	for id := range applications {
		result = append(result, ApplicationRef{ID: id})
	}

	slices.SortFunc(result, func(a ApplicationRef, b ApplicationRef) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) ApplicationUpdatePost(w http.ResponseWriter, req *http.Request, params waf.Params) { //nolint:dupl
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	var application Application
	errE := x.DecodeJSON(req.Body, &application)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if application.ID == nil {
		id, errE := identifier.FromString(params["id"]) //nolint:govet
		if errE != nil {
			s.BadRequestWithError(w, req, errE)
		}
		application.ID = &id
	} else if params["id"] != application.ID.String() {
		errE = errors.New("params ID does not match payload ID")
		errors.Details(errE)["params"] = params["id"]
		errors.Details(errE)["payload"] = *application.ID
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = UpdateApplication(ctx, &application)
	if errors.Is(errE, ErrApplicationUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errors.Is(errE, ErrApplicationNotFound) {
		waf.Error(w, req, http.StatusNotFound)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnApplication(ctx, w, req, &application)
}

func (s *Service) ApplicationCreatePost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	var application Application
	errE := x.DecodeJSON(req.Body, &application)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	if application.ID != nil {
		s.BadRequestWithError(w, req, errors.New("payload contains ID"))
		return
	}

	errE = CreateApplication(ctx, &application)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.returnApplicationRef(ctx, w, req, &application)
}
