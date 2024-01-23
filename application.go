package charon

import (
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
	ErrApplicationNotFound     = errors.Base("application not found")
	ErrApplicationUnauthorized = errors.Base("application change unauthorized")
)

var (
	applications   = make(map[identifier.Identifier][]byte) //nolint:gochecknoglobals
	applicationsMu = sync.RWMutex{}                         //nolint:gochecknoglobals
)

type Application struct {
	ID identifier.Identifier

	Admins []identifier.Identifier

	Name         string
	RedirectPath string
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

func SetApplication(ctx context.Context, application *Application) errors.E { //nolint:revive
	data, errE := x.MarshalWithoutEscapeHTML(application)
	if errE != nil {
		errors.Details(errE)["id"] = application.ID
		return errE
	}

	applicationsMu.Lock()
	defer applicationsMu.Unlock()

	applications[application.ID] = data
	return nil
}

func UpsertApplication(ctx context.Context, application *Application) errors.E {
	data, errE := x.MarshalWithoutEscapeHTML(application)
	if errE != nil {
		errors.Details(errE)["id"] = application.ID
		return errE
	}

	applicationsMu.Lock()
	defer applicationsMu.Unlock()

	existingData, ok := applications[application.ID]
	if !ok {
		applications[application.ID] = data
		return nil
	}

	var existingApplication Application
	errE = x.UnmarshalWithoutUnknownFields(existingData, &existingApplication)
	if errE != nil {
		errors.Details(errE)["id"] = application.ID
		return errE
	}

	account := mustGetAccount(ctx)
	if !slices.Contains(existingApplication.Admins, account) {
		return errors.WithDetails(ErrApplicationUnauthorized, "id", application.ID)
	}

	applications[application.ID] = data
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
	if value == "" {
		return nil, errors.WithStack(ErrApplicationNotFound)
	}

	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrApplicationNotFound)
	}

	return GetApplication(ctx, id)
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

	s.WriteJSON(w, req, application, nil)
}

func (s *Service) ApplicationsGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	result := []map[string]identifier.Identifier{}

	applicationsMu.RLock()
	defer applicationsMu.RUnlock()

	for id := range applications {
		result = append(result, map[string]identifier.Identifier{
			"id": id,
		})
	}

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) ApplicationsPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
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

	errE = UpsertApplication(ctx, &application)
	if errors.Is(errE, ErrApplicationUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	waf.Error(w, req, http.StatusOK)
}
