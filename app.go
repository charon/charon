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
	ErrAppNotFound     = errors.Base("app not found")
	ErrAppUnauthorized = errors.Base("app change unauthorized")
)

var (
	apps   = make(map[identifier.Identifier][]byte) //nolint:gochecknoglobals
	appsMu = sync.RWMutex{}                         //nolint:gochecknoglobals
)

type App struct {
	ID identifier.Identifier

	Admins []identifier.Identifier

	Name         string
	RedirectPath string
}

func GetApp(ctx context.Context, id identifier.Identifier) (*App, errors.E) { //nolint:revive
	appsMu.RLock()
	defer appsMu.RUnlock()

	data, ok := apps[id]
	if !ok {
		return nil, errors.WithDetails(ErrAppNotFound, "id", id)
	}
	var app App
	errE := x.UnmarshalWithoutUnknownFields(data, &app)
	if errE != nil {
		errors.Details(errE)["id"] = id
		return nil, errE
	}
	return &app, nil
}

func SetApp(ctx context.Context, app *App) errors.E { //nolint:revive
	data, errE := x.MarshalWithoutEscapeHTML(app)
	if errE != nil {
		errors.Details(errE)["id"] = app.ID
		return errE
	}

	appsMu.Lock()
	defer appsMu.Unlock()

	apps[app.ID] = data
	return nil
}

func UpsertApp(ctx context.Context, app *App) errors.E { //nolint:revive
	data, errE := x.MarshalWithoutEscapeHTML(app)
	if errE != nil {
		errors.Details(errE)["id"] = app.ID
		return errE
	}

	appsMu.Lock()
	defer appsMu.Unlock()

	existingData, ok := apps[app.ID]
	if !ok {
		apps[app.ID] = data
		return nil
	}

	var existingApp App
	errE = x.UnmarshalWithoutUnknownFields(existingData, &existingApp)
	if errE != nil {
		errors.Details(errE)["id"] = app.ID
		return errE
	}

	account := mustGetAccount(ctx)
	if !slices.Contains(existingApp.Admins, account) {
		return errors.WithDetails(ErrAppUnauthorized, "id", app.ID)
	}

	apps[app.ID] = data
	return nil
}

func (s *Service) App(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false, "Charon Dashboard") == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *Service) Apps(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.RequireAuthenticated(w, req, false, "Charon Dashboard") == nil {
		return
	}

	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func getAppFromID(ctx context.Context, value string) (*App, errors.E) {
	if value == "" {
		return nil, errors.WithStack(ErrAppNotFound)
	}

	id, errE := identifier.FromString(value)
	if errE != nil {
		return nil, errors.WrapWith(errE, ErrAppNotFound)
	}

	return GetApp(ctx, id)
}

func (s *Service) AppGet(w http.ResponseWriter, req *http.Request, params waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	app, errE := getAppFromID(ctx, params["id"])
	if errors.Is(errE, ErrAppNotFound) {
		s.NotFound(w, req)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	s.WriteJSON(w, req, app, nil)
}

func (s *Service) AppsGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	result := []map[string]identifier.Identifier{}

	appsMu.RLock()
	defer appsMu.RUnlock()

	for id := range apps {
		result = append(result, map[string]identifier.Identifier{
			"id": id,
		})
	}

	s.WriteJSON(w, req, result, nil)
}

func (s *Service) AppsPost(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body) //nolint:errcheck

	ctx := s.RequireAuthenticated(w, req, true, "Charon Dashboard")
	if ctx == nil {
		return
	}

	var app App
	errE := x.DecodeJSON(req.Body, &app)
	if errE != nil {
		s.BadRequestWithError(w, req, errE)
		return
	}

	errE = UpsertApp(ctx, &app)
	if errors.Is(errE, ErrAppUnauthorized) {
		waf.Error(w, req, http.StatusUnauthorized)
		return
	} else if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	waf.Error(w, req, http.StatusOK)
}
