package charon

import (
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"sync"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
)

// Store is a simple file-backed store of byte payloads keyed by Identifier.
//
// When constructed with a non-empty data directory, each entry is persisted to
// <dataDir>/<name>/<id>.json. The full set is also held in memory and loaded
// from disk on construction. With an empty data directory, the store is
// purely in-memory.
type Store struct {
	name string
	dir  string

	mu   sync.RWMutex
	data map[identifier.Identifier][]byte
}

// newStore creates a Store named name. When dataDir is non-empty,
// <dataDir>/<name> is created (if missing) and any existing <id>.json files
// in it are loaded into memory.
func newStore(dataDir, name string) (*Store, errors.E) {
	s := &Store{
		name: name,
		dir:  "",
		mu:   sync.RWMutex{},
		data: map[identifier.Identifier][]byte{},
	}
	if dataDir == "" {
		return s, nil
	}
	s.dir = filepath.Join(dataDir, name)
	err := os.MkdirAll(s.dir, 0o700) //nolint:mnd
	if err != nil {
		errE := errors.WithStack(err)
		errors.Details(errE)["dir"] = s.dir
		return nil, errE
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		errE := errors.WithStack(err)
		errors.Details(errE)["dir"] = s.dir
		return nil, errE
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fname := entry.Name()
		ext := filepath.Ext(fname)
		if ext != ".json" {
			continue
		}
		id, errE := identifier.MaybeString(fname[:len(fname)-len(ext)])
		if errE != nil {
			errors.Details(errE)["file"] = filepath.Join(s.dir, fname)
			return nil, errE
		}
		data, err := os.ReadFile(filepath.Join(s.dir, fname)) //nolint:gosec
		if err != nil {
			errE := errors.WithStack(err)
			errors.Details(errE)["file"] = filepath.Join(s.dir, fname)
			return nil, errE
		}
		s.data[id] = data
	}
	return s, nil
}

// Lock locks for read-write access. Required before Set, Delete, or any
// iteration that must observe a consistent snapshot relative to writes.
func (s *Store) Lock() { s.mu.Lock() }

// Unlock releases the write lock.
func (s *Store) Unlock() { s.mu.Unlock() }

// RLock locks for read-only access. Required before Get or Range.
func (s *Store) RLock() { s.mu.RLock() }

// RUnlock releases the read lock.
func (s *Store) RUnlock() { s.mu.RUnlock() }

// Get returns the payload stored at id, if any. Caller must hold a read or
// write lock.
func (s *Store) Get(id identifier.Identifier) ([]byte, bool) {
	d, ok := s.data[id]
	return d, ok
}

// Set replaces the payload at id. When persistence is enabled, the file is
// written to disk before the in-memory map is updated. Caller must hold the
// write lock.
func (s *Store) Set(id identifier.Identifier, data []byte) errors.E {
	if s.dir != "" {
		errE := writeFileAtomic(filepath.Join(s.dir, id.String()+".json"), data)
		if errE != nil {
			return errE
		}
	}
	s.data[id] = data
	return nil
}

// Delete removes the payload at id. Caller must hold the write lock.
func (s *Store) Delete(id identifier.Identifier) errors.E {
	if s.dir != "" {
		err := os.Remove(filepath.Join(s.dir, id.String()+".json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			errE := errors.WithStack(err)
			errors.Details(errE)["id"] = id
			return errE
		}
	}
	delete(s.data, id)
	return nil
}

// All returns a range-over-func iterator over all entries in undefined order.
// Caller must hold a read or write lock for the duration of the iteration.
func (s *Store) All() iter.Seq2[identifier.Identifier, []byte] {
	return func(yield func(identifier.Identifier, []byte) bool) {
		for id, data := range s.data {
			if !yield(id, data) {
				return
			}
		}
	}
}

// Len returns the number of stored entries. Caller must hold a read or write
// lock.
func (s *Store) Len() int { return len(s.data) }

// writeFileAtomic writes data to path via a same-directory temp file and a
// rename, so a reader never sees a partially-written file.
func writeFileAtomic(path string, data []byte) errors.E {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		errE := errors.WithStack(err)
		errors.Details(errE)["path"] = path
		return errE
	}
	tmpName := tmp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
			_ = os.Remove(tmpName) //nolint:gosec
		}
	}()
	_, err = tmp.Write(data)
	if err != nil {
		errE := errors.WithStack(err)
		errors.Details(errE)["path"] = path
		return errE
	}
	err = tmp.Close()
	if err != nil {
		errE := errors.WithStack(err)
		errors.Details(errE)["path"] = path
		return errE
	}
	closed = true
	err = os.Rename(tmpName, path) //nolint:gosec
	if err != nil {
		_ = os.Remove(tmpName) //nolint:gosec
		errE := errors.WithStack(err)
		errors.Details(errE)["path"] = path
		return errE
	}
	return nil
}
