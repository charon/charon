package charon //nolint:testpackage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/identifier"
)

func TestStoreInMemory(t *testing.T) {
	t.Parallel()

	s, errE := newStore("", "things")
	require.NoError(t, errE, "% -+#.1v", errE)

	id := identifier.New()

	s.RLock()
	_, ok := s.Get(id)
	s.RUnlock()
	assert.False(t, ok)

	s.Lock()
	errE = s.Set(id, []byte(`{"v":1}`))
	s.Unlock()
	require.NoError(t, errE, "% -+#.1v", errE)

	s.RLock()
	data, ok := s.Get(id)
	s.RUnlock()
	assert.True(t, ok)
	assert.Equal(t, `{"v":1}`, string(data))
}

func TestStorePersistsAcrossInstances(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	id := identifier.New()
	want := []byte(`{"v":"persisted"}`)

	s1, errE := newStore(dir, "things")
	require.NoError(t, errE, "% -+#.1v", errE)

	s1.Lock()
	errE = s1.Set(id, want)
	s1.Unlock()
	require.NoError(t, errE, "% -+#.1v", errE)

	// File should exist on disk under <dir>/things/<id>.json.
	path := filepath.Join(dir, "things", id.String()+".json")
	got, err := os.ReadFile(path) //nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, want, got)

	// A second Store at the same dataDir/name reads the persisted entry on construction.
	s2, errE := newStore(dir, "things")
	require.NoError(t, errE, "% -+#.1v", errE)

	s2.RLock()
	data, ok := s2.Get(id)
	s2.RUnlock()
	assert.True(t, ok)
	assert.Equal(t, want, data)
}

func TestStoreDelete(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	s, errE := newStore(dir, "things")
	require.NoError(t, errE, "% -+#.1v", errE)

	id := identifier.New()

	s.Lock()
	errE = s.Set(id, []byte("a"))
	s.Unlock()
	require.NoError(t, errE, "% -+#.1v", errE)

	s.Lock()
	errE = s.Delete(id)
	s.Unlock()
	require.NoError(t, errE, "% -+#.1v", errE)

	// File should be gone.
	_, err := os.Stat(filepath.Join(dir, "things", id.String()+".json"))
	assert.True(t, os.IsNotExist(err), "expected file to be removed, stat err: %v", err)

	// Deleting a missing entry is a no-op.
	s.Lock()
	errE = s.Delete(id)
	s.Unlock()
	assert.NoError(t, errE, "% -+#.1v", errE)
}

func TestStoreRange(t *testing.T) {
	t.Parallel()

	s, errE := newStore("", "things")
	require.NoError(t, errE, "% -+#.1v", errE)

	want := map[identifier.Identifier]string{
		identifier.New(): "a",
		identifier.New(): "b",
		identifier.New(): "c",
	}

	s.Lock()
	for id, v := range want {
		errE = s.Set(id, []byte(v))
		require.NoError(t, errE, "% -+#.1v", errE)
	}
	s.Unlock()

	got := map[identifier.Identifier]string{}
	s.RLock()
	for id, data := range s.All() {
		got[id] = string(data)
	}
	assert.Equal(t, 3, s.Len())
	s.RUnlock()
	assert.Equal(t, want, got)
}
