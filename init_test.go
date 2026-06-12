package charon_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	z "gitlab.com/tozd/go/zerolog"
	"gitlab.com/tozd/waf"

	"gitlab.com/charon/charon"
)

// TestCharonOrganizationRestart verifies that booting the service again over the same data directory
// reuses the existing Charon organization without modifying it, while booting with a different title
// creates a new organization.
func TestCharonOrganizationRestart(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test_cert.pem")
	keyPath := filepath.Join(tempDir, "test_key.pem")

	errE := x.CreateTempCertificateFiles(certPath, keyPath, []string{"localhost"})
	require.NoError(t, errE)

	dataDir := filepath.Join(tempDir, "data")
	organizationsDir := filepath.Join(dataDir, "organizations")

	boot := func(title string) {
		logger := zerolog.New(zerolog.NewTestWriter(t)).With().Timestamp().Logger()
		config := charon.Config{
			LoggingConfig: z.LoggingConfig{
				Logger: logger,
			},
			Server: waf.Server[*charon.Site]{
				HTTPS: waf.HTTPS{
					CertFile: certPath,
					KeyFile:  keyPath,
					Listen:   "localhost:8080",
				},
				Development: true,
			},
			Title:         title,
			ExternalPort:  8080,
			DataDirectory: dataDir,
		}

		service, errE := config.Init(t.Context(), testFiles)
		require.NoError(t, errE, "% -+#.1v", errE)

		_, errE = config.Prepare(t.Context(), service)
		require.NoError(t, errE, "% -+#.1v", errE)
	}

	boot("")

	entries, err := os.ReadDir(organizationsDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	organizationPath := filepath.Join(organizationsDir, entries[0].Name())

	// We modify the stored organization to verify that booting again does not overwrite it.
	data, err := os.ReadFile(organizationPath) //nolint:gosec
	require.NoError(t, err)
	var organization map[string]any
	err = json.Unmarshal(data, &organization)
	require.NoError(t, err)
	organization["description"] = "modified"
	data, err = json.Marshal(organization)
	require.NoError(t, err)
	err = os.WriteFile(organizationPath, data, 0o600)
	require.NoError(t, err)

	boot("")

	entries, err = os.ReadDir(organizationsDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	data, err = os.ReadFile(organizationPath) //nolint:gosec
	require.NoError(t, err)
	err = json.Unmarshal(data, &organization)
	require.NoError(t, err)
	require.Equal(t, "modified", organization["description"])

	// A different title creates a new organization.
	boot("Other")

	entries, err = os.ReadDir(organizationsDir)
	require.NoError(t, err)
	require.Len(t, entries, 2)
}
