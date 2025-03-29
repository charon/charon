package charon_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/charon/charon"
)

func TestNormalizeUsernameCaseMapped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Username string
		Expected string
		Error    string
	}{
		{`juliet@example.com`, `juliet@example.com`, ``},
		{`fussball`, `fussball`, ``},
		{`fußball`, `fußball`, ``},
		{`π`, `π`, ``},
		{`Σ`, `σ`, ``},
		{`σ`, `σ`, ``},
		{`ς`, `ς`, ``},
		{`foo bar`, ``, `precis: disallowed rune encountered`},
		{``, ``, `precis: transformation resulted in empty string`},
		{`henryⅣ`, ``, `precis: disallowed rune encountered`},
		{`∞`, ``, `bidirule: failed Bidi Rule`},

		{` juliet@example.com `, `juliet@example.com`, ``},
		{` `, ``, `precis: transformation resulted in empty string`},
	}

	for _, tt := range tests {
		t.Run(tt.Username, func(t *testing.T) {
			t.Parallel()

			out, errE := charon.TestingNormalizeUsernameCaseMapped(tt.Username)
			assert.Equal(t, tt.Expected, out)
			if tt.Error != "" {
				assert.EqualError(t, errE, tt.Error)
			}
		})
	}
}

func TestNormalizeUsernameCasePreserved(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Username string
		Expected string
		Error    string
	}{
		{`juliet@example.com`, `juliet@example.com`, ``},
		{`fussball`, `fussball`, ``},
		{`fußball`, `fußball`, ``},
		{`π`, `π`, ``},
		{`Σ`, `Σ`, ``},
		{`σ`, `σ`, ``},
		{`ς`, `ς`, ``},
		{`foo bar`, ``, `precis: disallowed rune encountered`},
		{``, ``, `precis: transformation resulted in empty string`},
		{`henryⅣ`, ``, `precis: disallowed rune encountered`},
		{`∞`, ``, `bidirule: failed Bidi Rule`},

		{` juliet@example.com `, `juliet@example.com`, ``},
		{` `, ``, `precis: transformation resulted in empty string`},
	}

	for _, tt := range tests {
		t.Run(tt.Username, func(t *testing.T) {
			t.Parallel()

			out, errE := charon.TestingNormalizeUsernameCasePreserved(tt.Username)
			assert.Equal(t, tt.Expected, out)
			if tt.Error != "" {
				assert.EqualError(t, errE, tt.Error)
			}
		})
	}
}

func TestNormalizePassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Password string
		Expected string
		Error    string
	}{
		{`correct horse battery staple`, `correct horse battery staple`, ``},
		{`Correct Horse Battery Staple`, `Correct Horse Battery Staple`, ``},
		{`πßå`, `πßå`, ``},
		{`Jack of ♦s`, `Jack of ♦s`, ``},
		{`foo bar`, `foo bar`, ``},
		{``, ``, `precis: transformation resulted in empty string`},
		{"my cat is a \u0009by", ``, `precis: disallowed rune encountered`},

		{` correct horse battery staple `, ` correct horse battery staple `, ``},
		{` `, ` `, ``},
	}

	for _, tt := range tests {
		t.Run(tt.Password, func(t *testing.T) {
			t.Parallel()

			out, errE := charon.TestingNormalizePassword([]byte(tt.Password))
			assert.Equal(t, tt.Expected, string(out))
			if tt.Error != "" {
				assert.EqualError(t, errE, tt.Error)
			}
		})
	}
}

func TestGetRandomCode(t *testing.T) {
	t.Parallel()

	for range 1000 {
		out, errE := charon.TestingGetRandomCode()
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Len(t, out, 6)
	}
}
