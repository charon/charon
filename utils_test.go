package charon

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
		tt := tt

		t.Run(tt.Username, func(t *testing.T) {
			t.Parallel()

			out, errE := normalizeUsernameCaseMapped(tt.Username)
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
		tt := tt

		t.Run(tt.Username, func(t *testing.T) {
			t.Parallel()

			out, errE := normalizeUsernameCasePreserved(tt.Username)
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
		tt := tt

		t.Run(tt.Password, func(t *testing.T) {
			t.Parallel()

			out, errE := normalizePassword([]byte(tt.Password))
			assert.Equal(t, tt.Expected, string(out))
			if tt.Error != "" {
				assert.EqualError(t, errE, tt.Error)
			}
		})
	}
}

func TestGetRandomCode(t *testing.T) {
	t.Parallel()

	for i := 0; i < 1000; i++ {
		out, errE := getRandomCode()
		assert.NoError(t, errE, "% -+#.1v", errE)
		assert.Len(t, out, 6)
	}
}
