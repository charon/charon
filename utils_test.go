package charon_test

import (
	"testing"
	"time"

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

func TestFindFirstString(t *testing.T) {
	t.Parallel()

	ts := time.Date(2025, 10, 9, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		token    map[string]interface{}
		keys     []string
		expected string
	}{
		{
			name:     "simple string",
			token:    map[string]interface{}{"firstName": "Alice"},
			keys:     []string{"firstName"},
			expected: "Alice",
		},
		{
			name:     "simple string with spaces",
			token:    map[string]interface{}{"first_name": "   Alice  "},
			keys:     []string{"first_name"},
			expected: "Alice",
		},
		{
			name:     "empty string",
			token:    map[string]interface{}{"given_name": ""},
			keys:     []string{"given_name"},
			expected: "",
		},
		{
			name: "multiple strings",
			token: map[string]interface{}{
				"givenName": []interface{}{"", "     Alice  ", "Bob"},
			},
			keys:     []string{"givenName"},
			expected: "Alice",
		},
		{
			name: "array with non-string elements",
			token: map[string]interface{}{
				"firstName": []interface{}{true, 123, ts, " Alice    "},
			},
			keys:     []string{"firstName"},
			expected: "Alice",
		},
		{
			name: "non-existing key",
			token: map[string]interface{}{
				"lastName": "Smith",
			},
			keys:     []string{"firstName"},
			expected: "",
		},
		{
			name: "multiple keys",
			token: map[string]interface{}{
				"first_name":   " Alice",
				"username":     " name surname ",
				"emailAddress": " foo@bar.com ",
			},
			keys:     []string{"firstName", "username", "name"},
			expected: "name surname",
		},
		{
			name:     "nil map",
			token:    nil,
			keys:     []string{"firstName"},
			expected: "",
		},
		{
			name: "empty array",
			token: map[string]interface{}{
				"names": []interface{}{},
			},
			keys:     []string{"names"},
			expected: "",
		},
		{
			name: "all empty strings in array",
			token: map[string]interface{}{
				"values": []interface{}{"", "   ", "\t\n", "\r", "\n", "\r\n"},
			},
			keys:     []string{"values"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.expected, charon.TestingFindFirstString(tt.token, tt.keys...))
		})
	}
}
