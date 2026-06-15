package charon_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gitlab.com/charon/charon"
)

func TestGravatarURL(t *testing.T) {
	t.Parallel()

	// The MD5 of "test@example.com" is the canonical Gravatar example hash.
	const expected = "https://www.gravatar.com/avatar/55502f40dc8b7c769880b10874abc9d0?d=identicon"

	assert.Equal(t, expected, charon.GravatarURL("test@example.com"))
	// Surrounding whitespace is trimmed before hashing, so the URL is unchanged.
	assert.Equal(t, expected, charon.GravatarURL("  test@example.com  "))
	// A different value yields a different hash, so the function is not returning a constant.
	assert.NotEqual(t, expected, charon.GravatarURL("other@example.com"))
}
