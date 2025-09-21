package charon_test

import (
	"testing"
	"time"

	"github.com/russellhaering/gosaml2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/charon/charon"
)

func TestParseAttributeValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       types.AttributeValue
		expected    any
		expectError bool
	}{
		// Integer types.
		{
			name:     "int type",
			input:    types.AttributeValue{Type: "int", Value: "42"},
			expected: int64(42),
		},
		{
			name:     "integer type",
			input:    types.AttributeValue{Type: "integer", Value: "123"},
			expected: int64(123),
		},
		{
			name:     "long type",
			input:    types.AttributeValue{Type: "long", Value: "9223372036854775807"},
			expected: int64(9223372036854775807),
		},
		{
			name:     "negativeInteger type",
			input:    types.AttributeValue{Type: "negativeInteger", Value: "-456"},
			expected: int64(-456),
		},
		{
			name:     "nonNegativeInteger type",
			input:    types.AttributeValue{Type: "nonNegativeInteger", Value: "789"},
			expected: int64(789),
		},
		{
			name:     "nonPositiveInteger type",
			input:    types.AttributeValue{Type: "nonPositiveInteger", Value: "-123"},
			expected: int64(-123),
		},
		{
			name:     "positiveInteger type",
			input:    types.AttributeValue{Type: "positiveInteger", Value: "456"},
			expected: int64(456),
		},
		{
			name:     "byte type",
			input:    types.AttributeValue{Type: "byte", Value: "127"},
			expected: int64(127),
		},
		{
			name:     "short type",
			input:    types.AttributeValue{Type: "short", Value: "32767"},
			expected: int64(32767),
		},
		{
			name:     "unsignedByte type",
			input:    types.AttributeValue{Type: "unsignedByte", Value: "255"},
			expected: int64(255),
		},
		{
			name:     "unsignedShort type",
			input:    types.AttributeValue{Type: "unsignedShort", Value: "65535"},
			expected: int64(65535),
		},
		{
			name:     "unsignedInt type",
			input:    types.AttributeValue{Type: "unsignedInt", Value: "4294967295"},
			expected: int64(4294967295),
		},
		{
			name:     "unsignedLong type",
			input:    types.AttributeValue{Type: "unsignedLong", Value: "123456789"},
			expected: int64(123456789),
		},

		// Float types.
		{
			name:     "float type",
			input:    types.AttributeValue{Type: "float", Value: "3.14"},
			expected: float64(3.14),
		},
		{
			name:     "double type",
			input:    types.AttributeValue{Type: "double", Value: "2.718281828"},
			expected: float64(2.718281828),
		},
		{
			name:     "decimal type",
			input:    types.AttributeValue{Type: "decimal", Value: "123.456"},
			expected: float64(123.456),
		},

		// Boolean type.
		{
			name:     "boolean true",
			input:    types.AttributeValue{Type: "boolean", Value: "true"},
			expected: true,
		},
		{
			name:     "boolean false",
			input:    types.AttributeValue{Type: "boolean", Value: "false"},
			expected: false,
		},
		{
			name:     "boolean 1",
			input:    types.AttributeValue{Type: "boolean", Value: "1"},
			expected: true,
		},
		{
			name:     "boolean 0",
			input:    types.AttributeValue{Type: "boolean", Value: "0"},
			expected: false,
		},

		// String types.
		{
			name:     "string type",
			input:    types.AttributeValue{Type: "string", Value: "hello world"},
			expected: "hello world",
		},
		{
			name:     "token type",
			input:    types.AttributeValue{Type: "token", Value: "  token_value  "},
			expected: "token_value",
		},
		{
			name:     "normalizedString type",
			input:    types.AttributeValue{Type: "normalizedString", Value: "  normalized  "},
			expected: "normalized",
		},
		{
			name:     "language type",
			input:    types.AttributeValue{Type: "language", Value: "en-US"},
			expected: "en-US",
		},
		{
			name:     "anyURI type",
			input:    types.AttributeValue{Type: "anyURI", Value: "https://example.com"},
			expected: "https://example.com",
		},
		{
			name:     "empty type defaults to string",
			input:    types.AttributeValue{Type: "", Value: "default string"},
			expected: "default string",
		},
		{
			name:     "empty string value returns nil",
			input:    types.AttributeValue{Type: "string", Value: ""},
			expected: nil,
		},
		{
			name:     "whitespace-only string value returns nil",
			input:    types.AttributeValue{Type: "string", Value: "   "},
			expected: nil,
		},

		// DateTime types.
		{
			name:     "dateTime with timezone",
			input:    types.AttributeValue{Type: "dateTime", Value: "2023-10-15T14:30:00.123456789Z"},
			expected: time.Date(2023, 10, 15, 14, 30, 0, 123456789, time.UTC),
		},
		{
			name:     "dateTime without timezone",
			input:    types.AttributeValue{Type: "dateTime", Value: "2023-10-15T14:30:00.123456789"},
			expected: time.Date(2023, 10, 15, 14, 30, 0, 123456789, time.UTC),
		},
		{
			name:     "time with timezone",
			input:    types.AttributeValue{Type: "time", Value: "14:30:00.123456789Z"},
			expected: time.Date(0, 1, 1, 14, 30, 0, 123456789, time.UTC),
		},
		{
			name:     "time without timezone",
			input:    types.AttributeValue{Type: "time", Value: "14:30:00.123456789"},
			expected: time.Date(0, 1, 1, 14, 30, 0, 123456789, time.UTC),
		},
		{
			name:     "date with timezone",
			input:    types.AttributeValue{Type: "date", Value: "2023-10-15Z"},
			expected: time.Date(2023, 10, 15, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "date without timezone",
			input:    types.AttributeValue{Type: "date", Value: "2023-10-15"},
			expected: time.Date(2023, 10, 15, 0, 0, 0, 0, time.UTC),
		},

		// Duration type.
		{
			name:     "duration with days",
			input:    types.AttributeValue{Type: "duration", Value: "P5D"},
			expected: 5 * 24 * time.Hour,
		},
		{
			name:     "duration with time components",
			input:    types.AttributeValue{Type: "duration", Value: "PT2H30M45.5S"},
			expected: 2*time.Hour + 30*time.Minute + 45500*time.Millisecond,
		},
		{
			name:     "duration with days and time",
			input:    types.AttributeValue{Type: "duration", Value: "P1DT2H30M"},
			expected: 24*time.Hour + 2*time.Hour + 30*time.Minute,
		},
		{
			name:     "negative duration",
			input:    types.AttributeValue{Type: "duration", Value: "-P1DT2H"},
			expected: -(24*time.Hour + 2*time.Hour),
		},

		// Namespaced types.
		{
			name:     "namespaced int type",
			input:    types.AttributeValue{Type: "xs:int", Value: "42"},
			expected: int64(42),
		},
		{
			name:     "namespaced string type",
			input:    types.AttributeValue{Type: "xs:string", Value: "namespaced"},
			expected: "namespaced",
		},

		// Error cases.
		{
			name:        "invalid int",
			input:       types.AttributeValue{Type: "int", Value: "not_a_number"},
			expectError: true,
		},
		{
			name:        "invalid float",
			input:       types.AttributeValue{Type: "float", Value: "not_a_float"},
			expectError: true,
		},
		{
			name:        "invalid boolean",
			input:       types.AttributeValue{Type: "boolean", Value: "maybe"},
			expectError: true,
		},
		{
			name:        "invalid dateTime",
			input:       types.AttributeValue{Type: "dateTime", Value: "not_a_datetime"},
			expectError: true,
		},
		{
			name:        "invalid time",
			input:       types.AttributeValue{Type: "time", Value: "not_a_time"},
			expectError: true,
		},
		{
			name:        "invalid date",
			input:       types.AttributeValue{Type: "date", Value: "not_a_date"},
			expectError: true,
		},
		{
			name:        "invalid duration",
			input:       types.AttributeValue{Type: "duration", Value: "not_a_duration"},
			expectError: true,
		},
		{
			name:        "unsupported type",
			input:       types.AttributeValue{Type: "unsupported", Value: "value"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := charon.TestingParseAttributeValue(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseAttributeValueEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("maximum int64 value", func(t *testing.T) {
		t.Parallel()
		input := types.AttributeValue{Type: "long", Value: "9223372036854775807"}
		result, err := charon.TestingParseAttributeValue(input)
		require.NoError(t, err)
		assert.Equal(t, int64(9223372036854775807), result)
	})

	t.Run("minimum int64 value", func(t *testing.T) {
		t.Parallel()
		input := types.AttributeValue{Type: "long", Value: "-9223372036854775808"}
		result, err := charon.TestingParseAttributeValue(input)
		require.NoError(t, err)
		assert.Equal(t, int64(-9223372036854775808), result)
	})

	t.Run("zero duration", func(t *testing.T) {
		t.Parallel()
		input := types.AttributeValue{Type: "duration", Value: "P0D"}
		result, err := charon.TestingParseAttributeValue(input)
		require.NoError(t, err)
		assert.Equal(t, time.Duration(0), result)
	})

	t.Run("complex namespace prefix", func(t *testing.T) {
		t.Parallel()
		// This should now work because we use the last colon to split the namespace.
		input := types.AttributeValue{Type: "http://www.w3.org/2001/XMLSchema:int", Value: "42"}
		result, err := charon.TestingParseAttributeValue(input)
		require.NoError(t, err)
		assert.Equal(t, int64(42), result)
	})

	t.Run("fractional seconds in duration", func(t *testing.T) {
		t.Parallel()
		input := types.AttributeValue{Type: "duration", Value: "PT1.5S"}
		result, err := charon.TestingParseAttributeValue(input)
		require.NoError(t, err)
		assert.Equal(t, 1500*time.Millisecond, result)
	})
}

func TestParseAttributeValueComplexDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected time.Duration
	}{
		{
			name:     "only seconds",
			input:    "PT30S",
			expected: 30 * time.Second,
		},
		{
			name:     "only minutes",
			input:    "PT5M",
			expected: 5 * time.Minute,
		},
		{
			name:     "only hours",
			input:    "PT3H",
			expected: 3 * time.Hour,
		},
		{
			name:     "only days",
			input:    "P7D",
			expected: 7 * 24 * time.Hour,
		},
		{
			name:     "all components",
			input:    "P2DT3H4M5.6S",
			expected: 2*24*time.Hour + 3*time.Hour + 4*time.Minute + 5600*time.Millisecond,
		},
		{
			name:     "negative all components",
			input:    "-P2DT3H4M5.6S",
			expected: -(2*24*time.Hour + 3*time.Hour + 4*time.Minute + 5600*time.Millisecond),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := types.AttributeValue{Type: "duration", Value: tt.input}
			result, err := charon.TestingParseAttributeValue(input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
