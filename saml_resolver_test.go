package charon_test

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/russellhaering/gosaml2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/charon/charon"
)

func TestParseAttributeValue(t *testing.T) { //nolint:maintidx
	t.Parallel()

	tests := []struct {
		name        string
		input       types.AttributeValue
		expected    any
		expectError bool
	}{
		// Integer types.
		{
			name:        "int type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "int", Value: "42"},
			expected:    int64(42),
			expectError: false,
		},
		{
			name:        "integer type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "integer", Value: "123"},
			expected:    int64(123),
			expectError: false,
		},
		{
			name:        "long type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "long", Value: "9223372036854775807"},
			expected:    int64(9223372036854775807),
			expectError: false,
		},
		{
			name:        "negativeInteger type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "negativeInteger", Value: "-456"},
			expected:    int64(-456),
			expectError: false,
		},
		{
			name:        "nonNegativeInteger type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "nonNegativeInteger", Value: "789"},
			expected:    int64(789),
			expectError: false,
		},
		{
			name:        "nonPositiveInteger type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "nonPositiveInteger", Value: "-123"},
			expected:    int64(-123),
			expectError: false,
		},
		{
			name:        "positiveInteger type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "positiveInteger", Value: "456"},
			expected:    int64(456),
			expectError: false,
		},
		{
			name:        "byte type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "byte", Value: "127"},
			expected:    int64(127),
			expectError: false,
		},
		{
			name:        "short type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "short", Value: "32767"},
			expected:    int64(32767),
			expectError: false,
		},
		{
			name:        "unsignedByte type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "unsignedByte", Value: "255"},
			expected:    int64(255),
			expectError: false,
		},
		{
			name:        "unsignedShort type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "unsignedShort", Value: "65535"},
			expected:    int64(65535),
			expectError: false,
		},
		{
			name:        "unsignedInt type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "unsignedInt", Value: "4294967295"},
			expected:    int64(4294967295),
			expectError: false,
		},
		{
			name:        "unsignedLong type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "unsignedLong", Value: "123456789"},
			expected:    int64(123456789),
			expectError: false,
		},

		// Float types.
		{
			name:        "float type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "float", Value: "3.14"},
			expected:    float64(3.14),
			expectError: false,
		},
		{
			name:        "double type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "double", Value: "2.718281828"},
			expected:    float64(2.718281828),
			expectError: false,
		},
		{
			name:        "decimal type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "decimal", Value: "123.456"},
			expected:    float64(123.456),
			expectError: false,
		},

		// Boolean type.
		{
			name:        "boolean true",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "boolean", Value: "true"},
			expected:    true,
			expectError: false,
		},
		{
			name:        "boolean false",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "boolean", Value: "false"},
			expected:    false,
			expectError: false,
		},
		{
			name:        "boolean 1",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "boolean", Value: "1"},
			expected:    true,
			expectError: false,
		},
		{
			name:        "boolean 0",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "boolean", Value: "0"},
			expected:    false,
			expectError: false,
		},

		// String types.
		{
			name:        "string type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "string", Value: "hello world"},
			expected:    "hello world",
			expectError: false,
		},
		{
			name:        "token type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "token", Value: "  token_value  "},
			expected:    "token_value",
			expectError: false,
		},
		{
			name:        "normalizedString type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "normalizedString", Value: "  normalized  "},
			expected:    "normalized",
			expectError: false,
		},
		{
			name:        "language type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "language", Value: "en-US"},
			expected:    "en-US",
			expectError: false,
		},
		{
			name:        "anyURI type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "anyURI", Value: "https://example.com"},
			expected:    "https://example.com",
			expectError: false,
		},
		{
			name:        "empty type defaults to string",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "", Value: "default string"},
			expected:    "default string",
			expectError: false,
		},
		{
			name:        "empty string value returns nil",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "string", Value: ""},
			expected:    nil,
			expectError: false,
		},
		{
			name:        "whitespace-only string value returns nil",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "string", Value: "   "},
			expected:    nil,
			expectError: false,
		},

		// DateTime types.
		{
			name:        "dateTime with timezone",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "dateTime", Value: "2023-10-15T14:30:00.123456789Z"},
			expected:    time.Date(2023, 10, 15, 14, 30, 0, 123456789, time.UTC),
			expectError: false,
		},
		{
			name:        "dateTime without timezone",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "dateTime", Value: "2023-10-15T14:30:00.123456789"},
			expected:    time.Date(2023, 10, 15, 14, 30, 0, 123456789, time.UTC),
			expectError: false,
		},
		{
			name:        "time with timezone",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "time", Value: "14:30:00.123456789Z"},
			expected:    time.Date(0, 1, 1, 14, 30, 0, 123456789, time.UTC),
			expectError: false,
		},
		{
			name:        "time without timezone",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "time", Value: "14:30:00.123456789"},
			expected:    time.Date(0, 1, 1, 14, 30, 0, 123456789, time.UTC),
			expectError: false,
		},
		{
			name:        "date with timezone",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "date", Value: "2023-10-15Z"},
			expected:    time.Date(2023, 10, 15, 0, 0, 0, 0, time.UTC),
			expectError: false,
		},
		{
			name:        "date without timezone",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "date", Value: "2023-10-15"},
			expected:    time.Date(2023, 10, 15, 0, 0, 0, 0, time.UTC),
			expectError: false,
		},

		// Duration type.
		{
			name:        "duration with days",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "duration", Value: "P5D"},
			expected:    5 * 24 * time.Hour,
			expectError: false,
		},
		{
			name:        "duration with time components",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "duration", Value: "PT2H30M45.5S"},
			expected:    2*time.Hour + 30*time.Minute + 45500*time.Millisecond,
			expectError: false,
		},
		{
			name:        "duration with days and time",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "duration", Value: "P1DT2H30M"},
			expected:    24*time.Hour + 2*time.Hour + 30*time.Minute,
			expectError: false,
		},
		{
			name:        "negative duration",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "duration", Value: "-P1DT2H"},
			expected:    -(24*time.Hour + 2*time.Hour),
			expectError: false,
		},

		// Namespaced types.
		{
			name:        "namespaced int type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "xs:int", Value: "42"},
			expected:    int64(42),
			expectError: false,
		},
		{
			name:        "namespaced string type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "xs:string", Value: "namespaced"},
			expected:    "namespaced",
			expectError: false,
		},

		// Error cases.
		{
			name:        "invalid int",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "int", Value: "not_a_number"},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid float",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "float", Value: "not_a_float"},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid boolean",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "boolean", Value: "maybe"},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid dateTime",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "dateTime", Value: "not_a_datetime"},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid time",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "time", Value: "not_a_time"},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid date",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "date", Value: "not_a_date"},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid duration",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "duration", Value: "not_a_duration"},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "unsupported type",
			input:       types.AttributeValue{XMLName: xml.Name{}, Type: "unsupported", Value: "value"},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, errE := charon.TestingParseAttributeValue(tt.input)

			if tt.expectError {
				assert.Error(t, errE)
				return
			}

			require.NoError(t, errE, "% -+#.1v", errE)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseAttributeValueEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("maximum int64 value", func(t *testing.T) {
		t.Parallel()
		input := types.AttributeValue{XMLName: xml.Name{}, Type: "long", Value: "9223372036854775807"}
		result, errE := charon.TestingParseAttributeValue(input)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Equal(t, int64(9223372036854775807), result)
	})

	t.Run("minimum int64 value", func(t *testing.T) {
		t.Parallel()
		input := types.AttributeValue{XMLName: xml.Name{}, Type: "long", Value: "-9223372036854775808"}
		result, errE := charon.TestingParseAttributeValue(input)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Equal(t, int64(-9223372036854775808), result)
	})

	t.Run("zero duration", func(t *testing.T) {
		t.Parallel()
		input := types.AttributeValue{XMLName: xml.Name{}, Type: "duration", Value: "P0D"}
		result, errE := charon.TestingParseAttributeValue(input)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Equal(t, time.Duration(0), result)
	})

	t.Run("complex namespace prefix", func(t *testing.T) {
		t.Parallel()
		// This should now work because we use the last colon to split the namespace.
		input := types.AttributeValue{XMLName: xml.Name{}, Type: "http://www.w3.org/2001/XMLSchema:int", Value: "42"}
		result, errE := charon.TestingParseAttributeValue(input)
		require.NoError(t, errE, "% -+#.1v", errE)
		assert.Equal(t, int64(42), result)
	})

	t.Run("fractional seconds in duration", func(t *testing.T) {
		t.Parallel()
		input := types.AttributeValue{XMLName: xml.Name{}, Type: "duration", Value: "PT1.5S"}
		result, errE := charon.TestingParseAttributeValue(input)
		require.NoError(t, errE, "% -+#.1v", errE)
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
			input := types.AttributeValue{XMLName: xml.Name{}, Type: "duration", Value: tt.input}
			result, errE := charon.TestingParseAttributeValue(input)
			require.NoError(t, errE, "% -+#.1v", errE)
			assert.Equal(t, tt.expected, result)
		})
	}
}
