// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// parseTree decodes JSON the same way the envelope path does: strict (duplicate
// keys rejected, integers preserved as json.Number).
func parseTree(t *testing.T, s string) any {
	t.Helper()
	tree, err := contract.ParseJSONStrict([]byte(s))
	if err != nil {
		t.Fatalf("ParseJSONStrict(%q): %v", s, err)
	}
	return tree
}

func TestEnforceSafeNumbers_RejectsUnsafe(t *testing.T) {
	// Each input carries a number that must be rejected. These are the
	// cross-language signature-mismatch vectors: a JS verifier would round or
	// reinterpret them, so they must never reach the canonical signing input.
	cases := []struct {
		name string
		json string
	}{
		{"float", `{"x": 1.5}`},
		{"exponent_lower", `{"x": 1e3}`},
		{"exponent_upper", `{"x": 1E3}`},
		{"exponent_negative", `{"x": 1e-3}`},
		{"negative_zero", `{"x": -0}`},
		{"above_safe_range", `{"x": 9007199254740992}`}, // 2^53
		{"far_above_safe_range", `{"x": 18446744073709551615}`},
		{"below_safe_range", `{"x": -9007199254740992}`}, // -(2^53)
		{"nested_in_array", `{"a": [1, 2, 9007199254740993]}`},
		{"nested_in_object", `{"a": {"b": {"c": 1.0}}}`},
		{"fractional_zero", `{"x": 0.0}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseTree(t, tc.json)
			err := EnforceSafeNumbers(tree)
			if !errors.Is(err, ErrUnsafeNumber) {
				t.Fatalf("EnforceSafeNumbers(%s) = %v, want ErrUnsafeNumber", tc.json, err)
			}
		})
	}
}

func TestEnforceSafeNumbers_AllowsSafe(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"zero", `{"x": 0}`},
		{"small_positive", `{"x": 42}`},
		{"small_negative", `{"x": -42}`},
		{"max_safe", `{"x": 9007199254740991}`},  // 2^53-1
		{"min_safe", `{"x": -9007199254740991}`}, // -(2^53-1)
		{"strings_unaffected", `{"x": "9007199254740992", "y": "1.5"}`},
		{"bools_and_null", `{"a": true, "b": false, "c": null}`},
		{"safe_in_array", `{"a": [0, 1, -1, 9007199254740991]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseTree(t, tc.json)
			if err := EnforceSafeNumbers(tree); err != nil {
				t.Fatalf("EnforceSafeNumbers(%s) = %v, want nil", tc.json, err)
			}
		})
	}
}

func TestValidateHex256(t *testing.T) {
	good := strings.Repeat("a", 64)
	if err := ValidateHex256(good); err != nil {
		t.Fatalf("ValidateHex256(64 a) = %v, want nil", err)
	}
	bad := []struct {
		name, in string
	}{
		{"too_short", strings.Repeat("a", 63)},
		{"too_long", strings.Repeat("a", 65)},
		{"uppercase", strings.Repeat("A", 64)},
		{"non_hex", strings.Repeat("g", 64)},
		{"empty", ""},
		{"mixed_case", strings.Repeat("a", 63) + "B"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateHex256(tc.in); !errors.Is(err, ErrBadGrammar) {
				t.Fatalf("ValidateHex256(%q) = %v, want ErrBadGrammar", tc.in, err)
			}
		})
	}
}

func TestValidateUint64String(t *testing.T) {
	good := []string{"0", "1", "42", "18446744073709551615"} // max uint64
	for _, s := range good {
		if err := ValidateUint64String(s); err != nil {
			t.Errorf("ValidateUint64String(%q) = %v, want nil", s, err)
		}
	}
	bad := []struct {
		name, in string
	}{
		{"empty", ""},
		{"leading_zero", "01"},
		{"negative", "-1"},
		{"plus", "+1"},
		{"float", "1.0"},
		{"hex", "0x10"},
		{"overflow_uint64", "18446744073709551616"},
		{"letters", "12a"},
		{"space", "1 "},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateUint64String(tc.in); !errors.Is(err, ErrBadGrammar) {
				t.Fatalf("ValidateUint64String(%q) = %v, want ErrBadGrammar", tc.in, err)
			}
		})
	}
}

func TestValidateDecimalAmount(t *testing.T) {
	good := []string{"0", "1", "-1", "0.5", "-0.5", "123.456", "1000000", "-1000000.01"}
	for _, s := range good {
		if err := ValidateDecimalAmount(s); err != nil {
			t.Errorf("ValidateDecimalAmount(%q) = %v, want nil", s, err)
		}
	}
	bad := []struct {
		name, in string
	}{
		{"empty", ""},
		{"sign_only", "-"},
		{"leading_zero_int", "01"},
		{"trailing_zero_frac", "1.50"},
		{"trailing_zero_frac_only", "0.0"},
		{"negative_zero", "-0"},
		{"negative_zero_frac", "-0.0"},
		{"exponent", "1e3"},
		{"no_int_part", ".5"},
		{"empty_frac", "1."},
		{"double_dot", "1.2.3"},
		{"letters", "1.2a"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateDecimalAmount(tc.in); !errors.Is(err, ErrBadGrammar) {
				t.Fatalf("ValidateDecimalAmount(%q) = %v, want ErrBadGrammar", tc.in, err)
			}
		})
	}
}

func TestValidateTimestamp(t *testing.T) {
	good := []string{
		"2026-06-01T00:00:00Z",
		"2026-06-01T00:00:00.123456789Z",
		"2026-06-01T00:00:00+02:00",
	}
	for _, s := range good {
		if err := ValidateTimestamp(s); err != nil {
			t.Errorf("ValidateTimestamp(%q) = %v, want nil", s, err)
		}
	}
	bad := []struct {
		name, in string
	}{
		{"empty", ""},
		{"no_zone", "2026-06-01T00:00:00"},
		{"date_only", "2026-06-01"},
		{"epoch_number_as_string", "1748736000"},
		{"garbage", "not-a-time"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateTimestamp(tc.in); !errors.Is(err, ErrBadGrammar) {
				t.Fatalf("ValidateTimestamp(%q) = %v, want ErrBadGrammar", tc.in, err)
			}
		})
	}
}
