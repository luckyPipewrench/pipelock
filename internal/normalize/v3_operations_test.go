// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeJSONUnicodeEscapes(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"no escape", "plain text", "plain text"},
		{"scalar", `Ab`, "Ab"},
		{"mixed case hex", `JK`, "JK"},
		{"surrogate pair", `🚀`, "\U0001F680"},
		{"lone high at end", `x\uD800`, "x�"},
		{"high then text", `\uD800abc`, "�abc"},
		{"high then scalar escape", `\uD83DA`, "�A"},
		{"high then bad low hex", `\uD83D\uZZZZ`, "�\\uZZZZ"},
		{"lone low", `\uDC00x`, "�x"},
		{"truncated", `\u12`, `\u12`},
		{"invalid hex", `\u12ZZ`, `\u12ZZ`},
		{"non-ASCII after escape", `\u12éA`, `\u12éA`},
		{"backslash u at end", `abc\u`, `abc\u`},
		{"valid then malformed", `AKIA\uDC00`, "AKIA�"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecodeJSONUnicodeEscapes(tc.in); got != tc.want {
				t.Fatalf("DecodeJSONUnicodeEscapes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestASCIIUpper(t *testing.T) {
	for in, want := range map[string]string{
		"":          "",
		"abc-XYZ_9": "ABC-XYZ_9",
		"straße":    "STRAßE", // only ASCII letters fold
		"ǆ":         "ǆ",
	} {
		if got := ASCIIUpper(in); got != want {
			t.Errorf("ASCIIUpper(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSupportedOperationKindsForProfile(t *testing.T) {
	all := SupportedOperationKinds()
	has := func(kinds []OperationKind, k OperationKind) bool {
		for _, kind := range kinds {
			if kind == k {
				return true
			}
		}
		return false
	}
	v1 := SupportedOperationKindsForProfile(EvidenceProvenanceProfileV1Digest)
	v2 := SupportedOperationKindsForProfile(EvidenceProvenanceProfileV2Digest)
	v3 := SupportedOperationKindsForProfile(EvidenceProvenanceProfileV3Digest)
	if len(v3) != len(all) || len(v2) != len(all)-2 || len(v1) != len(all)-3 {
		t.Fatalf("vocabulary sizes v1=%d v2=%d v3=%d all=%d", len(v1), len(v2), len(v3), len(all))
	}
	for _, k := range []OperationKind{OperationASCIIUpper, OperationJSONUnicodeEscape} {
		if has(v1, k) || has(v2, k) || !has(v3, k) {
			t.Fatalf("%s must be v3 only", k)
		}
	}
	if !has(v2, OperationASCIIAlphanumericStrip) || has(v1, OperationASCIIAlphanumericStrip) {
		t.Fatal("ascii_alphanumeric_strip must start at v2")
	}
	if got := SupportedOperationKindsForProfile("sha256:" + strings.Repeat("0", 64)); got != nil {
		t.Fatalf("unknown digest vocabulary = %v, want nil", got)
	}
}

func TestV3RecipeOperations(t *testing.T) {
	apply := func(t *testing.T, digest, ops, input string) (string, error) {
		t.Helper()
		var r Recipe
		if err := json.Unmarshal([]byte(`{"transform_profile_digest":"`+digest+`","operations":`+ops+`}`), &r); err != nil {
			return "", err
		}
		return r.Apply(input)
	}
	v3 := EvidenceProvenanceProfileV3Digest
	for _, tc := range []struct {
		name, digest, ops, in, want, wantErr string
	}{
		{"ascii_upper", v3, `[{"kind":"ascii_upper"}]`, "mfrgg", "MFRGG", ""},
		{"fold then liberal base32", v3, `[{"kind":"ascii_upper"},{"kind":"base32_decode_liberal"}]`, "mfrgg", "abc", ""},
		{"json escape", v3, `[{"kind":"json_unicode_escape"}]`, `A`, "A", ""},
		{"base32hex canonical", v3, `[{"kind":"base32_decode","alphabet":"base32hex","decode_padding":true}]`, "C5H66===", "abc", ""},
		{"base32hex liberal", v3, `[{"kind":"base32_decode_liberal","alphabet":"base32hex"}]`, "C5H66", "abc", ""},
		{"base32 standard alphabet", v3, `[{"kind":"base32_decode","alphabet":"standard","decode_padding":true}]`, "MFRGG===", "abc", ""},
		{"base32 malformed", v3, `[{"kind":"base32_decode","decode_padding":true}]`, "!!!!", "", "base32"},
		{"unknown base32 alphabet", v3, `[{"kind":"base32_decode","alphabet":"crockford"}]`, "abc", "", "unknown base32 alphabet"},
		{"unknown liberal base32 alphabet", v3, `[{"kind":"base32_decode_liberal","alphabet":"zbase32"}]`, "abc", "", "unknown base32 alphabet"},
		{"v2 rejects alphabet", EvidenceProvenanceProfileV2Digest, `[{"kind":"base32_decode_liberal","alphabet":"base32hex"}]`, "C5H66", "", "unsupported"},
		{"v2 rejects ascii_upper", EvidenceProvenanceProfileV2Digest, `[{"kind":"ascii_upper"}]`, "abc", "", "unsupported"},
		{"allowed params survive", v3, `[{"kind":"url_component","component":"query_value","selector":"q","occurrence":0},{"kind":"percent_decode","passes":1}]`, "https://h.example/?q=a%41", "aA", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := apply(t, tc.digest, tc.ops, tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, err %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestOperationUnmarshalRejectsMalformed(t *testing.T) {
	for _, in := range []string{`[]`, `{"kind":1}`, `{"kind":"lowercase"`, `"x"`} {
		var op Operation
		if err := json.Unmarshal([]byte(in), &op); err == nil {
			t.Errorf("Operation %s decoded without error", in)
		}
	}
}
