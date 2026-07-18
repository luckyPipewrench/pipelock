// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"slices"
	"testing"
)

func TestFailSafeSensitivity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		opts      ClassificationOptions
		confident bool
		want      ActionSensitivity
	}{
		{name: "failsafe_low_confidence_protects", opts: ClassificationOptions{FailSafe: true}, confident: false, want: SensitivityProtected},
		{name: "failsafe_confident_stays_normal", opts: ClassificationOptions{FailSafe: true}, confident: true, want: SensitivityNormal},
		{name: "disabled_low_confidence_stays_normal", opts: ClassificationOptions{}, confident: false, want: SensitivityNormal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := failSafeSensitivity(tc.opts, tc.confident); got != tc.want {
				t.Fatalf("failSafeSensitivity(%+v, %v) = %s, want %s", tc.opts, tc.confident, got, tc.want)
			}
		})
	}
}

func TestIntentJSONHelpers(t *testing.T) {
	t.Parallel()

	if got := flattenJSONStrings(""); got != nil {
		t.Fatalf("empty JSON strings = %v, want nil", got)
	}
	malformed := `{"path":`
	if got := flattenJSONStrings(malformed); len(got) != 1 || got[0] != malformed {
		t.Fatalf("malformed JSON strings = %v, want raw input", got)
	}
	nested := flattenJSONStrings(`{"outer":{"path":"/repo/file.txt"},"items":["alpha",{"url":"https://api.vendor.example"}]}`)
	for _, want := range []string{"outer", "path", "/repo/file.txt", "items", "alpha", "url", "https://api.vendor.example"} {
		if !slices.Contains(nested, want) {
			t.Fatalf("nested JSON strings missing %q in %v", want, nested)
		}
	}

	if got := firstURLLikeValue([]string{"not a url", "https://api.vendor.example"}); got != "https://api.vendor.example" {
		t.Fatalf("firstURLLikeValue = %q, want HTTPS URL", got)
	}
	if got := firstURLLikeValue([]string{"not a url"}); got != "" {
		t.Fatalf("firstURLLikeValue without URL = %q, want empty", got)
	}

	if !hasWriteIntent(`{"path":"/repo/file.txt","content":"new"}`) {
		t.Fatal("decoded write intent was not detected")
	}
	if !hasWriteIntent(`{"path":"/repo/file.txt","content":`) {
		t.Fatal("fallback write intent was not detected")
	}
	if hasWriteIntent(`{"path":"/repo/file.txt"}`) {
		t.Fatal("path without content should not be write intent")
	}

	if !hasMutatingNetworkIntent(`{"webhook":"https://api.vendor.example/hook"}`) {
		t.Fatal("webhook key should be mutating network intent")
	}
	if !hasMutatingNetworkIntent(`{"method":"DELETE"`) {
		t.Fatal("fallback DELETE method should be mutating network intent")
	}
}

func TestMutatingNetworkMethodBranches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "decoded post", raw: `{"method":" POST "}`, want: true},
		{name: "decoded get", raw: `{"method":"GET"}`, want: false},
		{name: "decoded non string", raw: `{"method":7}`, want: false},
		{name: "nested patch", raw: `{"request":{"method":"PATCH"}}`, want: true},
		{name: "malformed put fallback", raw: `{"method":"PUT"`, want: true},
		{name: "malformed get fallback", raw: `{"method":"GET"`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := hasMutatingNetworkMethod(tt.raw); got != tt.want {
				t.Fatalf("hasMutatingNetworkMethod(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}

	if jsonWalk("scalar", func(string, any) bool { return true }) {
		t.Fatal("jsonWalk should ignore scalar values")
	}
	if decoded, ok := decodeJSONValue(""); ok || decoded != nil {
		t.Fatalf("decodeJSONValue(empty) = (%v, %v), want nil false", decoded, ok)
	}
	if !jsonWalk([]any{map[string]any{"needle": "value"}}, func(key string, _ any) bool {
		return key == "needle"
	}) {
		t.Fatal("jsonWalk should find keys inside arrays")
	}
}
