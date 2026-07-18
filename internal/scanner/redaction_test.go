// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import "testing"

func TestRedactionSecretValuesNilScanner(t *testing.T) {
	t.Parallel()

	var sc *Scanner
	got := sc.RedactionSecretValues()
	if len(got.Env) != 0 || len(got.File) != 0 {
		t.Fatalf("nil scanner redaction values = %+v, want empty", got)
	}
}

func TestRedactionSecretValuesIncludesEncodedForms(t *testing.T) {
	t.Parallel()

	sc := &Scanner{
		envSecrets:  []string{"pa55", "pa55", "maze", ""},
		fileSecrets: []string{"file-secret"},
	}

	got := sc.RedactionSecretValues()
	assertContainsAll(t, got.Env,
		"pa55",
		"cGE1NQ==",
		"cGE1NQ",
		"70613535",
		"70613535",
		"70:61:35:35",
		"70 61 35 35",
		"70-61-35-35",
		"70,61,35,35",
		`\x70\x61\x35\x35`,
		"0x700x610x350x35",
		"6d617a65",
		"6D617A65",
		"OBQTKNI=",
		"OBQTKNI",
	)
	assertContainsAll(t, got.File, "file-secret")

	seen := map[string]bool{}
	for _, entry := range got.Env {
		if seen[entry] {
			t.Fatalf("duplicate redaction entry %q in %v", entry, got.Env)
		}
		seen[entry] = true
	}
}

func assertContainsAll(t *testing.T, got []string, want ...string) {
	t.Helper()

	seen := make(map[string]bool, len(got))
	for _, entry := range got {
		seen[entry] = true
	}
	for _, entry := range want {
		if !seen[entry] {
			t.Fatalf("redaction entries missing %q in %v", entry, got)
		}
	}
}
