// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRandFromCharsetInvalid(t *testing.T) {
	if _, err := randFromCharset(0, "abc"); err == nil {
		t.Fatal("want error for n <= 0")
	}
	if _, err := randFromCharset(4, ""); err == nil {
		t.Fatal("want error for empty charset")
	}
}

func TestSeedAWSCredentialsError(t *testing.T) {
	dir := t.TempDir()
	// Make ".aws" a regular file so MkdirAll fails ("not a directory").
	if err := os.WriteFile(filepath.Join(dir, ".aws"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := seedAWSCredentials(dir, "id", "secret"); err == nil {
		t.Fatal("want error when .aws is a file")
	}
}

func TestLiveCanaryValue(t *testing.T) {
	// The canary is a dead, AWS-access-key-shaped value generated with crypto/rand:
	// "AKIA" + 16 base32 chars, fresh per call (rotation), always the valid shape.
	got, err := liveCanaryValue()
	if err != nil {
		t.Fatalf("liveCanaryValue: %v", err)
	}
	if !isCanaryShape(got) {
		t.Fatalf("canary %q is not the synthetic AWS access-key shape", got)
	}
	other, err := liveCanaryValue()
	if err != nil {
		t.Fatalf("liveCanaryValue: %v", err)
	}
	if !isCanaryShape(other) {
		t.Fatalf("canary %q is not the synthetic AWS access-key shape", other)
	}
	if got == other {
		t.Fatal("canary values must rotate (be random) per call")
	}
}

func TestLiveSecretAccessKey(t *testing.T) {
	k, err := liveSecretAccessKey()
	if err != nil {
		t.Fatalf("liveSecretAccessKey: %v", err)
	}
	if len(k) != awsSecretKeyLen {
		t.Fatalf("secret key len = %d, want %d", len(k), awsSecretKeyLen)
	}
	for _, r := range k {
		if !strings.ContainsRune(awsSecretCharset, r) {
			t.Fatalf("secret key has out-of-charset rune %q", r)
		}
	}
	k2, err := liveSecretAccessKey()
	if err != nil {
		t.Fatalf("liveSecretAccessKey: %v", err)
	}
	if k == k2 {
		t.Fatal("secret keys must be random per call")
	}
}

func TestIsCanaryShape(t *testing.T) {
	good, err := liveCanaryValue()
	if err != nil {
		t.Fatalf("liveCanaryValue: %v", err)
	}
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"generated", good, true},
		{"wrong prefix", "BKIA234567ABCDEFGHIJ", false},
		{"too short", "AKIA2345", false},
		{"lowercase tail", "AKIA" + "abcdefghijklmnop", false},
		{"digit 0 not in base32", "AKIA" + "0000000000000000", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCanaryShape(tc.in); got != tc.want {
				t.Fatalf("isCanaryShape(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestLookupPlaygroundScenario(t *testing.T) {
	scenario, ok := lookupPlaygroundScenario(LiveDemoScenarioID)
	if !ok {
		t.Fatal("live demo scenario not found")
	}
	if scenario.ID != LiveDemoScenarioID {
		t.Fatalf("scenario ID = %q", scenario.ID)
	}
	const wantShape = "AKIA••••••••••EXAMPLE → exfiltrated"
	if scenario.RedactedShape != wantShape {
		t.Fatalf("redacted shape = %q, want %q", scenario.RedactedShape, wantShape)
	}

	if _, ok := lookupPlaygroundScenario("missing-playground-scenario"); ok {
		t.Fatal("unexpected scenario match")
	}
}
