// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signingflag

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidenceview"
)

func genTestKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub
}

func TestParseTrustedSigners_EmptyReturnsNil(t *testing.T) {
	t.Parallel()
	got, err := ParseTrustedSigners(nil)
	if err != nil || got != nil {
		t.Fatalf("got (%v, %v), want (nil, nil)", got, err)
	}
}

func TestParseTrustedSigners_InlineWithSource(t *testing.T) {
	t.Parallel()
	pub := genTestKey(t)
	keyHex := hex.EncodeToString(pub)
	got, err := ParseTrustedSigners([]string{"inline=" + keyHex + ",source=ops runbook"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := evidenceview.TrustedKey{Source: "ops runbook", ProvenanceKind: "static inline", Location: "--trusted-signer"}
	if got[keyHex] != want {
		t.Fatalf("got %+v, want %+v", got[keyHex], want)
	}
}

func TestParseTrustedSigners_FileKeyDefaultSource(t *testing.T) {
	t.Parallel()
	pub := genTestKey(t)
	keyHex := hex.EncodeToString(pub)
	keyFile := filepath.Join(t.TempDir(), "signer.pub")
	if err := os.WriteFile(keyFile, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := ParseTrustedSigners([]string{"file=" + keyFile})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := evidenceview.TrustedKey{Source: DefaultSource, ProvenanceKind: "imported file", Location: keyFile}
	if got[keyHex] != want {
		t.Fatalf("got %+v, want %+v", got[keyHex], want)
	}
}

func TestParseTrustedSigners_TrailingCommaSkipped(t *testing.T) {
	t.Parallel()
	pub := genTestKey(t)
	keyHex := hex.EncodeToString(pub)
	got, err := ParseTrustedSigners([]string{"inline=" + keyHex + ","})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := got[keyHex]; !ok {
		t.Fatalf("got %+v, want key present", got)
	}
}

func TestParseTrustedSigners_DuplicateKeyRejected(t *testing.T) {
	t.Parallel()
	pub := genTestKey(t)
	keyHex := hex.EncodeToString(pub)
	keyFile := filepath.Join(t.TempDir(), "signer.pub")
	if err := os.WriteFile(keyFile, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := ParseTrustedSigners([]string{"inline=" + keyHex, "file=" + keyFile})
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("want duplicate-key error, got %v", err)
	}
}

func TestParseTrustedSigners_ErrorCases(t *testing.T) {
	t.Parallel()
	pub := genTestKey(t)
	keyHex := hex.EncodeToString(pub)
	keyFile := filepath.Join(t.TempDir(), "signer.pub")
	if err := os.WriteFile(keyFile, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"inline and file exclusive", "inline=" + keyHex + ",file=" + keyFile, "mutually exclusive"},
		{"neither inline nor file", "source=x", "one of inline= or file= is required"},
		{"unknown kv key", "inline=" + keyHex + ",color=green", "unknown key"},
		{"missing equals", "justakey", "expected key=value"},
		{"duplicate inline", "inline=" + keyHex + ",inline=" + keyHex, "inline= may appear only once"},
		{"duplicate file", "file=" + keyFile + ",file=" + keyFile, "file= may appear only once"},
		{"duplicate source", "inline=" + keyHex + ",source=one,source=two", "source= may appear only once"},
		{"empty inline", "inline= ", "inline= value is empty"},
		{"empty file", "file= ", "file= value is empty"},
		{"garbage key", "inline=zz-not-a-key", "parse public key"},
		{"unreadable file", "file=" + filepath.Join(t.TempDir(), "nope.pub"), "read key file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseTrustedSigners([]string{tc.in})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}
