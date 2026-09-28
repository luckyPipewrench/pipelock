// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPublicKeyAsOpened(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(pub)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "k.hex")
	if err := os.WriteFile(keyFile, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.hex"), []byte("zz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sep := string(filepath.Separator)
	for _, tc := range []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "inline hex", input: keyHex},
		{name: "file", input: keyFile},
		{name: "unparseable file", input: filepath.Join(dir, "bad.hex"), wantErr: "parsing public key file"},
		{name: "missing file", input: filepath.Join(dir, "absent.hex"), wantErr: "reading public key file"},
		{name: "file before dot-dot", input: keyFile + sep + ".." + sep + "k.hex", wantErr: "reading public key"},
		{name: "empty", input: " ", wantErr: "public key is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LoadPublicKeyAsOpened(tc.input)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LoadPublicKeyAsOpened(%q) = %v, want error containing %q", tc.input, err, tc.wantErr)
				}
				return
			}
			if err != nil || !got.Equal(pub) {
				t.Fatalf("LoadPublicKeyAsOpened(%q) = %x, %v", tc.input, got, err)
			}
		})
	}
}
