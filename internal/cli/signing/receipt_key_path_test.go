// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// A --key file path is read as the operating system opens it, as every
// receipt verifier reads it: "link/../keys/k.hex" names the key under the
// link's target, not the lexical keys/k.hex.
func TestVerifyReceipt_KeyFileResolvesSymlinkBeforeDotDot(t *testing.T) {
	signer := parityKey(t)
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherHex := hex.EncodeToString(other)
	evidence := parityFixture(t)
	dir := t.TempDir()
	for _, sub := range []string{filepath.Join("a", "keys"), filepath.Join("b", "keys"), filepath.Join("b", "sub")} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "b", "sub"), filepath.Join(dir, "a", "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	sep := string(filepath.Separator)
	input := filepath.Join(dir, "a", "link") + sep + ".." + sep + "keys" + sep + "k.hex"
	lexical := filepath.Join(dir, "a", "keys", "k.hex")
	opened := filepath.Join(dir, "b", "keys", "k.hex")
	for _, tc := range []struct {
		name            string
		lexKey, openKey string
		wantOK          bool
	}{
		{name: "signer at the opened path", lexKey: otherHex, openKey: signer, wantOK: true},
		{name: "signer only at the lexical path", lexKey: signer, openKey: otherHex},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(lexical, []byte(tc.lexKey+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(opened, []byte(tc.openKey+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := runParityVerify(t, "--chain", evidence, "--key", input)
			if (err == nil) != tc.wantOK {
				t.Fatalf("want valid=%t, got %v\n%s", tc.wantOK, err, out)
			}
		})
	}
}
