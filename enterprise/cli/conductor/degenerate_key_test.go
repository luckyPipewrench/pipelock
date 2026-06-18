//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"crypto/ed25519"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestLoadFleetReportSigningKey_RejectsDegenerate proves the conductor signing
// key loader inherits the seed->stored-pub consistency check: a JSON keyfile
// whose private AND public halves are both all-zero passes the loader's
// stored-pub-vs-declared-pub agreement check (both zero), so only the
// derivation check rejects it. This is a representative parallel path for the
// other direct JSON signing-key loaders, which apply the same consistency check.
func TestLoadFleetReportSigningKey_RejectsDegenerate(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		keyID   string
		wantErr bool
		makeKey func(*testing.T) ed25519.PrivateKey
	}{
		{
			name:    "rejects all-zero degenerate key",
			file:    "zero.key",
			keyID:   "zero-1",
			wantErr: true,
			makeKey: func(_ *testing.T) ed25519.PrivateKey {
				return ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))
			},
		},
		{
			name:  "accepts generated key",
			file:  "real.key",
			keyID: "real-1",
			makeKey: func(t *testing.T) ed25519.PrivateKey {
				_, realKey, err := ed25519.GenerateKey(nil)
				if err != nil {
					t.Fatalf("GenerateKey: %v", err)
				}
				return realKey
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			key := tc.makeKey(t)
			path := writeFleetReportKeyFile(t, dir, tc.file, tc.keyID, signing.PurposeFleetReportSigning, key)

			id, got, err := loadFleetReportSigningKey(path)
			if tc.wantErr {
				if err == nil {
					t.Fatal("loadFleetReportSigningKey accepted an all-zero degenerate key (fail-open)")
				}
				return
			}
			if err != nil {
				t.Fatalf("loadFleetReportSigningKey rejected a real key: %v", err)
			}
			if id != tc.keyID || !got.Equal(key) {
				t.Fatalf("unexpected load result: id=%q keyMatches=%v", id, got.Equal(key))
			}
		})
	}
}
