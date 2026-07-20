// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

func TestRecoveryAuthorizationRejectsMalformedYAML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body []byte
	}{
		{name: "unclosed sequence", body: []byte("body:\n  signature: [")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			now := time.Now().UTC().Truncate(time.Second)
			_, pub, fp := recoveryFixture(t, now, envelopeExtJSON)
			path := filepath.Join(t.TempDir(), "recovery_authorization.yaml")
			if err := os.WriteFile(path, tc.body, 0o600); err != nil {
				t.Fatalf("write malformed recovery authorization: %v", err)
			}

			loaded, err := LoadRecoveryAuthorization(path, pub, fp, testRecoveryTargetHash, now)
			if loaded != nil {
				t.Fatalf("malformed YAML returned loaded authorization: %#v", loaded)
			}
			if !errors.Is(err, ErrRecoveryDecode) {
				t.Fatalf("error = %v, want ErrRecoveryDecode", err)
			}
		})
	}
}

func TestLoadPublicKeyRejectsPathReadFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setup      func(t *testing.T) string
		wantPrefix string
	}{
		{
			name: "directory at key path",
			setup: func(t *testing.T) string {
				t.Helper()
				path := filepath.Join(t.TempDir(), "key.pub")
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatalf("mkdir key path: %v", err)
				}
				return path
			},
			wantPrefix: "reading public key:",
		},
		{
			name: "symlink loop",
			setup: func(t *testing.T) string {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("os.Symlink on Windows requires SeCreateSymbolicLinkPrivilege")
				}
				path := filepath.Join(t.TempDir(), "loop.pub")
				if err := os.Symlink(path, path); err != nil {
					t.Fatalf("create symlink loop: %v", err)
				}
				return path
			},
			wantPrefix: "reading public key:",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			loaded, err := LoadPublicKey(tc.setup(t))
			if loaded != nil {
				t.Fatalf("invalid path returned key: %x", []byte(loaded))
			}
			if err == nil {
				t.Fatal("expected public key load error, got nil")
			}
			if !strings.HasPrefix(err.Error(), tc.wantPrefix) {
				t.Fatalf("error = %v, want it to start with %q", err, tc.wantPrefix)
			}
		})
	}
}

func TestKeystoreGenerateAgentRejectsFilesystemCollisions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T, base string, agent string)
		wantErr string
	}{
		{
			name: "agent directory path is a file",
			setup: func(t *testing.T, base string, agent string) {
				t.Helper()
				agentsDir := filepath.Join(base, agentsSubdir)
				if err := os.MkdirAll(agentsDir, 0o750); err != nil {
					t.Fatalf("mkdir agents dir: %v", err)
				}
				if err := os.WriteFile(filepath.Join(agentsDir, agent), []byte("not a directory"), 0o600); err != nil {
					t.Fatalf("write agent path file: %v", err)
				}
			},
			wantErr: "creating agent directory",
		},
		{
			name: "private key path is a directory",
			setup: func(t *testing.T, base string, agent string) {
				t.Helper()
				agentDir := filepath.Join(base, agentsSubdir, agent)
				if err := os.MkdirAll(filepath.Join(agentDir, privateKeyFile), 0o750); err != nil {
					t.Fatalf("mkdir private key path: %v", err)
				}
			},
			wantErr: "saving private key",
		},
		{
			name: "public key path is a directory",
			setup: func(t *testing.T, base string, agent string) {
				t.Helper()
				agentDir := filepath.Join(base, agentsSubdir, agent)
				if err := os.MkdirAll(filepath.Join(agentDir, publicKeyFile), 0o750); err != nil {
					t.Fatalf("mkdir public key path: %v", err)
				}
			},
			wantErr: "saving public key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base := t.TempDir()
			const agent = "agent"
			tc.setup(t, base, agent)

			ks := NewKeystore(base)
			pub, err := ks.ForceGenerateAgent(agent)
			if pub != nil {
				t.Fatalf("failed ForceGenerateAgent returned public key: %x", []byte(pub))
			}
			if err == nil {
				t.Fatal("expected filesystem collision error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestKeystoreRejectsContainmentBoundaryFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "trusted directory symlink escapes base",
			run: func(t *testing.T) {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("os.Symlink on Windows requires SeCreateSymbolicLinkPrivilege")
				}

				base := t.TempDir()
				outside := t.TempDir()
				ks := NewKeystore(base)
				pub, err := ks.ForceGenerateAgent("source")
				if err != nil {
					t.Fatalf("generate source key: %v", err)
				}
				if len(pub) == 0 {
					t.Fatal("generated empty source public key")
				}
				if err := os.Symlink(outside, filepath.Join(base, trustedSubdir)); err != nil {
					t.Fatalf("symlink trusted dir: %v", err)
				}

				err = ks.TrustKey("peer", ks.PublicKeyPath("source"))
				if err == nil {
					t.Fatal("expected trusted directory containment error, got nil")
				}
				if !strings.Contains(err.Error(), "trusted keys directory containment check") {
					t.Fatalf("error = %v, want trusted keys containment failure", err)
				}
				if entries, readErr := os.ReadDir(outside); readErr != nil {
					t.Fatalf("read outside dir: %v", readErr)
				} else if len(entries) != 0 {
					t.Fatalf("trusted key written outside keystore: %v", entries)
				}
			},
		},
		{
			name: "missing base directory",
			run: func(t *testing.T) {
				t.Helper()

				path := t.TempDir()
				ks := NewKeystore(filepath.Join(t.TempDir(), "missing-base"))
				err := ks.validateContainment(path)
				if err == nil {
					t.Fatal("expected missing base containment error, got nil")
				}
				if !strings.Contains(err.Error(), "resolving base dir") {
					t.Fatalf("error = %v, want base dir resolution failure", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t)
		})
	}
}

func TestRosterInternalTrustGatesRejectImpossibleLoaderStates(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name    string
		run     func() error
		wantErr error
	}{
		{
			name: "root key id missing",
			run: func() error {
				_, err := findRootKey(contract.KeyRoster{
					RosterSignedBy: "missing-root",
					Keys: []contract.KeyInfo{
						{
							KeyID:        "other-root",
							KeyPurpose:   string(PurposeRosterRoot),
							PublicKeyHex: testRosterPubHex,
							ValidFrom:    now.Add(-time.Minute).Format(time.RFC3339),
							Status:       contract.KeyStatusRoot,
						},
					},
				})
				return err
			},
			wantErr: ErrRosterRootMissing,
		},
		{
			name: "resolve key rejects unknown status",
			run: func() error {
				roster := &LoadedRoster{Body: contract.KeyRoster{Keys: []contract.KeyInfo{
					{
						KeyID:        "runtime-key",
						KeyPurpose:   string(PurposeReceiptSigning),
						PublicKeyHex: testRosterPubHex,
						ValidFrom:    now.Add(-time.Minute).Format(time.RFC3339),
						Status:       "paused",
					},
				}}}
				_, err := roster.ResolveKey("runtime-key", now)
				return err
			},
			wantErr: ErrRosterKeyInvalidStatus,
		},
		{
			name: "authorize rejects invalid key purpose",
			run: func() error {
				roster := &LoadedRoster{Body: contract.KeyRoster{Keys: []contract.KeyInfo{
					{
						KeyID:        "runtime-key",
						KeyPurpose:   "receipt-signer-typo",
						PublicKeyHex: testRosterPubHex,
						ValidFrom:    now.Add(-time.Minute).Format(time.RFC3339),
						Status:       contract.KeyStatusActive,
					},
				}}}
				return roster.AuthorizeSignerForPayload("proxy_decision", "runtime-key", now)
			},
			wantErr: ErrUnknownKeyPurpose,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.run()
			if err == nil {
				t.Fatalf("expected %v, got nil", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDecodePrivateKeyJSONRejectsMalformedTrailingData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "partial second object", input: `{"schema_version":1,"private":"aa"} {`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			priv, err := DecodePrivateKey(tc.input)
			if priv != nil {
				t.Fatalf("malformed JSON returned private key: %x", []byte(priv))
			}
			if err == nil {
				t.Fatal("expected trailing JSON decode error, got nil")
			}
			if !strings.Contains(err.Error(), "decoding JSON private key file") {
				t.Fatalf("error = %v, want JSON private key decode failure", err)
			}
		})
	}
}
