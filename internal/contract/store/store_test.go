// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

var testNow = time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)

type testSigner struct {
	keyID     string
	principal string
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
}

func TestReloadAcceptsSignedManifestAndPersistsAccepted(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	raw := mustJSON(t, env)
	hash, err := st.WriteActive(raw, testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	state, err := st.Reload(testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if state.ManifestHash != hash {
		t.Fatalf("manifest hash = %q, want %q", state.ManifestHash, hash)
	}
	if len(state.Contracts) != 1 {
		t.Fatalf("contracts len = %d, want 1", len(state.Contracts))
	}
	if _, err := os.Stat(state.AcceptedPath); err != nil {
		t.Fatalf("accepted manifest missing: %v", err)
	}
	if _, err := os.Stat(st.journalPath()); err != nil {
		t.Fatalf("journal missing: %v", err)
	}
}

func TestReloadReadOnlyDoesNotPersistAcceptedOrJournal(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	if _, err := st.WriteActive(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	opts := testOptions(testRoster(signer), "", 0, 1)
	opts.ReadOnly = true
	if _, err := st.Reload(opts); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, err := os.Stat(st.manifestDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("manifest dir err = %v, want not exist", err)
	}
	if _, err := os.Stat(st.journalPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal err = %v, want not exist", err)
	}
}

func TestReloadReadOnlyJournalsRejections(t *testing.T) {
	st := New(t.TempDir())
	if err := os.MkdirAll(st.root, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(st.activePath(), []byte(`{"body":`), 0o600); err != nil {
		t.Fatalf("write active: %v", err)
	}
	opts := testOptions(testRoster(newTestSigner(t, "act-1", "alice")), "", 0, 1)
	opts.ReadOnly = true
	if _, err := st.Reload(opts); !errors.Is(err, ErrDecode) {
		t.Fatalf("Reload err = %v, want ErrDecode", err)
	}
	raw, err := os.ReadFile(st.journalPath())
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if !strings.Contains(string(raw), `"outcome":"rejected"`) {
		t.Fatalf("journal = %s, want rejected outcome", raw)
	}
}

func TestReloadRejectsEnvironmentMismatch(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", contract.Environment{ID: "dev", Tenant: "tenant", DeploymentID: "dep"}, signer)
	_, err := st.ValidateEnvelope(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrEnvironmentMismatch) {
		t.Fatalf("ValidateEnvelope err = %v, want ErrEnvironmentMismatch", err)
	}
}

func TestReloadRequiresDistinctDualControl(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	alice := newTestSigner(t, "act-1", "alice")
	bob := newTestSigner(t, "act-2", "bob")
	one := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), alice)
	if _, err := st.ValidateEnvelope(mustJSON(t, one), testOptions(testRoster(alice, bob), "", 0, 2)); !errors.Is(err, ErrDualControl) {
		t.Fatalf("one signature err = %v, want ErrDualControl", err)
	}
	two := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), alice, bob)
	if _, err := st.ValidateEnvelope(mustJSON(t, two), testOptions(testRoster(alice, bob), "", 0, 2)); err != nil {
		t.Fatalf("two signatures ValidateEnvelope: %v", err)
	}
}

func TestReloadRejectsPriorAndGenerationRegressions(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 2, "sha256:old", testEnv(), signer)
	opts := testOptions(testRoster(signer), "sha256:current", 1, 1)
	if _, err := st.ValidateEnvelope(mustJSON(t, env), opts); !errors.Is(err, ErrPriorManifest) {
		t.Fatalf("prior err = %v, want ErrPriorManifest", err)
	}
	opts.PreviousHash = "sha256:old"
	opts.PreviousGeneration = 2
	if _, err := st.ValidateEnvelope(mustJSON(t, env), opts); !errors.Is(err, ErrGeneration) {
		t.Fatalf("generation err = %v, want ErrGeneration", err)
	}
}

func TestReloadRejectsMissingContractHistory(t *testing.T) {
	st := New(t.TempDir())
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, "sha256:"+stringsOf("a", 64), 1, "sha256:genesis", testEnv(), signer)
	_, err := st.ValidateEnvelope(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrContractHistory) {
		t.Fatalf("ValidateEnvelope err = %v, want ErrContractHistory", err)
	}
}

func TestWriteOnceRejectsDifferentBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "object.json")
	if err := writeOnce(path, []byte("same\n")); err != nil {
		t.Fatalf("writeOnce first: %v", err)
	}
	if err := writeOnce(path, []byte("same\n")); err != nil {
		t.Fatalf("writeOnce same: %v", err)
	}
	if err := writeOnce(path, []byte("different\n")); !errors.Is(err, ErrWriteOnceConflict) {
		t.Fatalf("writeOnce different err = %v, want ErrWriteOnceConflict", err)
	}
}

func TestLatestAcceptedUsesImmutableManifestHistory(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env1 := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	raw1 := mustJSON(t, env1)
	hash1, err := st.WriteActive(raw1, testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("WriteActive gen1: %v", err)
	}
	if _, err := st.Reload(testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("Reload gen1: %v", err)
	}
	env2 := signedManifest(t, cHash, 2, hash1, testEnv(), signer)
	if _, err := st.WriteActive(mustJSON(t, env2), testOptions(testRoster(signer), hash1, 1, 1)); err != nil {
		t.Fatalf("WriteActive gen2: %v", err)
	}
	if _, err := st.Reload(testOptions(testRoster(signer), hash1, 1, 1)); err != nil {
		t.Fatalf("Reload gen2: %v", err)
	}
	if err := os.WriteFile(st.journalPath(), []byte(`{"outcome":"accepted","generation":99}`+"\n"), 0o600); err != nil {
		t.Fatalf("tamper journal: %v", err)
	}
	latest, err := st.LatestAccepted(testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("LatestAccepted: %v", err)
	}
	if latest.Envelope.Body.Generation != 2 {
		t.Fatalf("latest generation = %d, want 2", latest.Envelope.Body.Generation)
	}
	if len(latest.Contracts) != 1 {
		t.Fatalf("latest contracts len = %d, want 1", len(latest.Contracts))
	}
}

func TestWriteActiveChecksExpectedPrior(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:actual", testEnv(), signer)
	if _, err := st.WriteActive(mustJSON(t, env), testOptions(testRoster(signer), "sha256:other", 0, 1)); !errors.Is(err, ErrPriorManifest) {
		t.Fatalf("WriteActive err = %v, want ErrPriorManifest", err)
	}
}

func TestReloadRejectsInvalidActiveAndJournalsFailure(t *testing.T) {
	st := New(t.TempDir())
	if err := os.MkdirAll(st.root, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(st.activePath(), []byte(`{"body":`), 0o600); err != nil {
		t.Fatalf("write active: %v", err)
	}
	_, err := st.Reload(testOptions(testRoster(newTestSigner(t, "act-1", "alice")), "", 0, 1))
	if !errors.Is(err, ErrDecode) {
		t.Fatalf("Reload err = %v, want ErrDecode", err)
	}
	raw, err := os.ReadFile(st.journalPath())
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if !strings.Contains(string(raw), `"outcome":"rejected"`) {
		t.Fatalf("journal = %s, want rejected outcome", raw)
	}
}

func TestValidateEnvelopeRejectsSignatureAuthorityFailures(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	alice := newTestSigner(t, "act-1", "alice")
	base := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), alice)

	tests := []struct {
		name   string
		mutate func(*contract.ActiveManifestEnvelope)
		roster *signing.LoadedRoster
		want   error
	}{
		{
			name:   "nil_roster",
			roster: nil,
			want:   ErrSignature,
		},
		{
			name: "wrong_purpose",
			mutate: func(env *contract.ActiveManifestEnvelope) {
				env.Signatures[0].KeyPurpose = signing.PurposeReceiptSigning.String()
			},
			roster: testRoster(alice),
			want:   ErrSignature,
		},
		{
			name: "wrong_algorithm",
			mutate: func(env *contract.ActiveManifestEnvelope) {
				env.Signatures[0].Algorithm = "ed25519ph"
			},
			roster: testRoster(alice),
			want:   ErrSignature,
		},
		{
			name: "unknown_key",
			mutate: func(env *contract.ActiveManifestEnvelope) {
				env.Signatures[0].KeyID = "missing"
			},
			roster: testRoster(alice),
			want:   ErrSignature,
		},
		{
			name: "principal_mismatch",
			mutate: func(env *contract.ActiveManifestEnvelope) {
				env.Signatures[0].Principal = "mallory"
			},
			roster: testRoster(alice),
			want:   ErrSignature,
		},
		{
			name: "bad_signature_format",
			mutate: func(env *contract.ActiveManifestEnvelope) {
				env.Signatures[0].Signature = "ed25519:aabb"
			},
			roster: testRoster(alice),
			want:   ErrSignature,
		},
		{
			name: "bad_signature_bytes",
			mutate: func(env *contract.ActiveManifestEnvelope) {
				env.Signatures[0].Signature = "ed25519:" + stringsOf("0", 128)
			},
			roster: testRoster(alice),
			want:   ErrSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := base
			env.Signatures = append([]contract.ManifestSignature(nil), base.Signatures...)
			if tt.mutate != nil {
				tt.mutate(&env)
			}
			opts := testOptions(tt.roster, "", 0, 1)
			_, err := st.ValidateEnvelope(mustJSON(t, env), opts)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ValidateEnvelope err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestValidateEnvelopeRejectsRosterPurposeMismatch(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	alice := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), alice)
	roster := testRoster(alice)
	roster.Body.Keys[0].KeyPurpose = signing.PurposeReceiptSigning.String()
	_, err := st.ValidateEnvelope(mustJSON(t, env), testOptions(roster, "", 0, 1))
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("ValidateEnvelope err = %v, want ErrSignature", err)
	}
}

func TestValidateEnvelopeRejectsStructuralManifest(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	env.Body.SelectorSetHash = "sha256:wrong"
	_, err := st.ValidateEnvelope(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrStructural) {
		t.Fatalf("ValidateEnvelope err = %v, want ErrStructural", err)
	}
}

func TestLoadContractsRejectsDecodeAndHashMismatch(t *testing.T) {
	st := New(t.TempDir())
	badHash := "sha256:" + stringsOf("b", 64)
	if err := os.MkdirAll(filepath.Dir(st.historyPath(badHash)), 0o700); err != nil {
		t.Fatalf("mkdir history: %v", err)
	}
	if err := os.WriteFile(st.historyPath(badHash), []byte("{"), 0o600); err != nil {
		t.Fatalf("write bad contract: %v", err)
	}
	sel := contract.ManifestSelector{SelectorID: "sha256:s", ContractHash: badHash}
	if _, err := st.loadContracts([]contract.ManifestSelector{sel}); !errors.Is(err, ErrDecode) {
		t.Fatalf("decode err = %v, want ErrDecode", err)
	}

	goodHash := putTestContract(t, st)
	mismatch := "sha256:" + stringsOf("c", 64)
	if err := os.Rename(st.historyPath(goodHash), st.historyPath(mismatch)); err != nil {
		t.Fatalf("rename history: %v", err)
	}
	sel.ContractHash = mismatch
	if _, err := st.loadContracts([]contract.ManifestSelector{sel}); !errors.Is(err, ErrContractHistory) {
		t.Fatalf("mismatch err = %v, want ErrContractHistory", err)
	}
}

func TestPutHistoryContractRejectsDecodeAndHashMismatch(t *testing.T) {
	st := New(t.TempDir())
	if _, err := st.PutHistoryContract([]byte("{")); !errors.Is(err, ErrDecode) {
		t.Fatalf("decode err = %v, want ErrDecode", err)
	}
	c := contract.Contract{
		SchemaVersion:    contract.SchemaVersionContract,
		ContractKind:     contract.ContractKind,
		ContractHash:     "sha256:wrong",
		DataClassRoot:    "internal",
		FieldDataClasses: map[string]string{},
	}
	raw := mustJSON(t, contract.ContractEnvelope{Body: c, Signature: "ed25519:" + stringsOf("0", 128)})
	if _, err := st.PutHistoryContract(raw); !errors.Is(err, ErrContractHistory) {
		t.Fatalf("hash mismatch err = %v, want ErrContractHistory", err)
	}
}

func TestLatestAcceptedRejectsBadHistoryAndMissingHistory(t *testing.T) {
	st := New(t.TempDir())
	if _, err := st.LatestAccepted(Options{}); err == nil {
		t.Fatal("LatestAccepted on missing dir returned nil error")
	}
	if err := os.MkdirAll(st.manifestDir(), 0o700); err != nil {
		t.Fatalf("mkdir manifests: %v", err)
	}
	if _, err := st.LatestAccepted(Options{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LatestAccepted empty err = %v, want os.ErrNotExist", err)
	}
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, "sha256:"+stringsOf("d", 64), 1, "sha256:genesis", testEnv(), signer)
	if err := os.WriteFile(filepath.Join(st.manifestDir(), hashFilename("sha256:"+stringsOf("e", 64), jsonExt)), mustJSON(t, env), 0o600); err != nil {
		t.Fatalf("write bad accepted manifest: %v", err)
	}
	if _, err := st.LatestAccepted(testOptions(testRoster(signer), "", 0, 1)); !errors.Is(err, ErrContractHistory) {
		t.Fatalf("LatestAccepted mismatch err = %v, want ErrContractHistory", err)
	}
}

func TestHashHelpersSurfacePreimageErrors(t *testing.T) {
	_, err := ContractHash(contract.Contract{
		Defaults: contract.ContractDefaults{Confidence: map[string]any{"bad": make(chan int)}},
	})
	if err == nil {
		t.Fatal("ContractHash returned nil error for unmarshalable contract")
	}
}

func TestParseSignatureRejectsMalformedValues(t *testing.T) {
	for _, sig := range []string{
		"",
		"sha256:" + stringsOf("0", 128),
		"ed25519:aabb",
		"ed25519:" + stringsOf("z", 128),
	} {
		if _, err := parseSignature(sig); err == nil {
			t.Fatalf("parseSignature(%q) returned nil error", sig)
		}
	}
}

func TestNowDefaultsToWallClock(t *testing.T) {
	if now(Options{}).IsZero() {
		t.Fatal("now returned zero time")
	}
}

func TestReloadMissingActiveReturnsDecodeError(t *testing.T) {
	_, err := New(t.TempDir()).Reload(Options{})
	if !errors.Is(err, ErrNoActiveManifest) {
		t.Fatalf("Reload err = %v, want ErrNoActiveManifest", err)
	}
}

func TestReloadAcceptedManifestWriteConflict(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	raw := mustJSON(t, env)
	state, err := st.ValidateEnvelope(raw, testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("ValidateEnvelope: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(st.manifestPath(state.ManifestHash)), 0o700); err != nil {
		t.Fatalf("mkdir manifest: %v", err)
	}
	if err := os.WriteFile(st.manifestPath(state.ManifestHash), []byte("different\n"), 0o600); err != nil {
		t.Fatalf("write conflicting manifest: %v", err)
	}
	if err := os.WriteFile(st.activePath(), raw, 0o600); err != nil {
		t.Fatalf("write active: %v", err)
	}
	if _, err := st.Reload(testOptions(testRoster(signer), "", 0, 1)); !errors.Is(err, ErrWriteOnceConflict) {
		t.Fatalf("Reload err = %v, want ErrWriteOnceConflict", err)
	}
}

func TestReloadReturnsJournalAppendFailure(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	raw := mustJSON(t, env)
	state, err := st.ValidateEnvelope(raw, testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("ValidateEnvelope: %v", err)
	}
	accepted, err := encodeForStorage(state.Envelope)
	if err != nil {
		t.Fatalf("encodeForStorage: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(st.manifestPath(state.ManifestHash)), 0o700); err != nil {
		t.Fatalf("mkdir manifest: %v", err)
	}
	if err := os.WriteFile(st.manifestPath(state.ManifestHash), accepted, 0o600); err != nil {
		t.Fatalf("write accepted: %v", err)
	}
	if err := os.WriteFile(st.activePath(), raw, 0o600); err != nil {
		t.Fatalf("write active: %v", err)
	}
	restore := replaceOpenFile(func(name string, flag int, perm os.FileMode) (writableFile, error) {
		if strings.HasSuffix(name, journalFilename) {
			return nil, fmt.Errorf("forced open error")
		}
		return os.OpenFile(name, flag, perm) //nolint:gosec // Test seam delegates to the production path for non-journal files.
	})
	defer restore()
	if _, err := st.Reload(testOptions(testRoster(signer), "", 0, 1)); err == nil {
		t.Fatal("Reload returned nil error with journal open failure")
	}
}

func TestReloadDoesNotPersistAcceptedWhenJournalFails(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	raw := mustJSON(t, env)
	state, err := st.ValidateEnvelope(raw, testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("ValidateEnvelope: %v", err)
	}
	if err := os.WriteFile(st.activePath(), raw, 0o600); err != nil {
		t.Fatalf("write active: %v", err)
	}
	restore := replaceOpenFile(func(name string, flag int, perm os.FileMode) (writableFile, error) {
		if strings.HasSuffix(name, journalFilename) {
			return nil, fmt.Errorf("forced open error")
		}
		return os.OpenFile(name, flag, perm) //nolint:gosec // Test seam delegates to the production path for non-journal files.
	})
	defer restore()
	if _, err := st.Reload(testOptions(testRoster(signer), "", 0, 1)); err == nil {
		t.Fatal("Reload returned nil error with journal open failure")
	}
	if _, err := os.Stat(st.manifestPath(state.ManifestHash)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("accepted manifest err = %v, want not exist", err)
	}
}

func TestReloadPropagatesAcceptedMarshalFailure(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	if err := os.WriteFile(st.activePath(), mustJSON(t, env), 0o600); err != nil {
		t.Fatalf("write active: %v", err)
	}
	restore := replaceMarshalJSON(func(any) ([]byte, error) {
		return nil, fmt.Errorf("forced marshal error")
	})
	defer restore()
	if _, err := st.Reload(testOptions(testRoster(signer), "", 0, 1)); err == nil {
		t.Fatal("Reload returned nil error with marshal failure")
	}
}

func TestWriteActivePropagatesAtomicWriteError(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	restore := replaceAtomicWrite(func(string, []byte, os.FileMode) error {
		return fmt.Errorf("forced atomic write error")
	})
	defer restore()
	if _, err := st.WriteActive(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1)); err == nil {
		t.Fatal("WriteActive returned nil error with atomic write failure")
	}
}

func TestWriteActivePropagatesMkdirError(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	restore := replaceMkdirAll(func(string, os.FileMode) error {
		return fmt.Errorf("forced mkdir error")
	})
	defer restore()
	if _, err := st.WriteActive(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1)); err == nil {
		t.Fatal("WriteActive returned nil error with mkdir failure")
	}
}

func TestPutHistoryContractRejectsStructuralContract(t *testing.T) {
	st := New(t.TempDir())
	c := contract.Contract{
		SchemaVersion:    99,
		ContractKind:     contract.ContractKind,
		DataClassRoot:    "internal",
		FieldDataClasses: map[string]string{},
	}
	hash, err := ContractHash(c)
	if err != nil {
		t.Fatalf("ContractHash: %v", err)
	}
	c.ContractHash = hash
	raw := mustJSON(t, contract.ContractEnvelope{Body: c, Signature: "ed25519:" + stringsOf("0", 128)})
	if _, err := st.PutHistoryContract(raw); !errors.Is(err, ErrStructural) {
		t.Fatalf("PutHistoryContract err = %v, want ErrStructural", err)
	}
}

func TestPutHistoryContractRejectsWriteOnceConflict(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	if err := os.WriteFile(st.historyPath(cHash), []byte("different\n"), 0o600); err != nil {
		t.Fatalf("overwrite history: %v", err)
	}
	c := contract.Contract{
		SchemaVersion:    contract.SchemaVersionContract,
		ContractKind:     contract.ContractKind,
		SignerKeyID:      "compile-key",
		KeyPurpose:       signing.PurposeContractCompileSigning.String(),
		DataClassRoot:    "internal",
		FieldDataClasses: map[string]string{},
		Selector:         contract.Selector{Agent: "agent-a", SelectorID: "sha256:selector"},
	}
	hash, err := ContractHash(c)
	if err != nil {
		t.Fatalf("ContractHash: %v", err)
	}
	c.ContractHash = hash
	raw := mustJSON(t, contract.ContractEnvelope{Body: c, Signature: "ed25519:" + stringsOf("0", 128)})
	if _, err := st.PutHistoryContract(raw); !errors.Is(err, ErrWriteOnceConflict) {
		t.Fatalf("PutHistoryContract err = %v, want ErrWriteOnceConflict", err)
	}
}

func TestLatestAcceptedRejectsReadAndDecodeErrors(t *testing.T) {
	st := New(t.TempDir())
	if err := os.MkdirAll(st.manifestDir(), 0o700); err != nil {
		t.Fatalf("mkdir manifests: %v", err)
	}
	name := hashFilename("sha256:"+stringsOf("0", 64), jsonExt)
	if err := os.WriteFile(filepath.Join(st.manifestDir(), name), []byte("{"), 0o600); err != nil {
		t.Fatalf("write bad manifest: %v", err)
	}
	if _, err := st.LatestAccepted(Options{}); !errors.Is(err, ErrDecode) {
		t.Fatalf("LatestAccepted decode err = %v, want ErrDecode", err)
	}
	restore := replaceReadFile(func(string) ([]byte, error) {
		return nil, fmt.Errorf("forced read error")
	})
	defer restore()
	if _, err := st.LatestAccepted(Options{}); err == nil {
		t.Fatal("LatestAccepted returned nil error with read failure")
	}
}

func TestLatestAcceptedSkipsNonManifestEntries(t *testing.T) {
	st := New(t.TempDir())
	if err := os.MkdirAll(filepath.Join(st.manifestDir(), "nested"), 0o700); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.WriteFile(filepath.Join(st.manifestDir(), "notes.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatalf("write ignored: %v", err)
	}
	if _, err := st.LatestAccepted(Options{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LatestAccepted err = %v, want os.ErrNotExist", err)
	}
}

func TestLatestAcceptedRejectsForgedManifestWithMatchingFilename(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	env.Signatures[0].Signature = "ed25519:" + stringsOf("0", 128)
	hash, err := ActiveManifestHash(env.Body)
	if err != nil {
		t.Fatalf("ActiveManifestHash: %v", err)
	}
	if err := os.MkdirAll(st.manifestDir(), 0o700); err != nil {
		t.Fatalf("mkdir manifests: %v", err)
	}
	if err := os.WriteFile(st.manifestPath(hash), mustJSON(t, env), 0o600); err != nil {
		t.Fatalf("write forged manifest: %v", err)
	}
	if _, err := st.LatestAccepted(testOptions(testRoster(signer), "", 0, 1)); !errors.Is(err, ErrSignature) {
		t.Fatalf("LatestAccepted err = %v, want ErrSignature", err)
	}
}

func TestLatestAcceptedRejectsMissingContractHistory(t *testing.T) {
	st := New(t.TempDir())
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, "sha256:"+stringsOf("f", 64), 1, "sha256:genesis", testEnv(), signer)
	hash, err := ActiveManifestHash(env.Body)
	if err != nil {
		t.Fatalf("ActiveManifestHash: %v", err)
	}
	if err := os.MkdirAll(st.manifestDir(), 0o700); err != nil {
		t.Fatalf("mkdir manifests: %v", err)
	}
	if err := os.WriteFile(st.manifestPath(hash), mustJSON(t, env), 0o600); err != nil {
		t.Fatalf("write accepted manifest: %v", err)
	}
	if _, err := st.LatestAccepted(testOptions(testRoster(signer), "", 0, 1)); !errors.Is(err, ErrContractHistory) {
		t.Fatalf("LatestAccepted err = %v, want ErrContractHistory", err)
	}
}

func TestValidateEnvelopeAllowsEmptyExpectedEnvironmentAndDefaultSignatureCount(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	opts := testOptions(testRoster(signer), "", 0, 0)
	opts.Environment = contract.Environment{}
	if _, err := st.ValidateEnvelope(mustJSON(t, env), opts); err != nil {
		t.Fatalf("ValidateEnvelope: %v", err)
	}
}

func TestValidateEnvelopeSkipsDuplicateKeysAndPrincipals(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	alice1 := newTestSigner(t, "act-1", "alice")
	alice2 := newTestSigner(t, "act-2", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), alice1, alice1, alice2)
	_, err := st.ValidateEnvelope(mustJSON(t, env), testOptions(testRoster(alice1, alice2), "", 0, 2))
	if !errors.Is(err, ErrDualControl) {
		t.Fatalf("ValidateEnvelope err = %v, want ErrDualControl", err)
	}
}

func TestValidateEnvelopeRejectsActivationKeyWithoutPrincipal(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	if _, err := st.ValidateEnvelope(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1)); !errors.Is(err, ErrSignature) {
		t.Fatalf("ValidateEnvelope err = %v, want ErrSignature", err)
	}
}

func TestValidateEnvelopeRejectsClaimedPrincipalsWhenRosterPrincipalEmpty(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	first := newTestSigner(t, "act-1", "")
	second := newTestSigner(t, "act-2", "")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), first, second)
	env.Signatures[0].Principal = "alice"
	env.Signatures[1].Principal = "bob"
	if _, err := st.ValidateEnvelope(mustJSON(t, env), testOptions(testRoster(first, second), "", 0, 2)); !errors.Is(err, ErrSignature) {
		t.Fatalf("ValidateEnvelope err = %v, want ErrSignature", err)
	}
}

func TestValidateEnvelopeRejectsBadRosterPublicKeyHex(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	roster := testRoster(signer)
	roster.Body.Keys[0].PublicKeyHex = "not-hex"
	_, err := st.ValidateEnvelope(mustJSON(t, env), testOptions(roster, "", 0, 1))
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("ValidateEnvelope err = %v, want ErrSignature", err)
	}
}

func TestWriteOncePropagatesFilesystemErrors(t *testing.T) {
	t.Run("mkdir", func(t *testing.T) {
		restore := replaceMkdirAll(func(string, os.FileMode) error {
			return fmt.Errorf("forced mkdir error")
		})
		t.Cleanup(restore)
		if err := writeOnce(filepath.Join(t.TempDir(), "a", "object"), []byte("x")); err == nil {
			t.Fatal("writeOnce returned nil with mkdir failure")
		}
	})
	t.Run("read", func(t *testing.T) {
		restore := replaceReadFile(func(string) ([]byte, error) {
			return nil, fmt.Errorf("forced read error")
		})
		t.Cleanup(restore)
		if err := writeOnce(filepath.Join(t.TempDir(), "object"), []byte("x")); err == nil {
			t.Fatal("writeOnce returned nil with read failure")
		}
	})
	t.Run("atomic", func(t *testing.T) {
		restoreRead := replaceReadFile(func(string) ([]byte, error) {
			return nil, os.ErrNotExist
		})
		t.Cleanup(restoreRead)
		restoreAtomic := replaceAtomicWrite(func(string, []byte, os.FileMode) error {
			return fmt.Errorf("forced atomic write error")
		})
		t.Cleanup(restoreAtomic)
		if err := writeOnce(filepath.Join(t.TempDir(), "object"), []byte("x")); err == nil {
			t.Fatal("writeOnce returned nil with atomic write failure")
		}
	})
}

func TestEncodeForStoragePropagatesMarshalError(t *testing.T) {
	restore := replaceMarshalJSON(func(any) ([]byte, error) {
		return nil, fmt.Errorf("forced marshal error")
	})
	defer restore()
	if _, err := encodeForStorage(struct{}{}); err == nil {
		t.Fatal("encodeForStorage returned nil with marshal failure")
	}
	if err := appendJournalForTest(New(t.TempDir())); err == nil {
		t.Fatal("appendJournal returned nil with marshal failure")
	}
}

func TestAppendJournalPropagatesWriteAndCloseErrors(t *testing.T) {
	t.Run("write", func(t *testing.T) {
		restore := replaceOpenFile(func(string, int, os.FileMode) (writableFile, error) {
			return fakeWritableFile{writeErr: fmt.Errorf("forced write error")}, nil
		})
		t.Cleanup(restore)
		if err := appendJournalForTest(New(t.TempDir())); err == nil {
			t.Fatal("appendJournal returned nil with write failure")
		}
	})
	t.Run("close", func(t *testing.T) {
		restore := replaceOpenFile(func(string, int, os.FileMode) (writableFile, error) {
			return fakeWritableFile{closeErr: fmt.Errorf("forced close error")}, nil
		})
		t.Cleanup(restore)
		if err := appendJournalForTest(New(t.TempDir())); err == nil {
			t.Fatal("appendJournal returned nil with close failure")
		}
	})
}

func TestAppendJournalPropagatesMkdirError(t *testing.T) {
	restore := replaceMkdirAll(func(string, os.FileMode) error {
		return fmt.Errorf("forced mkdir error")
	})
	defer restore()
	if err := appendJournalForTest(New(t.TempDir())); err == nil {
		t.Fatal("appendJournal returned nil with mkdir failure")
	}
}

func appendJournalForTest(st Store) error {
	return st.withLock(func() error {
		return st.appendJournalLocked(JournalEntry{Outcome: "forced"})
	})
}

func TestLoadContractsRejectsStructurallyInvalidContract(t *testing.T) {
	st := New(t.TempDir())
	c := contract.Contract{
		SchemaVersion:    99,
		ContractKind:     contract.ContractKind,
		DataClassRoot:    "internal",
		FieldDataClasses: map[string]string{},
	}
	hash, err := ContractHash(c)
	if err != nil {
		t.Fatalf("ContractHash: %v", err)
	}
	c.ContractHash = hash
	raw := mustJSON(t, contract.ContractEnvelope{Body: c, Signature: "ed25519:" + stringsOf("0", 128)})
	if err := os.MkdirAll(filepath.Dir(st.historyPath(hash)), 0o700); err != nil {
		t.Fatalf("mkdir history: %v", err)
	}
	if err := os.WriteFile(st.historyPath(hash), raw, 0o600); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	sel := contract.ManifestSelector{SelectorID: "sha256:s", ContractHash: hash}
	if _, err := st.loadContracts([]contract.ManifestSelector{sel}); !errors.Is(err, ErrStructural) {
		t.Fatalf("loadContracts err = %v, want ErrStructural", err)
	}
}

func replaceReadFile(fn func(string) ([]byte, error)) func() {
	prev := readFile
	readFile = fn
	return func() { readFile = prev }
}

func replaceMkdirAll(fn func(string, os.FileMode) error) func() {
	prev := mkdirAll
	mkdirAll = fn
	return func() { mkdirAll = prev }
}

func replaceOpenFile(fn func(string, int, os.FileMode) (writableFile, error)) func() {
	prev := openFile
	openFile = fn
	return func() { openFile = prev }
}

func replaceAtomicWrite(fn func(string, []byte, os.FileMode) error) func() {
	prev := atomicWrite
	atomicWrite = fn
	return func() { atomicWrite = prev }
}

func replaceMarshalJSON(fn func(any) ([]byte, error)) func() {
	prev := marshalJSON
	marshalJSON = fn
	return func() { marshalJSON = prev }
}

type fakeWritableFile struct {
	writeErr error
	closeErr error
}

func (f fakeWritableFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return len(p), nil
}

func (f fakeWritableFile) Close() error {
	return f.closeErr
}

func putTestContract(t *testing.T, st Store) string {
	t.Helper()
	c := contract.Contract{
		SchemaVersion:    contract.SchemaVersionContract,
		ContractKind:     contract.ContractKind,
		SignerKeyID:      "compile-key",
		KeyPurpose:       signing.PurposeContractCompileSigning.String(),
		DataClassRoot:    "internal",
		FieldDataClasses: map[string]string{},
		Selector:         contract.Selector{Agent: "agent-a", SelectorID: "sha256:selector"},
	}
	hash, err := ContractHash(c)
	if err != nil {
		t.Fatalf("ContractHash: %v", err)
	}
	c.ContractHash = hash
	raw := mustJSON(t, contract.ContractEnvelope{Body: c, Signature: "ed25519:" + stringsOf("0", 128)})
	got, err := st.PutHistoryContract(raw)
	if err != nil {
		t.Fatalf("PutHistoryContract: %v", err)
	}
	if got != hash {
		t.Fatalf("PutHistoryContract hash = %q, want %q", got, hash)
	}
	return hash
}

func signedManifest(t *testing.T, cHash string, generation uint64, prior string, env contract.Environment, signers ...testSigner) contract.ActiveManifestEnvelope {
	t.Helper()
	selector := contract.ManifestSelector{Agent: "agent-a", ContractHash: cHash}
	id, err := selector.ComputeSelectorID()
	if err != nil {
		t.Fatalf("ComputeSelectorID: %v", err)
	}
	selector.SelectorID = id
	setHash, err := contract.ComputeSelectorSetHash([]contract.ManifestSelector{selector})
	if err != nil {
		t.Fatalf("ComputeSelectorSetHash: %v", err)
	}
	body := contract.ActiveManifest{
		SchemaVersion:     1,
		ManifestKind:      contract.ManifestKindActivation,
		Generation:        generation,
		PriorManifestHash: prior,
		SelectorSetHash:   setHash,
		Environment:       env,
		Selectors:         []contract.ManifestSelector{selector},
		HistoryRoot:       "contracts/history/",
		SignedAt:          testNow,
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	out := contract.ActiveManifestEnvelope{Body: body}
	for _, signer := range signers {
		sig := ed25519.Sign(signer.priv, preimage)
		out.Signatures = append(out.Signatures, contract.ManifestSignature{
			KeyID:      signer.keyID,
			Principal:  signer.principal,
			KeyPurpose: signing.PurposeContractActivationSigning.String(),
			Algorithm:  "ed25519",
			Signature:  "ed25519:" + hex.EncodeToString(sig),
		})
	}
	return out
}

func testOptions(roster *signing.LoadedRoster, previousHash string, previousGeneration uint64, required int) Options {
	return Options{
		Environment:        testEnv(),
		Roster:             roster,
		PreviousHash:       previousHash,
		PreviousGeneration: previousGeneration,
		MinSignatures:      required,
		Now:                func() time.Time { return testNow },
	}
}

func testRoster(signers ...testSigner) *signing.LoadedRoster {
	keys := make([]contract.KeyInfo, 0, len(signers))
	for _, signer := range signers {
		keys = append(keys, contract.KeyInfo{
			KeyID:        signer.keyID,
			KeyPurpose:   signing.PurposeContractActivationSigning.String(),
			PublicKeyHex: hex.EncodeToString(signer.pub),
			ValidFrom:    testNow.Add(-time.Hour).Format(time.RFC3339),
			Status:       contract.KeyStatusActive,
			Principal:    signer.principal,
		})
	}
	return &signing.LoadedRoster{Body: contract.KeyRoster{Keys: keys}}
}

func newTestSigner(t *testing.T, keyID, principal string) testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return testSigner{keyID: keyID, principal: principal, pub: pub, priv: priv}
}

func testEnv() contract.Environment {
	return contract.Environment{ID: "prod", Tenant: "tenant", DeploymentID: "deployment"}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return append(raw, '\n')
}

func stringsOf(s string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(s)
	}
	return b.String()
}
