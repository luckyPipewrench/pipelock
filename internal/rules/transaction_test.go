// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRecoverBundleTransactionsCandidateActiveMergesFreshnessIdempotently(t *testing.T) {
	rulesDir := t.TempDir()
	name := "transaction-rules"
	priorData, _ := writeTransactionTestBundle(t, filepath.Join(rulesDir, name), transactionBundle("2026.01.0"))
	candidate := transactionBundle("2026.02.0")
	candidateData, candidateLock := transactionBundleBytes(t, candidate)
	next := &FreshnessState{HighestSeen: map[string]uint64{"community:" + name: 5}, FormatFloor: map[string]int{name: 2}}
	redo, err := NewBundleTransactionRedo(name, candidateData, nil, candidate, candidateLock, next)
	if err != nil {
		t.Fatalf("NewBundleTransactionRedo: %v", err)
	}
	record, err := WriteBundleTransactionRedo(rulesDir, redo)
	if err != nil {
		t.Fatalf("WriteBundleTransactionRedo: %v", err)
	}
	if err := os.Rename(filepath.Join(rulesDir, name), filepath.Join(rulesDir, name+".bak")); err != nil {
		t.Fatalf("move prior bundle: %v", err)
	}
	writeTransactionTestBundle(t, filepath.Join(rulesDir, name), candidate)
	if err := SaveFreshnessState(rulesDir, &FreshnessState{HighestSeen: map[string]uint64{"community:" + name: 8, "community:other": 9}, FormatFloor: map[string]int{name: 3}}); err != nil {
		t.Fatalf("seed newer freshness state: %v", err)
	}

	if err := RecoverBundleTransactions(rulesDir); err != nil {
		t.Fatalf("RecoverBundleTransactions: %v", err)
	}
	assertTransactionBundleBytes(t, filepath.Join(rulesDir, name), candidateData)
	state, err := LoadFreshnessState(rulesDir)
	if err != nil {
		t.Fatalf("LoadFreshnessState: %v", err)
	}
	if got := state.HighestSeen["community:"+name]; got != 8 {
		t.Fatalf("highest seen = %d, want monotonic merge to preserve 8", got)
	}
	if got := state.FormatFloor[name]; got != 3 {
		t.Fatalf("format floor = %d, want monotonic merge to preserve 3", got)
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatalf("redo record remains after recovery: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, name+".bak")); !os.IsNotExist(err) {
		t.Fatalf("prior backup remains after recovery: %v", err)
	}
	if err := RecoverBundleTransactions(rulesDir); err != nil {
		t.Fatalf("idempotent recovery: %v", err)
	}
	_ = priorData // documents that the first directory was a distinct prior artifact.
}

func TestRecoverBundleTransactionsRestoresOrClearsPreCandidatePhases(t *testing.T) {
	for _, tc := range []struct {
		name      string
		movePrior bool
	}{
		{name: "before prior rename"},
		{name: "after prior rename", movePrior: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			name := "transaction-rules"
			priorData, _ := writeTransactionTestBundle(t, filepath.Join(rulesDir, name), transactionBundle("2026.01.0"))
			candidate := transactionBundle("2026.02.0")
			candidateData, candidateLock := transactionBundleBytes(t, candidate)
			redo, err := NewBundleTransactionRedo(name, candidateData, nil, candidate, candidateLock, &FreshnessState{HighestSeen: map[string]uint64{"community:" + name: 5}, FormatFloor: map[string]int{name: 2}})
			if err != nil {
				t.Fatalf("NewBundleTransactionRedo: %v", err)
			}
			record, err := WriteBundleTransactionRedo(rulesDir, redo)
			if err != nil {
				t.Fatalf("WriteBundleTransactionRedo: %v", err)
			}
			if tc.movePrior {
				if err := os.Rename(filepath.Join(rulesDir, name), filepath.Join(rulesDir, name+".bak")); err != nil {
					t.Fatalf("move prior bundle: %v", err)
				}
			}
			if err := RecoverBundleTransactions(rulesDir); err != nil {
				t.Fatalf("RecoverBundleTransactions: %v", err)
			}
			assertTransactionBundleBytes(t, filepath.Join(rulesDir, name), priorData)
			if _, err := os.Stat(record); !os.IsNotExist(err) {
				t.Fatalf("redo record remains: %v", err)
			}
			if _, err := LoadFreshnessState(rulesDir); err != nil {
				t.Fatalf("pre-candidate recovery must not create or corrupt freshness state: %v", err)
			}
		})
	}
}

func TestRecoverBundleTransactionsFailsClosedOnCandidateMismatch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, dest string)
		want   string
	}{
		{
			name: "corrupt bundle",
			mutate: func(t *testing.T, dest string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dest, bundleFilename), []byte("corrupt"), 0o600); err != nil {
					t.Fatalf("corrupt candidate: %v", err)
				}
			},
			want: "candidate digest mismatch",
		},
		{
			name: "mismatched lock",
			mutate: func(t *testing.T, dest string) {
				t.Helper()
				lock, err := ReadLockFile(filepath.Join(dest, lockFilename))
				if err != nil {
					t.Fatalf("read candidate lock: %v", err)
				}
				lock.Source = "https://other.vendor.example/bundle.yaml"
				if err := WriteLockFile(filepath.Join(dest, lockFilename), lock); err != nil {
					t.Fatalf("mutate candidate lock: %v", err)
				}
			},
			want: "candidate lock mismatch",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			name := "transaction-rules"
			writeTransactionTestBundle(t, filepath.Join(rulesDir, name), transactionBundle("2026.01.0"))
			candidate := transactionBundle("2026.02.0")
			candidateData, candidateLock := transactionBundleBytes(t, candidate)
			redo, err := NewBundleTransactionRedo(name, candidateData, nil, candidate, candidateLock, &FreshnessState{HighestSeen: map[string]uint64{"community:" + name: 5}})
			if err != nil {
				t.Fatalf("NewBundleTransactionRedo: %v", err)
			}
			record, err := WriteBundleTransactionRedo(rulesDir, redo)
			if err != nil {
				t.Fatalf("WriteBundleTransactionRedo: %v", err)
			}
			if err := os.Rename(filepath.Join(rulesDir, name), filepath.Join(rulesDir, name+".bak")); err != nil {
				t.Fatalf("move prior bundle: %v", err)
			}
			writeTransactionTestBundle(t, filepath.Join(rulesDir, name), candidate)
			tc.mutate(t, filepath.Join(rulesDir, name))

			err = RecoverBundleTransactions(rulesDir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("RecoverBundleTransactions error = %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(record); err != nil {
				t.Fatalf("redo record was not preserved: %v", err)
			}
			if _, err := os.Stat(filepath.Join(rulesDir, name+".bak")); err != nil {
				t.Fatalf("prior backup was not preserved: %v", err)
			}
		})
	}
}

func TestLoadBundlesRecoversActiveTransactionBeforeReadingFreshness(t *testing.T) {
	rulesDir := t.TempDir()
	name := "transaction-rules"
	writeTransactionTestBundle(t, filepath.Join(rulesDir, name), transactionBundle("2026.01.0"))
	candidate := transactionBundle("2026.02.0")
	candidateData, candidateLock := transactionBundleBytes(t, candidate)
	redo, err := NewBundleTransactionRedo(name, candidateData, nil, candidate, candidateLock, &FreshnessState{HighestSeen: map[string]uint64{"community:" + name: 5}})
	if err != nil {
		t.Fatalf("NewBundleTransactionRedo: %v", err)
	}
	if _, err := WriteBundleTransactionRedo(rulesDir, redo); err != nil {
		t.Fatalf("WriteBundleTransactionRedo: %v", err)
	}
	if err := os.Rename(filepath.Join(rulesDir, name), filepath.Join(rulesDir, name+".bak")); err != nil {
		t.Fatalf("move prior bundle: %v", err)
	}
	writeTransactionTestBundle(t, filepath.Join(rulesDir, name), candidate)

	result := LoadBundles(rulesDir, LoadOptions{MinConfidence: confidenceLow, PipelockVersion: testPipelockVersion})
	if len(result.Errors) != 0 {
		t.Fatalf("LoadBundles errors = %v", result.Errors)
	}
	state, err := LoadFreshnessState(rulesDir)
	if err != nil {
		t.Fatalf("LoadFreshnessState: %v", err)
	}
	if got := state.HighestSeen["community:"+name]; got != 5 {
		t.Fatalf("recovered highest seen = %d, want 5", got)
	}
}

func TestBundleTransactionRedoRejectsInvalidInputsAndArtifacts(t *testing.T) {
	if path, err := WriteBundleTransactionRedo(t.TempDir(), nil); err != nil || path != "" {
		t.Fatalf("nil redo = %q, %v; want empty success", path, err)
	}
	bundle := transactionBundle("2026.02.0")
	data, lock := transactionBundleBytes(t, bundle)
	if _, err := NewBundleTransactionRedo(bundle.Name, data, nil, nil, lock, &FreshnessState{}); err == nil {
		t.Fatal("nil bundle accepted")
	}
	if _, err := NewBundleTransactionRedo("other", data, nil, bundle, lock, &FreshnessState{}); err == nil {
		t.Fatal("mismatched name accepted")
	}
	redo, err := NewBundleTransactionRedo(bundle.Name, data, []byte("signature"), bundle, lock, &FreshnessState{})
	if err != nil {
		t.Fatalf("NewBundleTransactionRedo: %v", err)
	}
	if _, err := WriteBundleTransactionRedo(t.TempDir(), &BundleTransactionRedo{}); err == nil {
		t.Fatal("invalid redo accepted")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, bundle.Name), 0o750); err != nil {
		t.Fatalf("create prior: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, bundle.Name, bundleFilename), data, 0o600); err != nil {
		t.Fatalf("write prior bundle: %v", err)
	}
	if _, err := WriteBundleTransactionRedo(dir, redo); err == nil || !strings.Contains(err.Error(), "fingerprint prior bundle") {
		t.Fatalf("WriteBundleTransactionRedo error = %v, want prior fingerprint failure", err)
	}
	nonEmpty := filepath.Join(t.TempDir(), "record.json")
	if err := os.Mkdir(nonEmpty, 0o750); err != nil {
		t.Fatalf("create record directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nonEmpty, "child"), []byte("x"), 0o600); err != nil {
		t.Fatalf("fill record directory: %v", err)
	}
	if err := RemoveBundleTransactionRedo(nonEmpty); err == nil {
		t.Fatal("non-empty record directory removed")
	}
}

func TestWriteBundleTransactionRedoRejectsOversizedState(t *testing.T) {
	bundle := transactionBundle("2026.02.0")
	data, lock := transactionBundleBytes(t, bundle)
	next := &FreshnessState{HighestSeen: make(map[string]uint64)}
	for i := 0; i < 30000; i++ {
		next.HighestSeen[fmt.Sprintf("community:bundle-%06d-long-identity", i)] = uint64(i)
	}
	redo, err := NewBundleTransactionRedo(bundle.Name, data, nil, bundle, lock, next)
	if err != nil {
		t.Fatalf("NewBundleTransactionRedo: %v", err)
	}
	if _, err := WriteBundleTransactionRedo(t.TempDir(), redo); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("WriteBundleTransactionRedo error = %v, want size rejection", err)
	}
}

func TestWriteBundleTransactionRedoSurfacesStorageAndDestinationFailures(t *testing.T) {
	bundle := transactionBundle("2026.02.0")
	data, lock := transactionBundleBytes(t, bundle)
	redo, err := NewBundleTransactionRedo(bundle.Name, data, nil, bundle, lock, &FreshnessState{})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("state parent is file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".pipelock-state"), []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := WriteBundleTransactionRedo(dir, redo); err == nil || !strings.Contains(err.Error(), "create bundle transaction directory") {
			t.Fatalf("write error = %v", err)
		}
	})
	t.Run("record path is directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(bundleTransactionPath(dir, bundle.Name), 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := WriteBundleTransactionRedo(dir, redo); err == nil || !strings.Contains(err.Error(), "write bundle transaction") {
			t.Fatalf("write error = %v", err)
		}
	})
	t.Run("destination fingerprint fails", func(t *testing.T) {
		dir := t.TempDir()
		record, err := WriteBundleTransactionRedo(dir, redo)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, bundle.Name, bundleFilename), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := RecoverBundleTransactions(dir); err == nil || !strings.Contains(err.Error(), "fingerprint destination") {
			t.Fatalf("recover error = %v", err)
		}
		if _, err := os.Stat(record); err != nil {
			t.Fatalf("record not preserved: %v", err)
		}
	})
}

func TestRecoverBundleTransactionsRejectsTransactionPathThatIsNotDirectory(t *testing.T) {
	dir := t.TempDir()
	transactionPath := filepath.Join(dir, ".pipelock-state", bundleTransactionDir)
	if err := os.MkdirAll(filepath.Dir(transactionPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(transactionPath, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecoverBundleTransactions(dir); err == nil || !strings.Contains(err.Error(), "read bundle transactions") {
		t.Fatalf("recover error = %v", err)
	}
}

func TestRecoverBundleTransactionsPreservesTamperedBackupAndFreshnessFailure(t *testing.T) {
	t.Run("tampered prior backup", func(t *testing.T) {
		rulesDir := t.TempDir()
		name := "transaction-rules"
		writeTransactionTestBundle(t, filepath.Join(rulesDir, name), transactionBundle("2026.01.0"))
		candidate := transactionBundle("2026.02.0")
		data, lock := transactionBundleBytes(t, candidate)
		redo, err := NewBundleTransactionRedo(name, data, nil, candidate, lock, &FreshnessState{})
		if err != nil {
			t.Fatal(err)
		}
		record, err := WriteBundleTransactionRedo(rulesDir, redo)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(rulesDir, name), filepath.Join(rulesDir, name+".bak")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rulesDir, name+".bak", lockFilename), []byte("tampered"), 0o600); err != nil {
			t.Fatal(err)
		}
		err = RecoverBundleTransactions(rulesDir)
		if err == nil || !strings.Contains(err.Error(), "prior backup does not match") {
			t.Fatalf("recover error = %v", err)
		}
		if _, err := os.Stat(record); err != nil {
			t.Fatalf("record not preserved: %v", err)
		}
		if _, err := os.Stat(filepath.Join(rulesDir, name+".bak")); err != nil {
			t.Fatalf("backup not preserved: %v", err)
		}
	})

	t.Run("active candidate with corrupt freshness", func(t *testing.T) {
		rulesDir := t.TempDir()
		name := "transaction-rules"
		writeTransactionTestBundle(t, filepath.Join(rulesDir, name), transactionBundle("2026.01.0"))
		candidate := transactionBundle("2026.02.0")
		data, lock := transactionBundleBytes(t, candidate)
		redo, err := NewBundleTransactionRedo(name, data, nil, candidate, lock, &FreshnessState{})
		if err != nil {
			t.Fatal(err)
		}
		record, err := WriteBundleTransactionRedo(rulesDir, redo)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(rulesDir, name), filepath.Join(rulesDir, name+".bak")); err != nil {
			t.Fatal(err)
		}
		writeTransactionTestBundle(t, filepath.Join(rulesDir, name), candidate)
		if err := os.WriteFile(filepath.Join(rulesDir, freshnessFilename), []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		err = RecoverBundleTransactions(rulesDir)
		if err == nil || !strings.Contains(err.Error(), "load freshness state") {
			t.Fatalf("recover error = %v", err)
		}
		if _, err := os.Stat(record); err != nil {
			t.Fatalf("record not preserved: %v", err)
		}
	})
}

func TestRecoverBundleTransactionsRejectsActiveCandidateWithUnreadableBackupArtifact(t *testing.T) {
	rulesDir := t.TempDir()
	name := "transaction-rules"
	writeTransactionTestBundle(t, filepath.Join(rulesDir, name), transactionBundle("2026.01.0"))
	candidate := transactionBundle("2026.02.0")
	data, lock := transactionBundleBytes(t, candidate)
	redo, err := NewBundleTransactionRedo(name, data, nil, candidate, lock, &FreshnessState{})
	if err != nil {
		t.Fatal(err)
	}
	record, err := WriteBundleTransactionRedo(rulesDir, redo)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(rulesDir, name), filepath.Join(rulesDir, name+".bak")); err != nil {
		t.Fatal(err)
	}
	writeTransactionTestBundle(t, filepath.Join(rulesDir, name), candidate)
	if err := os.Remove(filepath.Join(rulesDir, name+".bak", lockFilename)); err != nil {
		t.Fatal(err)
	}
	err = RecoverBundleTransactions(rulesDir)
	if err == nil || !strings.Contains(err.Error(), "fingerprint prior backup") {
		t.Fatalf("recover error = %v", err)
	}
	if _, err := os.Stat(record); err != nil {
		t.Fatalf("record not preserved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, name+".bak")); err != nil {
		t.Fatalf("backup not preserved: %v", err)
	}
}

func TestFreshnessConsumersFailClosedBeforeReadingInterruptedTransaction(t *testing.T) {
	rulesDir := t.TempDir()
	transactionDir := filepath.Join(rulesDir, ".pipelock-state", bundleTransactionDir)
	if err := os.MkdirAll(transactionDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(transactionDir, "broken.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFreshnessState(rulesDir); err == nil || !strings.Contains(err.Error(), "recover bundle transactions") {
		t.Fatalf("LoadFreshnessState error = %v, want recovery failure", err)
	}
	result := LoadBundles(rulesDir, LoadOptions{MinConfidence: confidenceLow, PipelockVersion: testPipelockVersion})
	if !result.Degraded || len(result.Errors) != 1 || result.Errors[0].Name != ".pipelock-state/rules-transactions" {
		t.Fatalf("LoadBundles result = %+v, want degraded transaction integrity failure", result)
	}
}

func TestRecoverBundleTransactionsRejectsMalformedRecordLayouts(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T, dir string)
	}{
		{
			name: "unexpected entry",
			make: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, "unexpected.txt"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "duplicate json keys",
			make: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, "record.json"), []byte(`{"version":1,"version":1}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			dir := filepath.Join(rulesDir, ".pipelock-state", bundleTransactionDir)
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			tc.make(t, dir)
			if err := RecoverBundleTransactions(rulesDir); err == nil || !strings.Contains(err.Error(), "fail-closed") {
				t.Fatalf("RecoverBundleTransactions error = %v, want fail-closed rejection", err)
			}
		})
	}
}

func TestValidateActiveCandidateRejectsSignatureAndMetadataMismatches(t *testing.T) {
	rulesDir := t.TempDir()
	name := "transaction-rules"
	bundle := transactionBundle("2026.02.0")
	data, lock := transactionBundleBytes(t, bundle)
	writeTransactionTestBundle(t, filepath.Join(rulesDir, name), bundle)
	redo, err := NewBundleTransactionRedo(name, data, []byte("signature"), bundle, lock, &FreshnessState{})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateActiveCandidate(filepath.Join(rulesDir, name), redo); err == nil || !strings.Contains(err.Error(), "candidate signature") {
		t.Fatalf("validateActiveCandidate error = %v, want missing signature", err)
	}
	redo.Candidate.SignaturePresent = false
	if err := os.WriteFile(filepath.Join(rulesDir, name, bundleFilename+".sig"), []byte("unexpected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateActiveCandidate(filepath.Join(rulesDir, name), redo); err == nil || !strings.Contains(err.Error(), "unexpected candidate signature") {
		t.Fatalf("validateActiveCandidate error = %v, want unexpected signature", err)
	}
}

func TestBundleArtifactFingerprintRejectsMissingLockAndOversizedBundle(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, bundleFilename), []byte("bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bundleArtifactFingerprint(dir); err == nil || !strings.Contains(err.Error(), "bundle lock") {
		t.Fatalf("fingerprint error = %v", err)
	}
	over := make([]byte, MaxBundleFileSize+1)
	if err := os.WriteFile(filepath.Join(dir, bundleFilename), over, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bundleArtifactFingerprint(dir); err == nil || !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("fingerprint error = %v", err)
	}
}

func transactionBundle(version string) *Bundle {
	bundle := testBundle("transaction-rules", []Rule{testDLPRule("txx", confidenceHigh, StatusStable)})
	bundle.Version = version
	return bundle
}

func transactionBundleBytes(t *testing.T, bundle *Bundle) ([]byte, *LockFile) {
	t.Helper()
	data, err := yaml.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	sum := sha256.Sum256(data)
	return data, &LockFile{InstalledVersion: bundle.Version, Source: "test", BundleSHA256: hex.EncodeToString(sum[:]), Unsigned: true}
}

func writeTransactionTestBundle(t *testing.T, dir string, bundle *Bundle) ([]byte, *LockFile) {
	t.Helper()
	data, lock := transactionBundleBytes(t, bundle)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create bundle dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, bundleFilename), data, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := WriteLockFile(filepath.Join(dir, lockFilename), lock); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	return data, lock
}

func assertTransactionBundleBytes(t *testing.T, dir string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Clean(filepath.Join(dir, bundleFilename)))
	if err != nil {
		t.Fatalf("read installed bundle: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("bundle bytes = %q, want %q", got, want)
	}
}
