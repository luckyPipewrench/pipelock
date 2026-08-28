// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	domrules "github.com/luckyPipewrench/pipelock/internal/rules"
)

func TestRulesInstallRemoteRejectsPersistedRollbacks(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	fingerprint := hex.EncodeToString(pub)
	setRulesKeyringHexForTest(t, fingerprint)

	current := []byte(v2InstallBundleYAML("2026.08.0", 10, fingerprint))
	currentSignature := signInstallBundle(current, priv)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			_, _ = w.Write(currentSignature)
			return
		}
		_, _ = w.Write(current)
	}))
	defer server.Close()
	originalClient := httpsOnlyClient
	httpsOnlyClient = server.Client()
	httpsOnlyClient.CheckRedirect = originalClient.CheckRedirect
	t.Cleanup(func() { httpsOnlyClient = originalClient })

	tests := []struct {
		name      string
		candidate func() []byte
		update    bool
		want      string
	}{
		{
			name: "older monotonic version",
			candidate: func() []byte {
				return []byte(v2InstallBundleYAML("2026.09.0", 4, fingerprint))
			},
			want: "version rollback",
		},
		{
			name: "forced update stages older monotonic version without lowering floor",
			candidate: func() []byte {
				return []byte(v2InstallBundleYAML("2026.07.0", 4, fingerprint))
			},
			update: true,
		},
		{
			name: "older bundle format",
			candidate: func() []byte {
				return []byte(v1InstallBundleYAML("2026.07.0"))
			},
			want: "format rollback",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			current = []byte(v2InstallBundleYAML("2026.08.0", 10, fingerprint))
			currentSignature = signInstallBundle(current, priv)
			_ = installRemoteForFreshnessTest(t, rulesDir, server.URL+testBundlePath, "")
			installed := append([]byte(nil), current...)

			current = tc.candidate()
			currentSignature = signInstallBundle(current, priv)
			var err error
			if tc.update {
				err = updateRemoteForFreshnessTest(t, rulesDir)
			} else {
				err = installRemoteForFreshnessTest(t, rulesDir, server.URL+testBundlePath, tc.want)
			}
			if tc.update && tc.want == "" {
				if err != nil {
					t.Fatalf("forced update error = %v, want success", err)
				}
				assertInstalledBundleBytes(t, rulesDir, testBundleName, current)
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("install error = %v, want %q", err, tc.want)
				}
				assertInstalledBundleBytes(t, rulesDir, testBundleName, installed)
			}
			state, loadErr := domrules.LoadFreshnessState(rulesDir)
			if loadErr != nil {
				t.Fatalf("load freshness state: %v", loadErr)
			}
			if got := state.HighestSeen["community:"+testBundleName]; got != 10 {
				t.Fatalf("highest seen = %d, want 10", got)
			}
			if got := state.FormatFloor[testBundleName]; got != 2 {
				t.Fatalf("format floor = %d, want 2", got)
			}
		})
	}
}

func updateRemoteForFreshnessTest(t *testing.T, rulesDir string) error {
	t.Helper()
	cmd := testRootCmd()
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"rules", "update", testBundleName, "--force", "--rules-dir", rulesDir})
	return cmd.Execute()
}

func TestStageRemoteBundleWithFreshnessRejectsVersionRollbackBeforeStaging(t *testing.T) {
	rulesDir := t.TempDir()
	name := "community-rules"
	original := []byte(v2NamedInstallBundleYAML(name, "2026.08.0", domrules.TierCommunity, 10, "test-signer"))
	writeInstalledBundleForFreshnessTest(t, rulesDir, name, original)
	if err := domrules.SaveFreshnessState(rulesDir, &domrules.FreshnessState{
		HighestSeen: map[string]uint64{"community:" + name: 10},
		FormatFloor: map[string]int{name: 2},
	}); err != nil {
		t.Fatalf("save freshness state: %v", err)
	}

	bundle, lock := remoteFreshnessCandidate(name, 2, 4)
	err := stageRemoteBundleWithFreshness(rulesDir, bundle, []byte("older candidate bytes"), []byte("signature"), lock, false, false)
	if err == nil || !strings.Contains(err.Error(), "version rollback") {
		t.Fatalf("stageRemoteBundleWithFreshness error = %v, want version rollback", err)
	}
	assertInstalledBundleBytes(t, rulesDir, name, original)
	state, err := domrules.LoadFreshnessState(rulesDir)
	if err != nil {
		t.Fatalf("load freshness state: %v", err)
	}
	if got := state.HighestSeen["community:"+name]; got != 10 {
		t.Fatalf("highest seen = %d, want 10", got)
	}
}

func TestStageRemoteBundleWithFreshnessRejectsFormatRollbackBeforeStaging(t *testing.T) {
	rulesDir := t.TempDir()
	name := "community-rules"
	original := []byte(v2NamedInstallBundleYAML(name, "2026.08.0", domrules.TierCommunity, 10, "test-signer"))
	writeInstalledBundleForFreshnessTest(t, rulesDir, name, original)
	if err := domrules.SaveFreshnessState(rulesDir, &domrules.FreshnessState{
		HighestSeen: map[string]uint64{"community:" + name: 10},
		FormatFloor: map[string]int{name: 2},
	}); err != nil {
		t.Fatalf("save freshness state: %v", err)
	}

	bundle, lock := remoteFreshnessCandidate(name, 1, 0)
	err := stageRemoteBundleWithFreshness(rulesDir, bundle, []byte("v1 candidate bytes"), []byte("signature"), lock, false, false)
	if err == nil || !strings.Contains(err.Error(), "format rollback") {
		t.Fatalf("stageRemoteBundleWithFreshness error = %v, want format rollback", err)
	}
	assertInstalledBundleBytes(t, rulesDir, name, original)
}

func TestStageRemoteBundleWithFreshnessFirstInstallIsTrustOnFirstUse(t *testing.T) {
	rulesDir := t.TempDir()
	name := "community-rules"
	bundle, lock := remoteFreshnessCandidate(name, 2, 4)
	data := []byte("first accepted candidate")

	if err := stageRemoteBundleWithFreshness(rulesDir, bundle, data, []byte("signature"), lock, true, false); err != nil {
		t.Fatalf("stageRemoteBundleWithFreshness: %v", err)
	}
	assertInstalledBundleBytes(t, rulesDir, name, data)
	state, err := domrules.LoadFreshnessState(rulesDir)
	if err != nil {
		t.Fatalf("load freshness state: %v", err)
	}
	if got := state.HighestSeen["community:"+name]; got != 4 {
		t.Fatalf("highest seen = %d, want 4", got)
	}
	if got := state.FormatFloor[name]; got != 2 {
		t.Fatalf("format floor = %d, want 2", got)
	}
}

func TestStageRemoteBundleWithFreshnessRejectsExistingInstallAndV2Metadata(t *testing.T) {
	t.Run("existing install", func(t *testing.T) {
		rulesDir := t.TempDir()
		bundle, lock := remoteFreshnessCandidate("community-rules", 1, 0)
		bundle.Version = lock.InstalledVersion
		data := []byte(v1NamedInstallBundleYAML(bundle.Name, bundle.Version))
		if err := stageRemoteBundleWithFreshness(rulesDir, bundle, data, nil, lock, true, false); err != nil {
			t.Fatalf("first stage: %v", err)
		}
		err := stageRemoteBundleWithFreshness(rulesDir, bundle, data, nil, lock, true, false)
		if err == nil || !strings.Contains(err.Error(), "already installed") {
			t.Fatalf("second stage error = %v, want already installed", err)
		}
	})

	tests := []struct {
		name   string
		mutate func(*domrules.Bundle)
		want   string
	}{
		{
			name: "key binding",
			mutate: func(bundle *domrules.Bundle) {
				bundle.KeyID = "different-signer"
			},
			want: "key_id",
		},
		{
			name: "required feature",
			mutate: func(bundle *domrules.Bundle) {
				bundle.RequiredFeatures = []string{"unknown_feature"}
			},
			want: "requires unknown feature",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle, lock := remoteFreshnessCandidate("community-rules", 2, 1)
			tc.mutate(bundle)
			err := stageRemoteBundleWithFreshness(t.TempDir(), bundle, []byte("candidate"), []byte("signature"), lock, false, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("stage error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestStageRemoteBundleWithFreshnessRejectsCrossTierReplacement(t *testing.T) {
	const signer = "test-signer"
	rulesDir := t.TempDir()
	communityData := []byte(v2InstallBundleYAML("2026.08.0", 10, signer))
	community, err := domrules.ParseBundle(communityData)
	if err != nil {
		t.Fatalf("parse community bundle: %v", err)
	}
	_, communityLock := remoteFreshnessCandidate(testBundleName, 2, 10)
	communityLock.InstalledVersion = community.Version
	if err := stageRemoteBundleWithFreshness(rulesDir, community, communityData, []byte("signature"), communityLock, false, false); err != nil {
		t.Fatalf("stage community bundle: %v", err)
	}

	standardData := []byte(v2NamedInstallBundleYAML(testBundleName, "2026.07.0", domrules.TierStandard, 1, signer))
	standard, err := domrules.ParseBundle(standardData)
	if err != nil {
		t.Fatalf("parse standard bundle: %v", err)
	}
	_, standardLock := remoteFreshnessCandidate(testBundleName, 2, 1)
	standardLock.InstalledVersion = standard.Version
	err = stageRemoteBundleWithFreshness(rulesDir, standard, standardData, []byte("signature"), standardLock, false, false)
	if err == nil || !strings.Contains(err.Error(), "tier change") {
		t.Fatalf("cross-tier stage error = %v, want tier change rejection", err)
	}
	assertInstalledBundleBytes(t, rulesDir, testBundleName, communityData)
}

func TestStageBundleTransactionRestoresInstalledBytesWhenCommitFails(t *testing.T) {
	rulesDir := t.TempDir()
	const name = "transaction-test"
	original := []byte("original bundle bytes")
	if err := stageBundle(rulesDir, name, original, nil, &domrules.LockFile{InstalledVersion: "1"}); err != nil {
		t.Fatalf("stage original bundle: %v", err)
	}
	state := &domrules.FreshnessState{HighestSeen: map[string]uint64{"community:" + name: 4}, FormatFloor: map[string]int{name: 2}}
	if err := domrules.SaveFreshnessState(rulesDir, state); err != nil {
		t.Fatalf("save original freshness state: %v", err)
	}

	next := &domrules.FreshnessState{HighestSeen: map[string]uint64{"community:" + name: 5}, FormatFloor: map[string]int{name: 2}}
	saveCalls := 0
	err := stageBundleTransaction(rulesDir, name, []byte("replacement bundle bytes"), nil, &domrules.LockFile{InstalledVersion: "2"}, func() error {
		return commitFreshnessStateWithSave(rulesDir, next, state, func(dir string, candidate *domrules.FreshnessState) error {
			saveCalls++
			if saveErr := domrules.SaveFreshnessState(dir, candidate); saveErr != nil {
				return saveErr
			}
			if saveCalls == 1 {
				return errors.New("forced freshness commit failure")
			}
			return nil
		})
	})
	if err == nil || !strings.Contains(err.Error(), "forced freshness commit failure") {
		t.Fatalf("stageBundleTransaction error = %v, want forced commit failure", err)
	}
	assertInstalledBundleBytes(t, rulesDir, name, original)
	got, loadErr := domrules.LoadFreshnessState(rulesDir)
	if loadErr != nil {
		t.Fatalf("load freshness state: %v", loadErr)
	}
	if got.HighestSeen["community:"+name] != 4 || got.FormatFloor[name] != 2 {
		t.Fatalf("freshness state changed after failed commit: %+v", got)
	}
	if saveCalls != 2 {
		t.Fatalf("freshness save calls = %d, want failed commit plus restoration", saveCalls)
	}
}

func TestStageBundleTransactionWithRedoRestoresPriorBundleAndClearsRedoOnCommitFailure(t *testing.T) {
	rulesDir := t.TempDir()
	const name = "redo-rollback-test"
	prior := []byte(v1NamedInstallBundleYAML(name, "2026.01.0"))
	if err := stageBundle(rulesDir, name, prior, nil, &domrules.LockFile{InstalledVersion: "2026.01.0", BundleSHA256: sha256Hex(prior), Unsigned: true}); err != nil {
		t.Fatalf("stage prior bundle: %v", err)
	}
	candidateData := []byte(v2NamedInstallBundleYAML(name, "2026.02.0", domrules.TierCommunity, 5, "test-signer"))
	candidate, err := domrules.ParseBundle(candidateData)
	if err != nil {
		t.Fatalf("parse candidate: %v", err)
	}
	lock := &domrules.LockFile{InstalledVersion: candidate.Version, BundleSHA256: sha256Hex(candidateData), SignerFingerprint: "test-signer"}
	next := &domrules.FreshnessState{HighestSeen: map[string]uint64{"community:" + name: 5}, FormatFloor: map[string]int{name: 2}}
	redo, err := domrules.NewBundleTransactionRedo(name, candidateData, nil, candidate, lock, next)
	if err != nil {
		t.Fatalf("prepare redo: %v", err)
	}
	err = stageBundleTransactionWithRedo(rulesDir, name, candidateData, nil, lock, redo, func() error {
		return errors.New("forced freshness commit failure")
	})
	if err == nil || !strings.Contains(err.Error(), "forced freshness commit failure") {
		t.Fatalf("stageBundleTransactionWithRedo error = %v", err)
	}
	assertInstalledBundleBytes(t, rulesDir, name, prior)
	if _, err := os.Stat(filepath.Join(rulesDir, ".pipelock-state", "rules-transactions")); err == nil {
		entries, readErr := os.ReadDir(filepath.Join(rulesDir, ".pipelock-state", "rules-transactions"))
		if readErr != nil || len(entries) != 0 {
			t.Fatalf("redo record remains after rollback: entries=%v err=%v", entries, readErr)
		}
	}
}

func TestFreshnessStagesRejectInterruptedTransactionAndInvalidRedoPreparation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage func(string, *domrules.Bundle, []byte, *domrules.LockFile) error
	}{
		{
			name: "local",
			stage: func(dir string, bundle *domrules.Bundle, data []byte, lock *domrules.LockFile) error {
				return stageLocalBundleWithFormatFloor(dir, bundle, data, lock, false)
			},
		},
		{
			name: "remote",
			stage: func(dir string, bundle *domrules.Bundle, data []byte, lock *domrules.LockFile) error {
				return stageRemoteBundleWithFreshness(dir, bundle, data, nil, lock, false, false)
			},
		},
	} {
		t.Run(tc.name+" interrupted transaction", func(t *testing.T) {
			rulesDir := t.TempDir()
			transactionDir := filepath.Join(rulesDir, ".pipelock-state", "rules-transactions")
			if err := os.MkdirAll(transactionDir, 0o750); err != nil {
				t.Fatalf("create transaction directory: %v", err)
			}
			if err := os.WriteFile(filepath.Join(transactionDir, "corrupt.json"), []byte("not json"), 0o600); err != nil {
				t.Fatalf("write corrupt transaction: %v", err)
			}
			data := []byte(v1NamedInstallBundleYAML("transaction-rules", "2026.01.0"))
			bundle, err := domrules.ParseBundle(data)
			if err != nil {
				t.Fatalf("parse candidate: %v", err)
			}
			err = tc.stage(rulesDir, bundle, data, &domrules.LockFile{InstalledVersion: bundle.Version, BundleSHA256: sha256Hex(data), Unsigned: true})
			if err == nil || !strings.Contains(err.Error(), "recovering rules transactions") {
				t.Fatalf("stage error = %v, want interrupted transaction rejection", err)
			}
		})

		t.Run(tc.name+" invalid redo preparation", func(t *testing.T) {
			data := []byte(v1NamedInstallBundleYAML("transaction-rules", "2026.01.0"))
			bundle, err := domrules.ParseBundle(data)
			if err != nil {
				t.Fatalf("parse candidate: %v", err)
			}
			err = tc.stage(t.TempDir(), bundle, data, nil)
			if err == nil || !strings.Contains(err.Error(), "prepare rules transaction") {
				t.Fatalf("stage error = %v, want redo preparation failure", err)
			}
		})
	}
}

func TestStageBundleTransactionWithRedoSurfacesRedoWriteFailure(t *testing.T) {
	rulesDir := t.TempDir()
	name := "redo-write-failure"
	data := []byte(v1NamedInstallBundleYAML(name, "2026.01.0"))
	bundle, err := domrules.ParseBundle(data)
	if err != nil {
		t.Fatalf("parse candidate: %v", err)
	}
	lock := &domrules.LockFile{InstalledVersion: bundle.Version, BundleSHA256: sha256Hex(data), Unsigned: true}
	redo, err := domrules.NewBundleTransactionRedo(name, data, nil, bundle, lock, &domrules.FreshnessState{})
	if err != nil {
		t.Fatalf("prepare redo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, ".pipelock-state"), []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("block transaction directory: %v", err)
	}
	err = stageBundleTransactionWithRedo(rulesDir, name, data, nil, lock, redo, nil)
	if err == nil || !strings.Contains(err.Error(), "writing bundle transaction redo") {
		t.Fatalf("stageBundleTransactionWithRedo error = %v, want redo write failure", err)
	}
}

func TestStageBundleTransactionWithRedoSurfacesRollbackAndRedoCleanupFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		commit func(t *testing.T, record string, dest string) error
		want   string
	}{
		{
			name: "rollback",
			commit: func(t *testing.T, _ string, dest string) error {
				t.Helper()
				if err := os.RemoveAll(dest); err != nil {
					t.Fatal(err)
				}
				return errors.New("commit failed")
			},
			want: "committing and restoring installed bundle",
		},
		{
			name: "cleanup after failed commit",
			commit: func(t *testing.T, record string, _ string) error {
				t.Helper()
				if err := os.Remove(record); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(record, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(record, "child"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				return errors.New("commit failed")
			},
			want: "clearing recovered transaction",
		},
		{
			name: "cleanup after success",
			commit: func(t *testing.T, record string, _ string) error {
				t.Helper()
				if err := os.Remove(record); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(record, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(record, "child"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				return nil
			},
			want: "removing bundle transaction redo",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			name := "redo-cleanup-" + strings.ReplaceAll(tc.name, " ", "-")
			data := []byte(v1NamedInstallBundleYAML(name, "2026.01.0"))
			bundle, err := domrules.ParseBundle(data)
			if err != nil {
				t.Fatal(err)
			}
			lock := &domrules.LockFile{InstalledVersion: bundle.Version, BundleSHA256: sha256Hex(data), Unsigned: true}
			redo, err := domrules.NewBundleTransactionRedo(name, data, nil, bundle, lock, &domrules.FreshnessState{})
			if err != nil {
				t.Fatal(err)
			}
			record, err := domrules.WriteBundleTransactionRedo(rulesDir, redo)
			if err != nil {
				t.Fatal(err)
			}
			err = stageBundleTransactionWithRedo(rulesDir, name, data, nil, lock, redo, func() error {
				return tc.commit(t, record, filepath.Join(rulesDir, name))
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("stageBundleTransactionWithRedo error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestStageAndRecoverySurfacePathErrors(t *testing.T) {
	badPath := filepath.Join(t.TempDir(), "bad\x00path")
	if err := stageBundle(t.TempDir(), "bad\x00name", []byte("candidate"), nil, &domrules.LockFile{}); err == nil {
		t.Fatal("stageBundle accepted invalid path")
	}
	if err := rollbackBundleTransaction(badPath, ""); err == nil || !strings.Contains(err.Error(), "preserving failed candidate") {
		t.Fatalf("rollbackBundleTransaction error = %v, want failed-candidate preservation error", err)
	}
	if err := recoverBundleTransaction(badPath); err == nil || !strings.Contains(err.Error(), "checking installed bundle recovery") {
		t.Fatalf("recoverBundleTransaction error = %v, want stat error", err)
	}
	symlinkDest := filepath.Join(t.TempDir(), "missing")
	if err := os.Symlink(symlinkDest+".bak", symlinkDest+".bak"); err != nil {
		t.Fatalf("create backup symlink loop: %v", err)
	}
	if err := recoverBundleTransaction(symlinkDest); err == nil || !strings.Contains(err.Error(), "checking prior bundle recovery") {
		t.Fatalf("recoverBundleTransaction backup error = %v, want backup stat error", err)
	}
	dest := filepath.Join(t.TempDir(), "candidate")
	if err := os.Mkdir(dest, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := rollbackBundleTransaction(dest, "\x00bad-backup"); err == nil || !strings.Contains(err.Error(), "restoring prior bundle") {
		t.Fatalf("rollbackBundleTransaction restore error = %v", err)
	}
}

func TestRulesResetFreshnessRejectsInterruptedTransaction(t *testing.T) {
	rulesDir := t.TempDir()
	transactionDir := filepath.Join(rulesDir, ".pipelock-state", "rules-transactions")
	if err := os.MkdirAll(transactionDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(transactionDir, "broken.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := testRootCmd()
	cmd.SetOut(&strings.Builder{})
	cmd.SetArgs([]string{"rules", "reset-freshness", "--rules-dir", rulesDir})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "recovering rules transactions") {
		t.Fatalf("reset-freshness error = %v, want recovery rejection", err)
	}
}

func TestRollbackBundleTransactionWithRenameReportsBothRestoreDirections(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "candidate")
	backup := filepath.Join(t.TempDir(), "prior")
	t.Run("prior restore fails but candidate returns", func(t *testing.T) {
		calls := 0
		err := rollbackBundleTransactionWithRename(dest, backup, func(_, _ string) error {
			calls++
			if calls == 2 {
				return errors.New("prior restore failed")
			}
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "restoring prior bundle") {
			t.Fatalf("rollback error = %v", err)
		}
	})
	t.Run("both restores fail", func(t *testing.T) {
		calls := 0
		err := rollbackBundleTransactionWithRename(dest, backup, func(_, _ string) error {
			calls++
			if calls > 1 {
				return fmt.Errorf("rename failure %d", calls)
			}
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "restoring failed candidate") {
			t.Fatalf("rollback error = %v", err)
		}
	})
}

func TestRecoverBundleTransactionWithRenameReportsBackupAndFailedCandidateFailures(t *testing.T) {
	t.Run("backup restore", func(t *testing.T) {
		dir := t.TempDir()
		dest := filepath.Join(dir, "bundle")
		backup := dest + ".bak"
		if err := os.Mkdir(backup, 0o750); err != nil {
			t.Fatal(err)
		}
		err := recoverBundleTransactionWithRename(dest, func(_, _ string) error { return errors.New("backup rename failed") })
		if err == nil || !strings.Contains(err.Error(), "recovering prior installed bundle") {
			t.Fatalf("recover error = %v", err)
		}
	})
	t.Run("failed candidate restore", func(t *testing.T) {
		dir := t.TempDir()
		dest := filepath.Join(dir, "bundle")
		failed := dest + ".failed"
		if err := os.Mkdir(failed, 0o750); err != nil {
			t.Fatal(err)
		}
		err := recoverBundleTransactionWithRename(dest, func(_, _ string) error { return errors.New("failed rename") })
		if err == nil || !strings.Contains(err.Error(), "recovering failed candidate") {
			t.Fatalf("recover error = %v", err)
		}
	})
}

func TestCheckInstalledBundleIdentityReadFailure(t *testing.T) {
	dest := t.TempDir()
	if err := os.Mkdir(filepath.Join(dest, "bundle.yaml"), 0o750); err != nil {
		t.Fatalf("create directory in bundle path: %v", err)
	}
	bundle, _ := remoteFreshnessCandidate("identity-read-failure", 1, 0)
	if err := checkInstalledBundleIdentity(dest, bundle, false); err == nil || !strings.Contains(err.Error(), "reading installed bundle identity") {
		t.Fatalf("checkInstalledBundleIdentity error = %v, want read failure", err)
	}
}

func TestRecoverBundleTransactionPrefersPriorBundle(t *testing.T) {
	rulesDir := t.TempDir()
	dest := filepath.Join(rulesDir, "recovery-test")
	if err := os.MkdirAll(dest+".bak", 0o750); err != nil {
		t.Fatalf("create backup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest+".bak", "bundle.yaml"), []byte("prior"), 0o600); err != nil {
		t.Fatalf("write backup: %v", err)
	}
	if err := os.MkdirAll(dest+".failed", 0o750); err != nil {
		t.Fatalf("create failed candidate: %v", err)
	}
	if err := recoverBundleTransaction(dest); err != nil {
		t.Fatalf("recoverBundleTransaction: %v", err)
	}
	assertInstalledBundleBytes(t, rulesDir, "recovery-test", []byte("prior"))
	if _, err := os.Stat(dest + ".failed"); !os.IsNotExist(err) {
		t.Fatalf("failed candidate remains after recovery: %v", err)
	}
}

func TestRecoverBundleTransactionRestoresFailedCandidateWithoutBackup(t *testing.T) {
	rulesDir := t.TempDir()
	dest := filepath.Join(rulesDir, "recovery-test")
	if err := os.MkdirAll(dest+".failed", 0o750); err != nil {
		t.Fatalf("create failed candidate: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest+".failed", "bundle.yaml"), []byte("candidate"), 0o600); err != nil {
		t.Fatalf("write failed candidate: %v", err)
	}
	if err := recoverBundleTransaction(dest); err != nil {
		t.Fatalf("recoverBundleTransaction: %v", err)
	}
	assertInstalledBundleBytes(t, rulesDir, "recovery-test", []byte("candidate"))
	if err := recoverBundleTransaction(dest); err != nil {
		t.Fatalf("recoverBundleTransaction existing destination: %v", err)
	}
}

func TestStageBundleTransactionFailedFirstInstallLeavesNoBundle(t *testing.T) {
	rulesDir := t.TempDir()
	err := stageBundleTransaction(rulesDir, "first-install", []byte("candidate"), nil, &domrules.LockFile{}, func() error {
		return errors.New("forced commit failure")
	})
	if err == nil || !strings.Contains(err.Error(), "forced commit failure") {
		t.Fatalf("stageBundleTransaction error = %v, want commit failure", err)
	}
	if _, statErr := os.Stat(filepath.Join(rulesDir, "first-install")); !os.IsNotExist(statErr) {
		t.Fatalf("failed first install remains: %v", statErr)
	}
}

func TestCommitFreshnessStateReportsFailedRestoration(t *testing.T) {
	calls := 0
	err := commitFreshnessStateWithSave(t.TempDir(), &domrules.FreshnessState{}, &domrules.FreshnessState{}, func(string, *domrules.FreshnessState) error {
		calls++
		return fmt.Errorf("save failure %d", calls)
	})
	if err == nil || !strings.Contains(err.Error(), "save failure 1") || !strings.Contains(err.Error(), "save failure 2") {
		t.Fatalf("commitFreshnessStateWithSave error = %v, want commit and restoration failures", err)
	}
}

func TestFreshnessStagingRejectsCorruptInstalledIdentity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage func(string, *domrules.Bundle, *domrules.LockFile) error
	}{
		{
			name: "local",
			stage: func(dir string, bundle *domrules.Bundle, lock *domrules.LockFile) error {
				return stageLocalBundleWithFormatFloor(dir, bundle, []byte("candidate"), lock, false)
			},
		},
		{
			name: "remote",
			stage: func(dir string, bundle *domrules.Bundle, lock *domrules.LockFile) error {
				return stageRemoteBundleWithFreshness(dir, bundle, []byte("candidate"), nil, lock, false, false)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			writeInstalledBundleForFreshnessTest(t, rulesDir, "corrupt-rules", []byte("not a bundle"))
			bundle, lock := remoteFreshnessCandidate("corrupt-rules", 1, 0)
			err := tc.stage(rulesDir, bundle, lock)
			if err == nil || !strings.Contains(err.Error(), "parsing installed bundle identity") {
				t.Fatalf("stage error = %v, want installed identity failure", err)
			}
		})
	}
}

func TestStageBundleFreshnessRejectsCorruptPersistedState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage func(string, *domrules.Bundle, *domrules.LockFile) error
	}{
		{
			name: "local",
			stage: func(rulesDir string, bundle *domrules.Bundle, lock *domrules.LockFile) error {
				return stageLocalBundleWithFormatFloor(rulesDir, bundle, []byte("candidate"), lock, false)
			},
		},
		{
			name: "remote",
			stage: func(rulesDir string, bundle *domrules.Bundle, lock *domrules.LockFile) error {
				return stageRemoteBundleWithFreshness(rulesDir, bundle, []byte("candidate"), nil, lock, false, false)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(rulesDir, ".freshness.json"), []byte("not json"), 0o600); err != nil {
				t.Fatalf("write corrupt state: %v", err)
			}
			bundle, lock := remoteFreshnessCandidate("community-rules", 1, 0)
			err := tc.stage(rulesDir, bundle, lock)
			if err == nil || !strings.Contains(err.Error(), "loading rules freshness state") {
				t.Fatalf("stage error = %v, want freshness load failure", err)
			}
		})
	}
}

func TestStageLocalBundleWithFormatFloorRejectsV1AfterV2(t *testing.T) {
	rulesDir := t.TempDir()
	name := "third-party-rules"
	original := []byte(v2NamedInstallBundleYAML(name, "2026.08.0", domrules.TierCommunity, 8, "test-signer"))
	writeInstalledBundleForFreshnessTest(t, rulesDir, name, original)
	if err := domrules.SaveFreshnessState(rulesDir, &domrules.FreshnessState{
		HighestSeen: map[string]uint64{"community:" + name: 8},
		FormatFloor: map[string]int{name: 2},
	}); err != nil {
		t.Fatalf("save freshness state: %v", err)
	}

	bundle, lock := remoteFreshnessCandidate(name, 1, 0)
	lock.Unsigned = true
	err := stageLocalBundleWithFormatFloor(rulesDir, bundle, []byte("v1 local candidate"), lock, false)
	if err == nil || !strings.Contains(err.Error(), "format rollback") {
		t.Fatalf("stageLocalBundleWithFormatFloor error = %v, want format rollback", err)
	}
	assertInstalledBundleBytes(t, rulesDir, name, original)
}

func TestFreshnessStagingRejectsInstalledV2DowngradeWithoutState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage func(string, *domrules.Bundle, []byte, *domrules.LockFile, bool) error
	}{
		{
			name: "local",
			stage: func(rulesDir string, bundle *domrules.Bundle, data []byte, lock *domrules.LockFile, force bool) error {
				lock.Unsigned = true
				return stageLocalBundleWithFormatFloor(rulesDir, bundle, data, lock, force)
			},
		},
		{
			name: "remote",
			stage: func(rulesDir string, bundle *domrules.Bundle, data []byte, lock *domrules.LockFile, force bool) error {
				return stageRemoteBundleWithFreshness(rulesDir, bundle, data, nil, lock, false, force)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			installed := []byte(v2NamedInstallBundleYAML("third-party-rules", "2026.08.0", domrules.TierCommunity, 8, "test-signer"))
			writeInstalledBundleForFreshnessTest(t, rulesDir, "third-party-rules", installed)
			writeInstalledLockForFreshnessTest(t, rulesDir, "third-party-rules", installed)
			candidate, lock := remoteFreshnessCandidate("third-party-rules", 1, 0)
			candidate.Version = "2026.07.0"
			err := tc.stage(rulesDir, candidate, []byte(v1NamedInstallBundleYAML(candidate.Name, candidate.Version)), lock, false)
			if err == nil || !strings.Contains(err.Error(), "format rollback") {
				t.Fatalf("stage error = %v, want installed-format rollback", err)
			}
			assertInstalledBundleBytes(t, rulesDir, candidate.Name, installed)

			candidateData := []byte(v1NamedInstallBundleYAML(candidate.Name, candidate.Version))
			if err := tc.stage(rulesDir, candidate, candidateData, lock, true); err != nil {
				t.Fatalf("forced format rollback: %v", err)
			}
			assertInstalledBundleBytes(t, rulesDir, candidate.Name, candidateData)
		})
	}
}

func TestFreshnessStagingRejectsOlderV1InstalledVersionUnlessForced(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage func(string, *domrules.Bundle, []byte, *domrules.LockFile, bool) error
	}{
		{
			name: "local",
			stage: func(rulesDir string, bundle *domrules.Bundle, data []byte, lock *domrules.LockFile, force bool) error {
				lock.Unsigned = true
				return stageLocalBundleWithFormatFloor(rulesDir, bundle, data, lock, force)
			},
		},
		{
			name: "remote",
			stage: func(rulesDir string, bundle *domrules.Bundle, data []byte, lock *domrules.LockFile, force bool) error {
				return stageRemoteBundleWithFreshness(rulesDir, bundle, data, nil, lock, true, force)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			name := "third-party-rules"
			installed := []byte(v1NamedInstallBundleYAML(name, "2026.08.0"))
			writeInstalledBundleForFreshnessTest(t, rulesDir, name, installed)
			writeInstalledLockForFreshnessTest(t, rulesDir, name, installed)

			candidateData := []byte(v1NamedInstallBundleYAML(name, "2026.07.0"))
			candidate, err := domrules.ParseBundle(candidateData)
			if err != nil {
				t.Fatalf("parse candidate: %v", err)
			}
			_, lock := remoteFreshnessCandidate(name, 1, 0)
			lock.InstalledVersion = candidate.Version
			lock.BundleSHA256 = sha256Hex(candidateData)

			err = tc.stage(rulesDir, candidate, candidateData, lock, false)
			if err == nil || !strings.Contains(err.Error(), "older than installed") {
				t.Fatalf("stage error = %v, want older-version rejection", err)
			}
			assertInstalledBundleBytes(t, rulesDir, name, installed)

			if err := tc.stage(rulesDir, candidate, candidateData, lock, true); err != nil {
				t.Fatalf("forced older v1 stage: %v", err)
			}
			assertInstalledBundleBytes(t, rulesDir, name, candidateData)
		})
	}
}

func TestFreshnessStagingAllowsEqualAndNewerV2Candidates(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage func(string, *domrules.Bundle, []byte, *domrules.LockFile) error
	}{
		{
			name: "local",
			stage: func(rulesDir string, bundle *domrules.Bundle, data []byte, lock *domrules.LockFile) error {
				lock.Unsigned = true
				return stageLocalBundleWithFormatFloor(rulesDir, bundle, data, lock, false)
			},
		},
		{
			name: "remote",
			stage: func(rulesDir string, bundle *domrules.Bundle, data []byte, lock *domrules.LockFile) error {
				return stageRemoteBundleWithFreshness(rulesDir, bundle, data, nil, lock, true, false)
			},
		},
	} {
		for _, version := range []struct {
			name      string
			version   string
			monotonic uint64
			wantSkip  bool
		}{
			{name: "equal", version: "2026.08.0", monotonic: 8, wantSkip: true},
			{name: "newer", version: "2026.09.0", monotonic: 9},
		} {
			t.Run(tc.name+" "+version.name, func(t *testing.T) {
				rulesDir := t.TempDir()
				installed := []byte(v2NamedInstallBundleYAML("third-party-rules", "2026.08.0", domrules.TierCommunity, 8, "test-signer"))
				writeInstalledBundleForFreshnessTest(t, rulesDir, "third-party-rules", installed)
				writeInstalledLockForFreshnessTest(t, rulesDir, "third-party-rules", installed)
				candidateData := []byte(v2NamedInstallBundleYAML("third-party-rules", version.version, domrules.TierCommunity, version.monotonic, "test-signer"))
				candidate, err := domrules.ParseBundle(candidateData)
				if err != nil {
					t.Fatalf("parse candidate: %v", err)
				}
				_, lock := remoteFreshnessCandidate(candidate.Name, 2, version.monotonic)
				lock.InstalledVersion = candidate.Version
				lock.BundleSHA256 = sha256Hex(candidateData)
				err = tc.stage(rulesDir, candidate, candidateData, lock)
				if version.wantSkip {
					if err == nil || !strings.Contains(err.Error(), "skipping") {
						t.Fatalf("equal candidate error = %v, want already-installed skip", err)
					}
				} else if err != nil {
					t.Fatalf("stage %s candidate: %v", version.name, err)
				}
				assertInstalledBundleBytes(t, rulesDir, candidate.Name, candidateData)
			})
		}
	}
}

func TestFreshnessStagingRejectsPersistedFormatFloorWithoutInstalledBundle(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage func(string, *domrules.Bundle, *domrules.LockFile) error
	}{
		{
			name: "local",
			stage: func(dir string, bundle *domrules.Bundle, lock *domrules.LockFile) error {
				return stageLocalBundleWithFormatFloor(dir, bundle, []byte("candidate"), lock, false)
			},
		},
		{
			name: "remote",
			stage: func(dir string, bundle *domrules.Bundle, lock *domrules.LockFile) error {
				return stageRemoteBundleWithFreshness(dir, bundle, []byte("candidate"), nil, lock, false, false)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			if err := domrules.SaveFreshnessState(rulesDir, &domrules.FreshnessState{FormatFloor: map[string]int{"floor-rules": 2}}); err != nil {
				t.Fatalf("save freshness state: %v", err)
			}
			bundle, lock := remoteFreshnessCandidate("floor-rules", 1, 0)
			err := tc.stage(rulesDir, bundle, lock)
			if err == nil || !strings.Contains(err.Error(), "format rollback") {
				t.Fatalf("stage error = %v, want persisted format rollback", err)
			}
		})
	}
}

func TestCheckInstalledBundleIdentityRejectsOversizedManifest(t *testing.T) {
	dest := t.TempDir()
	oversized := make([]byte, domrules.MaxBundleFileSize+1)
	if err := os.WriteFile(filepath.Join(dest, "bundle.yaml"), oversized, 0o600); err != nil {
		t.Fatalf("write oversized bundle: %v", err)
	}
	bundle, _ := remoteFreshnessCandidate("oversized", 1, 0)
	err := checkInstalledBundleIdentity(dest, bundle, false)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("checkInstalledBundleIdentity error = %v, want size rejection", err)
	}
}

func TestInstallLocalRejectsUnsignedV2WithoutRecordingFloor(t *testing.T) {
	rulesDir := t.TempDir()
	sourceDir := t.TempDir()
	bundle := []byte(v2InstallBundleYAML("2026.08.0", 1, "unsigned-test-key"))
	if err := os.WriteFile(filepath.Join(sourceDir, "bundle.yaml"), bundle, 0o600); err != nil {
		t.Fatalf("write local bundle: %v", err)
	}

	err := installLocal(&strings.Builder{}, rulesDir, sourceDir, true, true, false)
	if err == nil || !strings.Contains(err.Error(), "must be signed and installed from HTTPS") {
		t.Fatalf("installLocal error = %v, want signed HTTPS requirement", err)
	}
	if _, statErr := os.Stat(filepath.Join(rulesDir, ".freshness.json")); !os.IsNotExist(statErr) {
		t.Fatalf("freshness state exists after rejected unsigned v2 install: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(rulesDir, testBundleName)); !os.IsNotExist(statErr) {
		t.Fatalf("bundle directory exists after rejected unsigned v2 install: %v", statErr)
	}
}

func remoteFreshnessCandidate(name string, format int, monotonic uint64) (*domrules.Bundle, *domrules.LockFile) {
	const signer = "test-signer"
	return &domrules.Bundle{
			FormatVersion:    format,
			Name:             name,
			Tier:             domrules.TierCommunity,
			MonotonicVersion: monotonic,
			PublishedAt:      "2026-08-27T00:00:00Z",
			ExpiresAt:        "2030-01-01T00:00:00Z",
			KeyID:            signer,
		}, &domrules.LockFile{
			InstalledVersion:  "2026.08.0",
			InstalledAt:       "2026-08-27T00:00:00Z",
			Source:            "https://rules.example/bundle.yaml",
			LastCheck:         "2026-08-27T00:00:00Z",
			BundleSHA256:      "candidate-digest",
			SignerFingerprint: signer,
		}
}

func writeInstalledBundleForFreshnessTest(t *testing.T, rulesDir, name string, data []byte) {
	t.Helper()
	dir := filepath.Join(rulesDir, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create installed bundle dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.yaml"), data, 0o600); err != nil {
		t.Fatalf("write installed bundle: %v", err)
	}
}

func writeInstalledLockForFreshnessTest(t *testing.T, rulesDir, name string, data []byte) {
	t.Helper()
	bundle, err := domrules.ParseBundle(data)
	if err != nil {
		t.Fatalf("parse installed bundle: %v", err)
	}
	_, lock := remoteFreshnessCandidate(name, bundle.FormatVersion, bundle.MonotonicVersion)
	lock.InstalledVersion = bundle.Version
	lock.BundleSHA256 = sha256Hex(data)
	if err := domrules.WriteLockFile(filepath.Join(rulesDir, name, "bundle.lock"), lock); err != nil {
		t.Fatalf("write installed lock: %v", err)
	}
}

func assertInstalledBundleBytes(t *testing.T, rulesDir, name string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Clean(filepath.Join(rulesDir, name, "bundle.yaml"))) // #nosec G304 -- test path is below t.TempDir
	if err != nil {
		t.Fatalf("read installed bundle: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("installed bundle = %q, want %q", got, want)
	}
}

func installRemoteForFreshnessTest(t *testing.T, rulesDir, source, wantErr string) error {
	t.Helper()
	cmd := testRootCmd()
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"rules", "install", "--source", source, "--rules-dir", rulesDir})
	err := cmd.Execute()
	if wantErr == "" && err != nil {
		t.Fatalf("install remote bundle: %v", err)
	}
	return err
}

func signInstallBundle(data []byte, privateKey ed25519.PrivateKey) []byte {
	encoded := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, data))
	return []byte(encoded + "\n")
}

func v2InstallBundleYAML(version string, monotonic uint64, fingerprint string) string {
	return v2NamedInstallBundleYAML(testBundleName, version, domrules.TierCommunity, monotonic, fingerprint)
}

func v2NamedInstallBundleYAML(name, version, tier string, monotonic uint64, fingerprint string) string {
	return fmt.Sprintf(`format_version: 2
name: %s
version: %q
author: test
description: Test bundle
min_pipelock: "1.0.0"
tier: %s
monotonic_version: %d
published_at: "2026-08-27T00:00:00Z"
expires_at: "2030-01-01T00:00:00Z"
key_id: %q
rules: []
`, name, version, tier, monotonic, fingerprint)
}

func v1InstallBundleYAML(version string) string {
	return v1NamedInstallBundleYAML(testBundleName, version)
}

func v1NamedInstallBundleYAML(name, version string) string {
	return fmt.Sprintf(`format_version: 1
name: %s
version: %q
author: test
description: Test bundle
min_pipelock: "1.0.0"
rules: []
`, name, version)
}
