//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// seedCleanStore publishes one wildcard-audience bundle into a real policy-bundle
// store under <storageDir>/policy-bundles, exercising the same on-disk layout the
// offline commands read. It returns the storage dir to pass via --storage-dir.
func seedCleanStore(t *testing.T) string {
	t.Helper()
	storageDir := t.TempDir()
	pb := filepath.Join(storageDir, "policy-bundles")
	store, err := controlplane.OpenFileBundleStore(pb)
	if err != nil {
		t.Fatalf("OpenFileBundleStore: %v", err)
	}
	bundle := offlineTestBundle(t)
	if _, _, err := store.Publish(t.Context(), bundle, controlplane.PublishOptions{Now: time.Now().UTC()}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	return storageDir
}

// offlineTestBundle builds a minimal valid, signed policy bundle.
func offlineTestBundle(t *testing.T) conductorcore.PolicyBundle {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	payload := conductorcore.PolicyBundlePayload{ConfigYAML: "mode: strict\napi_allowlist:\n  - api.example.com\n"}
	payloadHash, err := payload.PayloadHash()
	if err != nil {
		t.Fatalf("PayloadHash: %v", err)
	}
	policyHash, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash: %v", err)
	}
	bundle := conductorcore.PolicyBundle{
		SchemaVersion:      conductorcore.SchemaVersion,
		BundleID:           "bundle-offline-cli",
		OrgID:              "org-cli",
		FleetID:            "prod",
		Environment:        "prod",
		Audience:           conductorcore.Audience{InstanceIDs: []string{"*"}},
		Version:            1,
		CreatedAt:          now.Add(-time.Minute),
		NotBefore:          now.Add(-time.Minute),
		ExpiresAt:          now.Add(2 * time.Hour),
		MinPipelockVersion: "1.2.3",
		PolicyHash:         policyHash,
		PayloadSHA256:      payloadHash,
		Payload:            payload,
	}
	preimage, err := bundle.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	bundle.Signatures = []conductorcore.SignatureProof{{
		SignerKeyID: "policy-key-1",
		KeyPurpose:  signing.PurposePolicyBundleSigning,
		Algorithm:   conductorcore.SignatureAlgorithmEd25519,
		Signature:   conductorcore.SignaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(priv, preimage)),
	}}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("bundle Validate: %v", err)
	}
	return bundle
}

func TestStoreInspectOfflineCmd_NoFleetLicenseFailsClosed(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := Cmd()
	cmd.SetArgs([]string{"store", "inspect-offline", "--storage-dir", t.TempDir()})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("inspect-offline without fleet license: err = %v, want ErrFleetLicenseRequired", err)
	}
}

func TestStoreRepairOfflineCmd_NoFleetLicenseFailsClosed(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := Cmd()
	cmd.SetArgs([]string{"store", "repair", "--storage-dir", t.TempDir(), "--confirm"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("repair without fleet license: err = %v, want ErrFleetLicenseRequired", err)
	}
}

func TestRunStoreInspectOffline_MissingStorageDir(t *testing.T) {
	err := runStoreInspectOffline(newCapturingCmd(), storeOfflineOptions{})
	if err == nil || !strings.Contains(err.Error(), "--storage-dir is required") {
		t.Fatalf("missing storage-dir error = %v, want --storage-dir required", err)
	}
}

func TestStoreInspectOfflineCmd_CleanStoreReportsNoOrphans(t *testing.T) {
	setFleetLicenseEnv(t)
	storageDir := seedCleanStore(t)
	var out bytes.Buffer
	cmd := Cmd()
	cmd.SetArgs([]string{"store", "inspect-offline", "--storage-dir", storageDir})
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("inspect-offline: %v", err)
	}
	got := out.String()
	for _, want := range []string{"streams: 1", "orphaned records: none"} {
		if !strings.Contains(got, want) {
			t.Errorf("inspect-offline output missing %q\n--- output ---\n%s", want, got)
		}
	}
}

func TestStoreRepairOfflineCmd_CleanStoreDryRunNoOp(t *testing.T) {
	setFleetLicenseEnv(t)
	storageDir := seedCleanStore(t)
	var out bytes.Buffer
	cmd := Cmd()
	// No --confirm: dry run.
	cmd.SetArgs([]string{"store", "repair", "--storage-dir", storageDir})
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("repair dry run: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "dry run: no removable orphaned records found") {
		t.Errorf("repair dry-run output = %q, want clean dry-run message", got)
	}
}

func TestStoreBackupRestoreRoundTrip(t *testing.T) {
	setFleetLicenseEnv(t)
	storageDir := seedCleanStore(t)
	if err := os.WriteFile(filepath.Join(storageDir, "enrollments.json"), []byte(`{"tokens":{},"followers":{}}`+"\n"), 0o600); err != nil {
		t.Fatalf("write enrollments: %v", err)
	}
	emergencyDir := filepath.Join(storageDir, "emergency-controls")
	if err := os.MkdirAll(emergencyDir, 0o750); err != nil {
		t.Fatalf("mkdir emergency: %v", err)
	}
	if err := os.WriteFile(filepath.Join(emergencyDir, "marker.json"), []byte(`{"ok":true}`+"\n"), 0o600); err != nil {
		t.Fatalf("write emergency marker: %v", err)
	}

	backupDir := filepath.Join(t.TempDir(), "backup")
	var backupOut bytes.Buffer
	backupCmd := Cmd()
	backupCmd.SetArgs([]string{"store", "backup", "--storage-dir", storageDir, "--backup-dir", backupDir})
	backupCmd.SetOut(&backupOut)
	backupCmd.SetErr(&backupOut)
	if err := backupCmd.Execute(); err != nil {
		t.Fatalf("backup: %v\n%s", err, backupOut.String())
	}
	if !strings.Contains(backupOut.String(), "created conductor storage backup") {
		t.Fatalf("backup output = %q, want created message", backupOut.String())
	}
	if _, err := os.Stat(filepath.Join(backupDir, backupManifestFile)); err != nil {
		t.Fatalf("backup manifest missing: %v", err)
	}

	restoreDir := filepath.Join(t.TempDir(), "restored-storage")
	var dryRunOut bytes.Buffer
	dryRunCmd := Cmd()
	dryRunCmd.SetArgs([]string{"store", "restore", "--storage-dir", restoreDir, "--backup-dir", backupDir})
	dryRunCmd.SetOut(&dryRunOut)
	dryRunCmd.SetErr(&dryRunOut)
	if err := dryRunCmd.Execute(); err != nil {
		t.Fatalf("restore dry run: %v", err)
	}
	if _, err := os.Stat(restoreDir); !os.IsNotExist(err) {
		t.Fatalf("dry run created restore dir (stat err=%v), want no dir", err)
	}

	var restoreOut bytes.Buffer
	restoreCmd := Cmd()
	restoreCmd.SetArgs([]string{"store", "restore", "--storage-dir", restoreDir, "--backup-dir", backupDir, "--confirm"})
	restoreCmd.SetOut(&restoreOut)
	restoreCmd.SetErr(&restoreOut)
	if err := restoreCmd.Execute(); err != nil {
		t.Fatalf("restore: %v\n%s", err, restoreOut.String())
	}
	if _, err := os.Stat(filepath.Join(restoreDir, "enrollments.json")); err != nil {
		t.Fatalf("restored enrollments missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(restoreDir, "emergency-controls", "marker.json")); err != nil {
		t.Fatalf("restored emergency marker missing: %v", err)
	}
	report, err := controlplane.InspectOfflineStore(filepath.Join(restoreDir, policyBundlesSubdir))
	if err != nil {
		t.Fatalf("InspectOfflineStore(restored): %v", err)
	}
	if len(report.Streams) != 1 || report.Streams[0].HeadBundleID != "bundle-offline-cli" {
		t.Fatalf("restored stream report = %+v, want bundle-offline-cli", report.Streams)
	}
}

func TestStoreRestoreIntoExistingEmptyStorageDirMovesAside(t *testing.T) {
	setFleetLicenseEnv(t)
	sourceStorage := seedCleanStore(t)
	backupDir := filepath.Join(t.TempDir(), "backup")
	if err := runStoreBackup(newCapturingCmd(), storeOfflineOptions{
		storageDir: sourceStorage,
		backupDir:  backupDir,
	}); err != nil {
		t.Fatalf("runStoreBackup() error = %v", err)
	}

	parent := t.TempDir()
	restoreDir := filepath.Join(parent, "restored-storage")
	if err := os.Mkdir(restoreDir, 0o750); err != nil {
		t.Fatalf("mkdir empty restore target: %v", err)
	}

	var out bytes.Buffer
	restoreCmd := Cmd()
	restoreCmd.SetArgs([]string{"store", "restore", "--storage-dir", restoreDir, "--backup-dir", backupDir, "--confirm"})
	restoreCmd.SetOut(&out)
	restoreCmd.SetErr(&out)
	if err := restoreCmd.Execute(); err != nil {
		t.Fatalf("restore into existing empty dir: %v\n%s", err, out.String())
	}
	if _, err := os.Stat(filepath.Join(restoreDir, policyBundlesSubdir)); err != nil {
		t.Fatalf("restored policy-bundles missing: %v", err)
	}
	matches, err := filepath.Glob(restoreDir + ".pre-restore-*")
	if err != nil {
		t.Fatalf("glob pre-restore dirs: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("pre-restore dirs = %v, want exactly one moved-aside empty target", matches)
	}
	entries, err := os.ReadDir(matches[0])
	if err != nil {
		t.Fatalf("read moved-aside empty target: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("moved-aside empty target has %d entries, want empty", len(entries))
	}
	if !strings.Contains(out.String(), "previous storage moved to") {
		t.Fatalf("restore output = %q, want moved-aside path", out.String())
	}
}

func TestStoreRestoreRejectsNonDirectoryTarget(t *testing.T) {
	setFleetLicenseEnv(t)
	sourceStorage := seedCleanStore(t)
	backupDir := filepath.Join(t.TempDir(), "backup")
	if err := runStoreBackup(newCapturingCmd(), storeOfflineOptions{
		storageDir: sourceStorage,
		backupDir:  backupDir,
	}); err != nil {
		t.Fatalf("runStoreBackup() error = %v", err)
	}

	restorePath := filepath.Join(t.TempDir(), "restored-storage")
	if err := os.WriteFile(restorePath, []byte("not a directory\n"), 0o600); err != nil {
		t.Fatalf("write non-directory restore target: %v", err)
	}
	err := runStoreRestore(newCapturingCmd(), storeOfflineOptions{
		storageDir: restorePath,
		backupDir:  backupDir,
		confirm:    true,
	})
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("runStoreRestore(non-directory target) error = %v, want not-a-directory rejection", err)
	}
	data, readErr := os.ReadFile(filepath.Clean(restorePath)) // #nosec G304 -- restorePath is a test-owned temp fixture.
	if readErr != nil {
		t.Fatalf("non-directory restore target missing after rejection: %v", readErr)
	}
	if string(data) != "not a directory\n" {
		t.Fatalf("non-directory restore target changed to %q", string(data))
	}
}

func TestStoreBackupRejectsBackupInsideStorage(t *testing.T) {
	storageDir := seedCleanStore(t)
	err := runStoreBackup(newCapturingCmd(), storeOfflineOptions{
		storageDir: storageDir,
		backupDir:  filepath.Join(storageDir, "backups", "one"),
	})
	if err == nil || !strings.Contains(err.Error(), "must not be inside") {
		t.Fatalf("runStoreBackup() error = %v, want inside-storage rejection", err)
	}
}

func newCapturingCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	return cmd
}

func TestStoreBackupRejectsNonDirectoryStorage(t *testing.T) {
	dir := t.TempDir()
	fileStorage := filepath.Join(dir, "notadir")
	if err := os.WriteFile(fileStorage, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	err := runStoreBackup(newCapturingCmd(), storeOfflineOptions{
		storageDir: fileStorage,
		backupDir:  filepath.Join(dir, "backup"),
	})
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("runStoreBackup(file) = %v, want not-a-directory rejection", err)
	}
}
