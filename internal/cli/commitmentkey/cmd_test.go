// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package commitmentkey

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	domkey "github.com/luckyPipewrench/pipelock/internal/commitmentkey"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func TestCommandLifecycleAndAudit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "keyring.json")
	backup := filepath.Join(dir, "backup", "keyring.json")

	stdout, stderr, err := execute(t, "initialize", "--keyring", path)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	first := decodeMetadata(t, stdout)
	assertAudit(t, stderr, "initialize", "succeeded")
	assertNoKeyMaterial(t, stdout, stderr)

	stdout, stderr, err = execute(t, "inspect", "--keyring", path)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if got := decodeMetadata(t, stdout); got.ActiveID != first.ActiveID || got.Epoch != 1 {
		t.Fatalf("inspect metadata = %+v, want active %q epoch 1", got, first.ActiveID)
	}
	assertAudit(t, stderr, "inspect", "succeeded")
	assertNoKeyMaterial(t, stdout, stderr)

	stdout, stderr, err = execute(t, "rotate", "--keyring", path)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	rotated := decodeMetadata(t, stdout)
	if rotated.Epoch != 2 || rotated.ActiveID == first.ActiveID || len(rotated.Keys) != 2 {
		t.Fatalf("rotated metadata = %+v", rotated)
	}
	assertAudit(t, stderr, "rotate", "succeeded")
	assertNoKeyMaterial(t, stdout, stderr)

	_, stderr, err = execute(t, "retire", "--keyring", path, "--key-id", first.ActiveID, "--epoch", "1")
	if !errors.Is(err, domkey.ErrRetainedKey) {
		t.Fatalf("retire retained error = %v, want ErrRetainedKey", err)
	}
	assertAudit(t, stderr, "retire", "denied")

	stdout, stderr, err = execute(t, "backup", "--keyring", path, "--out", backup)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	assertAudit(t, stderr, "backup", "succeeded")
	assertNoKeyMaterial(t, stdout, stderr)
	if err := os.Remove(path); err != nil {
		t.Fatalf("destroy keyring: %v", err)
	}
	stdout, stderr, err = execute(t, "restore", "--keyring", path, "--from", backup)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	assertAudit(t, stderr, "restore", "succeeded")
	assertNoKeyMaterial(t, stdout, stderr)

	keyring, err := domkey.Load(path)
	if err != nil {
		t.Fatalf("Load restored: %v", err)
	}
	handle, err := keyring.Open(first.ActiveID, first.Epoch)
	if err != nil {
		t.Fatalf("Open retired key: %v", err)
	}
	source := contractreceipt.ProvenanceSource{SourceOrdinal: 1, SourceID: "source-1", Recipe: normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest}}
	commitment, err := contractreceipt.CommitView(handle.Key, source, "opened after restore")
	if err != nil {
		t.Fatalf("CommitView: %v", err)
	}
	stdout, stderr, err = executeInput(t, "opened after restore", "test", "--keyring", path, "--key-id", first.ActiveID, "--epoch", "1", "--source-id", "source-1", "--source-ordinal", "1", "--commitment", commitment)
	if err != nil {
		t.Fatalf("test opening: %v", err)
	}
	if !strings.Contains(stdout, `"opened": true`) {
		t.Fatalf("test output = %q", stdout)
	}
	assertAudit(t, stderr, "test", "succeeded")
	assertNoKeyMaterial(t, stdout, stderr)

	recipe := normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationLowercase}}}
	source.Recipe = recipe
	commitment, err = contractreceipt.CommitView(handle.Key, source, "opened after restore")
	if err != nil {
		t.Fatalf("CommitView with typed recipe: %v", err)
	}
	recipeBytes, err := json.Marshal(recipe)
	if err != nil {
		t.Fatalf("Marshal recipe: %v", err)
	}
	_, stderr, err = executeInput(t, "opened after restore", "test", "--keyring", path, "--key-id", first.ActiveID, "--epoch", "1", "--source-id", "source-1", "--source-ordinal", "1", "--commitment", commitment, "--recipe-json", string(recipeBytes))
	if err != nil {
		t.Fatalf("test opening with typed recipe: %v", err)
	}
	assertAudit(t, stderr, "test", "succeeded")

	stdout, stderr, err = execute(t, "retire", "--keyring", path, "--key-id", first.ActiveID, "--epoch", "1", "--accept-loss", "--allow-unaudited")
	if err != nil {
		t.Fatalf("retire with explicit loss acceptance: %v", err)
	}
	if got := decodeMetadata(t, stdout); len(got.Keys) != 1 || got.Epoch != 2 {
		t.Fatalf("retired metadata = %+v, want only epoch 2", got)
	}
	assertAudit(t, stderr, "retire", "succeeded")
	assertAuditAuthorization(t, stderr, "operator_accept_loss,operator_allow_unaudited")
	assertNoKeyMaterial(t, stdout, stderr)
}

func TestCommandConfigResolutionAndMismatchDenial(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\nevidence_provenance:\n  commitment_keyring_path: state/keyring.json\n"), 0o600); err != nil {
		t.Fatalf("WriteFile config: %v", err)
	}
	stdout, _, err := execute(t, "initialize", "--config", cfgPath)
	if err != nil {
		t.Fatalf("initialize via config: %v", err)
	}
	metadata := decodeMetadata(t, stdout)
	_, stderr, err := executeInput(t, "value", "test", "--config", cfgPath, "--key-id", metadata.ActiveID, "--epoch", "1", "--source-id", "source-1", "--commitment", "hmac-sha256:"+strings.Repeat("0", 64))
	if !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("test mismatch error = %v", err)
	}
	assertAudit(t, stderr, "test", "denied")
	if _, _, err := execute(t, "inspect", "--keyring", "x", "--config", cfgPath); err == nil {
		t.Fatal("mutually exclusive path flags succeeded")
	}
}

func TestCommandConfigResolutionIgnoresUnrelatedRuntimeFiles(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	body := "mode: balanced\nlicense_file: missing-license.txt\nevidence_provenance:\n  commitment_keyring_path: state/keyring.json\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile config: %v", err)
	}
	if _, _, err := execute(t, "initialize", "--config", cfgPath); err != nil {
		t.Fatalf("initialize should not read unrelated runtime files: %v", err)
	}
}

func TestParseRecipeRejectsUnknownAndTrailingFields(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown":  `{"transform_profile_digest":"` + normalize.EvidenceProvenanceProfileV1Digest + `","operations":[],"extra":true}`,
		"trailing": `{"transform_profile_digest":"` + normalize.EvidenceProvenanceProfileV1Digest + `","operations":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRecipe(raw); err == nil {
				t.Fatalf("parseRecipe(%s) succeeded", raw)
			}
		})
	}
}

func TestCommandDenialBranches(t *testing.T) {
	const (
		activeIDMarker = "{active-key-id}"
		backupMarker   = "{backup-path}"
		keyringMarker  = "{keyring-path}"
		missingMarker  = "{missing-keyring-path}"
	)

	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	backup := filepath.Join(dir, "backup.json")
	if _, _, err := execute(t, "initialize", "--keyring", path); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	for _, test := range []struct {
		name          string
		operation     string
		args          []string
		wantAudit     bool
		wantErr       string
		wantAuditText string
	}{
		{name: "initialize rerun", operation: "initialize", args: []string{"initialize", "--keyring", keyringMarker}, wantAudit: true},
		{name: "inspect missing", operation: "inspect", args: []string{"inspect", "--keyring", missingMarker}, wantAudit: true},
		{name: "rotate missing", operation: "rotate", args: []string{"rotate", "--keyring", missingMarker}, wantAudit: true},
		{name: "retire without loss acceptance", operation: "retire", args: []string{"retire", "--keyring", keyringMarker, "--key-id", activeIDMarker, "--epoch", "1"}, wantAudit: true},
		{name: "retire missing required flags before keyring access", operation: "retire", args: []string{"retire", "--keyring", missingMarker, "--accept-loss", "--allow-unaudited"}, wantAudit: true, wantErr: `required flag(s) "key-id, epoch" not set`, wantAuditText: `required flag(s) "key-id, epoch" not set`},
		{name: "retire requires explicit unaudited break glass", operation: "retire", args: []string{"retire", "--keyring", missingMarker, "--key-id", activeIDMarker, "--epoch", "1", "--accept-loss"}, wantAudit: true, wantErr: "--allow-unaudited is required to retire without a durable audit sink", wantAuditText: "--allow-unaudited is required to retire without a durable audit sink"},
		{name: "backup missing required flag before keyring access", operation: "backup", args: []string{"backup", "--keyring", missingMarker}, wantAudit: true, wantErr: `required flag(s) "out" not set`, wantAuditText: `required flag(s) "out" not set`},
		{name: "restore missing required flag before keyring access", operation: "restore", args: []string{"restore", "--keyring", missingMarker}, wantAudit: true, wantErr: `required flag(s) "from" not set`, wantAuditText: `required flag(s) "from" not set`},
		{name: "test unknown key", operation: "test", args: []string{"test", "--keyring", keyringMarker, "--key-id", "ck_00000000000000000000000000000000", "--epoch", "1", "--source-id", "source-1", "--commitment", "hmac-sha256:" + strings.Repeat("0", 64)}, wantAudit: true},
		{name: "test missing required flag before keyring access", operation: "test", args: []string{"test", "--keyring", missingMarker, "--key-id", activeIDMarker, "--epoch", "1", "--source-id", "source-1"}, wantAudit: true, wantErr: `required flag(s) "commitment" not set`, wantAuditText: `required flag(s) "commitment" not set`},
		{name: "test reports every missing required flag", operation: "test", args: []string{"test", "--keyring", missingMarker}, wantAudit: true, wantErr: `required flag(s) "key-id, epoch, source-id, commitment" not set`, wantAuditText: `required flag(s) "key-id, epoch, source-id, commitment" not set`},
		{name: "test invalid recipe", operation: "test", args: []string{"test", "--keyring", keyringMarker, "--key-id", activeIDMarker, "--epoch", "1", "--source-id", "source-1", "--commitment", "hmac-sha256:" + strings.Repeat("0", 64), "--recipe-json", `{}`}, wantAudit: true},
		{name: "missing path selector", operation: "inspect", args: []string{"inspect"}, wantAudit: true},
		{name: "initialize missing path selector", operation: "initialize", args: []string{"initialize"}, wantAudit: true},
		{name: "rotate missing path selector", operation: "rotate", args: []string{"rotate"}, wantAudit: true},
		{name: "retire missing path selector", operation: "retire", args: []string{"retire", "--key-id", activeIDMarker, "--epoch", "1"}, wantAudit: true},
		{name: "backup missing path selector", operation: "backup", args: []string{"backup", "--out", backupMarker}, wantAudit: true},
		{name: "restore missing path selector", operation: "restore", args: []string{"restore", "--from", keyringMarker}, wantAudit: true},
		{name: "test missing path selector", operation: "test", args: []string{"test", "--key-id", activeIDMarker, "--epoch", "1", "--source-id", "source-1", "--commitment", "hmac-sha256:" + strings.Repeat("0", 64)}, wantAudit: true},
		{name: "test invalid source utf8", operation: "test", args: []string{"test", "--keyring", keyringMarker, "--key-id", activeIDMarker, "--epoch", "1", "--source-id", string([]byte{0xff}), "--commitment", "hmac-sha256:" + strings.Repeat("0", 64)}, wantAudit: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			caseDir := t.TempDir()
			casePath := filepath.Join(caseDir, "keyring.json")
			caseMissingPath := filepath.Join(caseDir, "missing.json")
			caseBackupPath := filepath.Join(caseDir, "backup.json")
			if _, _, err := execute(t, "initialize", "--keyring", casePath); err != nil {
				t.Fatalf("initialize case keyring: %v", err)
			}
			caseMetadata := mustLoadMetadata(t, casePath)
			replacer := strings.NewReplacer(
				activeIDMarker, caseMetadata.ActiveID,
				backupMarker, caseBackupPath,
				keyringMarker, casePath,
				missingMarker, caseMissingPath,
			)
			args := make([]string, len(test.args))
			for i, arg := range test.args {
				args[i] = replacer.Replace(arg)
			}
			before := map[string]testFileSnapshot{
				casePath:        snapshotTestFile(t, casePath),
				caseMissingPath: snapshotTestFile(t, caseMissingPath),
				caseBackupPath:  snapshotTestFile(t, caseBackupPath),
			}

			_, stderr, err := execute(t, args...)
			if err == nil {
				t.Fatal("command succeeded")
			}
			if test.wantErr != "" && err.Error() != test.wantErr {
				t.Fatalf("command error = %q, want %q", err, test.wantErr)
			}
			if test.wantAudit {
				assertAudit(t, stderr, test.operation, "denied")
			}
			if test.wantAuditText != "" {
				assertAuditReason(t, stderr, test.wantAuditText)
			}
			for snapshotPath, snapshot := range before {
				assertTestFileSnapshot(t, snapshotPath, snapshot)
			}
		})
	}

	if _, _, err := execute(t, "backup", "--keyring", path, "--out", backup); err != nil {
		t.Fatalf("first backup: %v", err)
	}
	_, stderr, err := execute(t, "backup", "--keyring", path, "--out", backup)
	if err == nil {
		t.Fatal("duplicate backup succeeded")
	}
	assertAudit(t, stderr, "backup", "denied")
	_, stderr, err = execute(t, "restore", "--keyring", path, "--from", backup)
	if err == nil {
		t.Fatal("restore over existing keyring succeeded")
	}
	assertAudit(t, stderr, "restore", "denied")
}

func TestWriteJSONReportsOutputFailure(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(failingWriter{})
	if err := writeJSON(cmd, map[string]bool{"ok": true}); err == nil {
		t.Fatal("writeJSON succeeded with failing writer")
	}
}

func TestCommandReadsPrivateViewFromStdinOrSecureFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	if _, _, err := execute(t, "initialize", "--keyring", path); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	keyring, err := domkey.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	handle, err := keyring.Active()
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	source := contractreceipt.ProvenanceSource{SourceID: "source-1", Recipe: normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest}}
	const privateView = "private transformed evidence"
	commitment, err := contractreceipt.CommitView(handle.Key, source, privateView)
	if err != nil {
		t.Fatalf("CommitView: %v", err)
	}
	args := []string{"test", "--keyring", path, "--key-id", handle.KeyID, "--epoch", "1", "--source-id", "source-1", "--commitment", commitment}
	if _, stderr, err := executeInput(t, privateView, args...); err != nil {
		t.Fatalf("test from stdin: %v", err)
	} else if strings.Contains(stderr, privateView) {
		t.Fatal("private view appeared in audit/operator output")
	}
	viewPath := filepath.Join(dir, "view.txt")
	if err := os.WriteFile(viewPath, []byte(privateView), 0o600); err != nil {
		t.Fatalf("WriteFile view: %v", err)
	}
	if _, _, err := execute(t, append(args, "--view-file", viewPath)...); err != nil {
		t.Fatalf("test from file: %v", err)
	}
	if _, _, err := execute(t, append(args, "--view", privateView)...); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("argv private view error = %v, want unknown --view flag", err)
	}
}

func TestCommandRejectsSymlinkPrivateView(t *testing.T) {
	if !supportsUnixSymlinkTest(runtime.GOOS) {
		t.Skip("Windows uses reparse-point checks and may not permit symlink creation")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	if _, _, err := execute(t, "initialize", "--keyring", path); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	keyring, err := domkey.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	handle, err := keyring.Active()
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	const privateView = "private transformed evidence"
	source := contractreceipt.ProvenanceSource{SourceID: "source-1", Recipe: normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest}}
	commitment, err := contractreceipt.CommitView(handle.Key, source, privateView)
	if err != nil {
		t.Fatalf("CommitView: %v", err)
	}
	viewPath := filepath.Join(dir, "view.txt")
	if err := os.WriteFile(viewPath, []byte(privateView), 0o600); err != nil {
		t.Fatalf("WriteFile view: %v", err)
	}
	link := filepath.Join(dir, "view-link.txt")
	if err := os.Symlink(viewPath, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	args := []string{"test", "--keyring", path, "--key-id", handle.KeyID, "--epoch", "1", "--source-id", "source-1", "--commitment", commitment, "--view-file", link}
	if _, stderr, err := execute(t, args...); !errors.Is(err, domkey.ErrSymlink) {
		t.Fatalf("symlink view error = %v stderr=%q, want ErrSymlink", err, stderr)
	}
}

func TestSymlinkTestPlatformGuard(t *testing.T) {
	if supportsUnixSymlinkTest("windows") {
		t.Fatal("Windows selected for Unix symlink test")
	}
	if !supportsUnixSymlinkTest("linux") {
		t.Fatal("Linux excluded from Unix symlink test")
	}
}

func supportsUnixSymlinkTest(goos string) bool {
	return goos != "windows"
}

func TestLifecycleCommandsSurfaceInertCapabilityNotice(t *testing.T) {
	_, stderr, err := execute(t, "initialize")
	if err == nil {
		t.Fatal("initialize without path succeeded")
	}
	if !strings.Contains(stderr, "nothing is currently being committed") {
		t.Fatalf("stderr = %q, want inert-capability notice", stderr)
	}
	cmd := Cmd()
	if !strings.Contains(cmd.Long, "Nothing is currently being") {
		t.Fatalf("commitment-key help omits inert-capability notice: %q", cmd.Long)
	}
}

func TestReadViewRejectsStdinReadFailureAndOversize(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.SetIn(failingReader{})
	if _, err := readView(cmd, "-"); err == nil || !strings.Contains(err.Error(), "read private evidence view") {
		t.Fatalf("readView failing stdin error = %v", err)
	}
	cmd.SetIn(io.LimitReader(repeatingReader{}, privateViewMaxSize+1))
	if _, err := readView(cmd, "-"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readView oversized stdin error = %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

type repeatingReader struct{}

func (repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestConfigPathResolutionDenials(t *testing.T) {
	dir := t.TempDir()
	missingField := filepath.Join(dir, "missing-field.yaml")
	if err := os.WriteFile(missingField, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	malformed := filepath.Join(dir, "malformed.yaml")
	if err := os.WriteFile(malformed, []byte("mode: [\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	for name, path := range map[string]string{"missing_field": missingField, "malformed": malformed} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := execute(t, "inspect", "--config", path); err == nil {
				t.Fatalf("inspect with config %s succeeded", path)
			}
		})
	}
}

func execute(t *testing.T, args ...string) (string, string, error) {
	return executeInput(t, "", args...)
}

func executeInput(t *testing.T, input string, args ...string) (string, string, error) {
	t.Helper()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	root := &cobra.Command{Use: "pipelock", SilenceUsage: true, SilenceErrors: true}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetIn(strings.NewReader(input))
	root.AddCommand(Cmd())
	root.SetArgs(append([]string{"commitment-key"}, args...))
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

func decodeMetadata(t *testing.T, raw string) domkey.Metadata {
	t.Helper()
	var metadata domkey.Metadata
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		t.Fatalf("decode metadata %q: %v", raw, err)
	}
	return metadata
}

func mustLoadMetadata(t *testing.T, path string) domkey.Metadata {
	t.Helper()
	keyring, err := domkey.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return keyring.Metadata()
}

func TestSnapshotTestFilePreservesDanglingSymlink(t *testing.T) {
	if !supportsUnixSymlinkTest(runtime.GOOS) {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}
	dir := t.TempDir()
	const target = "missing.json"
	link := filepath.Join(dir, "keyring.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	snapshot := snapshotTestFile(t, link)
	if !snapshot.exists {
		t.Fatal("dangling symlink reported as nonexistent")
	}
	if snapshot.mode&os.ModeSymlink == 0 {
		t.Fatalf("snapshot mode = %s, want symlink", snapshot.mode)
	}
	if snapshot.linkTarget != target {
		t.Fatalf("symlink target = %q, want %q", snapshot.linkTarget, target)
	}
	if snapshot.data != nil {
		t.Fatalf("symlink snapshot data = %q, want nil", snapshot.data)
	}
}

type testFileSnapshot struct {
	data       []byte
	linkTarget string
	mode       os.FileMode
	exists     bool
}

func snapshotTestFile(t *testing.T, path string) testFileSnapshot {
	t.Helper()
	cleanPath := filepath.Clean(path)
	info, err := os.Lstat(cleanPath)
	if errors.Is(err, os.ErrNotExist) {
		return testFileSnapshot{}
	}
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	snapshot := testFileSnapshot{mode: info.Mode(), exists: true}
	if info.Mode().IsRegular() {
		snapshot.data, err = os.ReadFile(cleanPath)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		snapshot.linkTarget, err = os.Readlink(cleanPath)
		if err != nil {
			t.Fatalf("readlink %s: %v", path, err)
		}
	}
	return snapshot
}

func assertTestFileSnapshot(t *testing.T, path string, want testFileSnapshot) {
	t.Helper()
	got := snapshotTestFile(t, path)
	if got.exists != want.exists {
		t.Fatalf("file existence for %s = %t, want %t", path, got.exists, want.exists)
	}
	if got.exists && got.mode != want.mode {
		t.Fatalf("file mode for %s = %s, want %s", path, got.mode, want.mode)
	}
	if got.linkTarget != want.linkTarget {
		t.Fatalf("symlink target for %s = %q, want %q", path, got.linkTarget, want.linkTarget)
	}
	if !bytes.Equal(got.data, want.data) {
		t.Fatalf("file contents changed for %s", path)
	}
}

func assertAudit(t *testing.T, raw, operation, outcome string) {
	t.Helper()
	event := decodeAudit(t, raw)
	if event.EventType != "commitment_key_lifecycle" || event.Operation != operation || event.Outcome != outcome || event.Timestamp == "" {
		t.Fatalf("audit event = %+v", event)
	}
	if outcome == "denied" && event.Reason == "" {
		t.Fatalf("denied audit event has no reason: %+v", event)
	}
}

func assertAuditAuthorization(t *testing.T, raw, authorization string) {
	t.Helper()
	event := decodeAudit(t, raw)
	if event.Authorization != authorization {
		t.Fatalf("audit authorization = %q, want %q", event.Authorization, authorization)
	}
}

func assertAuditReason(t *testing.T, raw, reason string) {
	t.Helper()
	event := decodeAudit(t, raw)
	if event.Reason != reason {
		t.Fatalf("audit reason = %q, want %q", event.Reason, reason)
	}
}

func decodeAudit(t *testing.T, raw string) auditEvent {
	t.Helper()
	var events []auditEvent
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var event auditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if event.EventType == "commitment_key_lifecycle" {
			events = append(events, event)
		}
	}
	if len(events) != 1 {
		t.Fatalf("audit capture has %d commitment_key_lifecycle events, want exactly 1: %q", len(events), raw)
	}
	return events[0]
}

func assertNoKeyMaterial(t *testing.T, outputs ...string) {
	t.Helper()
	for _, output := range outputs {
		if strings.Contains(output, `"key"`) {
			t.Fatalf("operator output exposed key material field: %s", output)
		}
	}
}
