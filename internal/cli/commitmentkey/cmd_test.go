// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package commitmentkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	domkey "github.com/luckyPipewrench/pipelock/internal/commitmentkey"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func requireUnixDurableAuditFile(t *testing.T) {
	t.Helper()
	if !audit.DurableAuditFileSupported() {
		t.Skip("durable lifecycle audit files are unsupported on this platform")
	}
}

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

	stdout, stderr, err = execute(t, "retire", "--keyring", path, "--key-id", first.ActiveID, "--epoch", "1", "--accept-loss")
	if err != nil {
		t.Fatalf("retire with explicit loss acceptance: %v", err)
	}
	if got := decodeMetadata(t, stdout); len(got.Keys) != 1 || got.Epoch != 2 {
		t.Fatalf("retired metadata = %+v, want only epoch 2", got)
	}
	assertAudit(t, stderr, "retire", "succeeded")
	assertAuditAuthorization(t, stderr, "operator_accept_loss")
	assertNoKeyMaterial(t, stdout, stderr)
}

func TestCommandConfigResolutionAndMismatchDenial(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	body := "mode: balanced\nlogging:\n  output: file\n  file: " + filepath.Join(dir, "audit.jsonl") + "\nevidence_provenance:\n  commitment_keyring_path: state/keyring.json\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
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
	body := "mode: balanced\nlicense_file: missing-license.txt\nlogging:\n  output: file\n  file: " + filepath.Join(dir, "audit.jsonl") + "\nevidence_provenance:\n  commitment_keyring_path: state/keyring.json\n"
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
		{name: "retire missing required flags before keyring access", operation: "retire", args: []string{"retire", "--keyring", missingMarker, "--accept-loss"}, wantAudit: true, wantErr: `required flag(s) "key-id, epoch" not set`, wantAuditText: "missing_required_flag"},
		{name: "backup missing required flag before keyring access", operation: "backup", args: []string{"backup", "--keyring", missingMarker}, wantAudit: true, wantErr: `required flag(s) "out" not set`, wantAuditText: "missing_required_flag"},
		{name: "restore missing required flag before keyring access", operation: "restore", args: []string{"restore", "--keyring", missingMarker}, wantAudit: true, wantErr: `required flag(s) "from" not set`, wantAuditText: "missing_required_flag"},
		{name: "test unknown key", operation: "test", args: []string{"test", "--keyring", keyringMarker, "--key-id", "ck_00000000000000000000000000000000", "--epoch", "1", "--source-id", "source-1", "--commitment", "hmac-sha256:" + strings.Repeat("0", 64)}, wantAudit: true},
		{name: "test missing required flag before keyring access", operation: "test", args: []string{"test", "--keyring", missingMarker, "--key-id", activeIDMarker, "--epoch", "1", "--source-id", "source-1"}, wantAudit: true, wantErr: `required flag(s) "commitment" not set`, wantAuditText: "missing_required_flag"},
		{name: "test reports every missing required flag", operation: "test", args: []string{"test", "--keyring", missingMarker}, wantAudit: true, wantErr: `required flag(s) "key-id, epoch, source-id, commitment" not set`, wantAuditText: "missing_required_flag"},
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

func TestLifecycleDurableAuditCoversMutationsAndDenial(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	backupPath := filepath.Join(dir, "backup.json")
	restoredPath := filepath.Join(dir, "restored.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	configPath := writeLifecycleAuditConfig(t, dir, keyringPath, auditPath, "file", "")

	stdout, _, err := execute(t, "initialize", "--config", configPath)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	first := decodeMetadata(t, stdout)
	if _, _, err := execute(t, "rotate", "--config", configPath); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, _, err := execute(t, "backup", "--config", configPath, "--out", backupPath); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if _, _, err := execute(t, "backup", "--config", configPath, "--out", backupPath); err == nil {
		t.Fatal("duplicate backup succeeded")
	}
	restoreConfig := writeLifecycleAuditConfig(t, dir, restoredPath, auditPath, "both", "")
	if _, _, err := execute(t, "restore", "--config", restoreConfig, "--from", backupPath); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, _, err := execute(t, "retire", "--config", configPath, "--key-id", first.ActiveID, "--epoch", "1", "--accept-loss"); err != nil {
		t.Fatalf("retire: %v", err)
	}

	for operation, outcome := range map[string]string{
		"initialize": "succeeded",
		"rotate":     "succeeded",
		"backup":     "denied",
		"restore":    "succeeded",
		"retire":     "succeeded",
	} {
		assertDurableAudit(t, auditPath, operation, outcome)
		assertDurableMutationAuditPair(t, auditPath, operation, outcome)
	}
	assertNoKeyMaterial(t, string(mustReadFile(t, auditPath)))
}

func TestLifecycleAuditFileMatchesStderrRecord(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	configPath := writeLifecycleAuditConfig(t, dir, keyringPath, auditPath, "file", "")

	stdout, stderr, err := execute(t, "initialize", "--config", configPath)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	assertMatchingLifecycleRecords(t, "initialize", "succeeded", stderr, string(mustReadFile(t, auditPath)))

	metadata := decodeMetadata(t, stdout)
	_, stderr, err = execute(t, "retire", "--config", configPath, "--key-id", metadata.ActiveID, "--epoch", "1")
	if err == nil {
		t.Fatal("retire without --accept-loss succeeded")
	}
	assertMatchingLifecycleRecords(t, "retire", "denied", stderr, string(mustReadFile(t, auditPath)))
}

func TestRetireWithoutAcceptLossOmitsAuthorizationFromIntentAndOutcome(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	configPath := writeLifecycleAuditConfig(t, dir, keyringPath, auditPath, "file", "")

	stdout, _, err := execute(t, "initialize", "--config", configPath)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	metadata := decodeMetadata(t, stdout)
	_, stderr, err := execute(t, "retire", "--config", configPath, "--key-id", metadata.ActiveID, "--epoch", "1")
	if err == nil {
		t.Fatal("retire without --accept-loss succeeded")
	}
	assertDurableMutationAuditPair(t, auditPath, "retire", "denied")
	for _, records := range []string{stderr, string(mustReadFile(t, auditPath))} {
		if strings.Contains(records, "operator_accept_loss") {
			t.Fatalf("retire without --accept-loss recorded false authorization: %q", records)
		}
	}
}

func TestInspectSupportsRawKeyringWithReadOnlyWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	if _, _, err := execute(t, "initialize", "--keyring", path); err != nil {
		t.Fatalf("initialize fixture: %v", err)
	}
	stdout, stderr, err := executeRaw(t, "inspect", "--keyring", path)
	if err != nil {
		t.Fatalf("inspect --keyring: %v", err)
	}
	if got := decodeMetadata(t, stdout); got.ActiveID == "" {
		t.Fatalf("inspect metadata = %+v, want active key", got)
	}
	if !strings.Contains(stderr, "proceeding because this operation is read-only") {
		t.Fatalf("inspect stderr = %q, want read-only sink warning", stderr)
	}
}

func TestLifecycleAuditDoesNotExposePrivateViewPath(t *testing.T) {
	if !supportsUnixSymlinkTest(runtime.GOOS) {
		t.Skip("Windows uses reparse-point checks and may not permit symlink creation")
	}
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	configPath := writeLifecycleAuditConfig(t, dir, keyringPath, auditPath, "file", "")
	stdout, _, err := execute(t, "initialize", "--config", configPath)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	metadata := decodeMetadata(t, stdout)
	viewPath := filepath.Join(dir, "private-view.txt")
	if err := os.WriteFile(viewPath, []byte("private transformed evidence"), 0o600); err != nil {
		t.Fatalf("WriteFile view: %v", err)
	}
	linkPath := filepath.Join(dir, "private-view-link.txt")
	if err := os.Symlink(viewPath, linkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, stderr, err := execute(t, "test", "--config", configPath, "--key-id", metadata.ActiveID, "--epoch", "1", "--source-id", "source-1", "--commitment", "hmac-sha256:"+strings.Repeat("0", 64), "--view-file", linkPath)
	if !errors.Is(err, domkey.ErrSymlink) {
		t.Fatalf("test with symlink private view error = %v, want ErrSymlink", err)
	}
	for _, output := range []string{stderr, string(mustReadFile(t, auditPath))} {
		if strings.Contains(output, viewPath) || strings.Contains(output, linkPath) {
			t.Fatalf("lifecycle audit exposed private view path: %q", output)
		}
	}
}

func TestLifecycleAuditDenialsIgnoreBlockedFilter(t *testing.T) {
	for _, tc := range []struct {
		name           string
		includeBlocked string
	}{
		{name: "omitted", includeBlocked: ""},
		{name: "explicit false", includeBlocked: "false"},
		{name: "explicit true", includeBlocked: "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			keyringPath := filepath.Join(dir, "keyring.json")
			auditPath := filepath.Join(dir, "audit.jsonl")
			configPath := writeLifecycleAuditConfig(t, dir, keyringPath, auditPath, "file", tc.includeBlocked)
			stdout, _, err := execute(t, "initialize", "--config", configPath)
			if err != nil {
				t.Fatalf("initialize: %v", err)
			}
			metadata := decodeMetadata(t, stdout)
			if _, _, err := execute(t, "retire", "--config", configPath, "--key-id", metadata.ActiveID, "--epoch", "1"); err == nil {
				t.Fatal("retire without --accept-loss succeeded")
			}
			assertDurableAudit(t, auditPath, "retire", "denied")
		})
	}
}

func TestConcurrentRotationsSerializeKeyringAndDurableAudit(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	configPath := writeLifecycleAuditConfig(t, dir, keyringPath, auditPath, "file", "")
	if _, _, err := execute(t, "initialize", "--config", configPath); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	const rotations = 12
	errs := make(chan error, rotations)
	var wg sync.WaitGroup
	for range rotations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := executeCommand("", "rotate", "--config", configPath)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent rotate: %v", err)
		}
	}

	metadata := mustLoadMetadata(t, keyringPath)
	if metadata.Epoch != rotations+1 || len(metadata.Keys) != rotations+1 {
		t.Fatalf("concurrent rotations produced epoch=%d keys=%d, want %d", metadata.Epoch, len(metadata.Keys), rotations+1)
	}

	type pair struct{ intent, outcome bool }
	pairs := make(map[string]pair, rotations)
	for _, line := range strings.Split(strings.TrimSpace(string(mustReadFile(t, auditPath))), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("interleaved audit record %q: %v", line, err)
		}
		if event["operation"] != "rotate" {
			continue
		}
		operationID, _ := event["operation_id"].(string)
		state := pairs[operationID]
		if event["phase"] == "intent" && event["outcome"] == "pending" {
			state.intent = true
		}
		if event["phase"] == "outcome" && event["outcome"] == "succeeded" {
			state.outcome = true
		}
		pairs[operationID] = state
	}
	if len(pairs) != rotations {
		t.Fatalf("rotate audit attempts = %d, want %d", len(pairs), rotations)
	}
	for operationID, state := range pairs {
		if !state.intent || !state.outcome {
			t.Fatalf("rotate audit pair %s = %+v, want durable intent and outcome", operationID, state)
		}
	}
}

func TestLifecycleAuditSinkFailureDirections(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	setupConfig := writeLifecycleAuditConfig(t, dir, keyringPath, filepath.Join(dir, "audit.jsonl"), "file", "")
	if _, _, err := execute(t, "initialize", "--config", setupConfig); err != nil {
		t.Fatalf("test fixture initialize: %v", err)
	}
	before := snapshotTestFile(t, keyringPath)
	if _, stderr, err := executeRaw(t, "rotate", "--keyring", keyringPath); err == nil || !strings.Contains(stderr, `"outcome":"denied"`) {
		t.Fatalf("rotate without --config err=%v stderr=%q, want denied lifecycle audit", err, stderr)
	}
	assertTestFileSnapshot(t, keyringPath, before)

	tests := []struct {
		name       string
		configBody string
	}{
		{name: "missing logging block", configBody: "mode: balanced\nevidence_provenance:\n  commitment_keyring_path: " + keyringPath + "\n"},
		{name: "stdout only", configBody: lifecycleAuditConfig(keyringPath, filepath.Join(dir, "stdout-audit.jsonl"), "stdout", "")},
		{name: "missing audit file", configBody: lifecycleAuditConfig(keyringPath, "", "file", "")},
		{name: "unopenable file", configBody: lifecycleAuditConfig(keyringPath, filepath.Join(dir, "missing", "audit.jsonl"), "file", "")},
		{name: "invalid logging format", configBody: strings.Replace(lifecycleAuditConfig(keyringPath, filepath.Join(dir, "audit.jsonl"), "file", ""), "  output:", "  format: xml\n  output:", 1)},
		{name: "text logging format", configBody: strings.Replace(lifecycleAuditConfig(keyringPath, filepath.Join(dir, "audit.jsonl"), "file", ""), "  output:", "  format: text\n  output:", 1)},
	}
	if runtime.GOOS == "linux" {
		tests = append(tests, struct {
			name       string
			configBody string
		}{name: "full device", configBody: lifecycleAuditConfig(keyringPath, "/dev/full", "file", "")})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(configPath, []byte(tc.configBody), 0o600); err != nil {
				t.Fatalf("WriteFile config: %v", err)
			}
			before := snapshotTestFile(t, keyringPath)
			_, stderr, err := execute(t, "rotate", "--config", configPath)
			if err == nil {
				t.Fatal("rotate succeeded without a durable sink")
			}
			if !strings.Contains(stderr, `"outcome":"denied"`) {
				t.Fatalf("stderr = %q, want denied lifecycle audit", stderr)
			}
			assertTestFileSnapshot(t, keyringPath, before)
		})
	}

	readOnlyConfig := filepath.Join(dir, "readonly.yaml")
	if err := os.WriteFile(readOnlyConfig, []byte(lifecycleAuditConfig(keyringPath, filepath.Join(dir, "missing", "audit.jsonl"), "file", "")), 0o600); err != nil {
		t.Fatalf("WriteFile readonly config: %v", err)
	}
	if _, stderr, err := execute(t, "inspect", "--config", readOnlyConfig); err != nil || !strings.Contains(stderr, "proceeding because this operation is read-only") {
		t.Fatalf("inspect err=%v stderr=%q, want warning and success", err, stderr)
	}
}

func TestLifecycleAuditAppendsToExistingFile(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	const existing = "{\"event\":\"previous\"}\n"
	if err := os.WriteFile(auditPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("write existing audit log: %v", err)
	}
	configPath := writeLifecycleAuditConfig(t, dir, keyringPath, auditPath, "file", "")

	if _, _, err := execute(t, "initialize", "--config", configPath); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	data := string(mustReadFile(t, auditPath))
	if !strings.HasPrefix(data, existing) {
		t.Fatalf("audit log = %q, want existing record preserved", data)
	}
	assertDurableAudit(t, auditPath, "initialize", "succeeded")
}

func TestLifecycleAuditRequiresConfiguredFile(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(configPath, []byte("logging:\n  output: file\nevidence_provenance:\n  commitment_keyring_path: keyring.json\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	flags := pathFlags{configFile: configPath}

	if _, err := flags.durableAuditSink(); err == nil || err.Error() != "logging.file is required for a file-backed lifecycle audit sink" {
		t.Fatalf("durableAuditSink error = %v, want missing logging.file error", err)
	}
}

func TestLifecycleCommandsAuditResolveFailureAfterOpeningDurableSink(t *testing.T) {
	dir := t.TempDir()
	configPath := writeLifecycleAuditConfig(t, dir, filepath.Join(dir, "keyring.json"), filepath.Join(dir, "audit.jsonl"), "file", "")

	for _, tc := range []struct {
		name      string
		operation string
		args      []string
	}{
		{name: "initialize", operation: "initialize"},
		{name: "rotate", operation: "rotate"},
		{name: "retire", operation: "retire", args: []string{"--key-id", "ck_test", "--epoch", "1"}},
		{name: "backup", operation: "backup", args: []string{"--out", filepath.Join(dir, "backup.json")}},
		{name: "restore", operation: "restore", args: []string{"--from", filepath.Join(dir, "backup.json")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{tc.name, "--config", configPath, "--keyring", filepath.Join(dir, tc.name+"-keyring.json")}, tc.args...)
			_, _, err := execute(t, args...)
			if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
				t.Fatalf("%s error = %v, want --keyring/--config refusal", tc.name, err)
			}
			assertDurableAudit(t, filepath.Join(dir, "audit.jsonl"), tc.operation, "denied")
		})
	}
}

func TestLifecycleCommandsRejectUnavailableDurableSink(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	configPath := writeLifecycleAuditConfig(t, dir, keyringPath, filepath.Join(dir, "missing", "audit.jsonl"), "file", "")

	for _, operation := range []string{"initialize", "rotate", "retire", "backup", "restore"} {
		t.Run(operation, func(t *testing.T) {
			_, _, err := execute(t, operation, "--config", configPath)
			if err == nil || !strings.Contains(err.Error(), "file-backed lifecycle audit sink") {
				t.Fatalf("%s error = %v, want durable sink refusal", operation, err)
			}
			if _, statErr := os.Stat(keyringPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s created keyring despite unavailable audit sink: stat error = %v", operation, statErr)
			}
		})
	}
}

func TestLifecycleCommandsRejectGroupWritableAuditParent(t *testing.T) {
	requireUnixDurableAuditFile(t)
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	if err := os.Mkdir(auditDir, 0o700); err != nil {
		t.Fatalf("create audit directory: %v", err)
	}
	if err := os.Chmod(auditDir, 0o770); err != nil { // #nosec G302 -- test requires an intentionally group-writable fixture.
		t.Fatalf("make audit directory group writable: %v", err)
	}
	keyringPath := filepath.Join(dir, "keyring.json")
	configPath := writeLifecycleAuditConfig(t, dir, keyringPath, filepath.Join(auditDir, "audit.jsonl"), "file", "")

	for _, tc := range []struct {
		operation string
		args      []string
	}{
		{operation: "initialize"},
		{operation: "rotate"},
		{operation: "retire", args: []string{"--key-id", "ck_test", "--epoch", "1"}},
		{operation: "backup", args: []string{"--out", filepath.Join(dir, "backup.json")}},
		{operation: "restore", args: []string{"--from", filepath.Join(dir, "backup.json")}},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			args := append([]string{tc.operation, "--config", configPath}, tc.args...)
			if _, _, err := execute(t, args...); err == nil || !strings.Contains(err.Error(), "group or world writable") {
				t.Fatalf("%s error = %v, want unsafe-audit-parent refusal", tc.operation, err)
			}
			if _, err := os.Stat(keyringPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s modified the keyring with an unsafe audit parent: %v", tc.operation, err)
			}
		})
	}
}

func TestLifecycleAuditHelpersRejectUnavailableSink(t *testing.T) {
	t.Run("mutation without prepared sink", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		if err := beginMutationAudit(cmd, "rotate", "", 0, ""); err == nil || !strings.Contains(err.Error(), "not prepared") {
			t.Fatalf("beginMutationAudit error = %v, want unprepared-sink refusal", err)
		}
	})

	t.Run("closed sink makes intent and outcome fail", func(t *testing.T) {
		requireUnixDurableAuditFile(t)
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		logger, err := audit.NewDurableFile("json", path, false, false)
		if err != nil {
			t.Fatalf("NewDurableFile: %v", err)
		}
		logger.Close()
		cmd := &cobra.Command{}
		cmd.SetContext(context.WithValue(context.Background(), lifecycleAuditSinkContextKey{}, &lifecycleAuditSink{logger: logger, operationID: "cka_test"}))
		if err := beginMutationAudit(cmd, "rotate", "", 0, ""); err == nil || !strings.Contains(err.Error(), "not open") {
			t.Fatalf("beginMutationAudit error = %v, want closed-sink refusal", err)
		}

		cmd.SetContext(context.WithValue(context.Background(), lifecycleAuditSinkContextKey{}, &lifecycleAuditSink{logger: logger, operationID: "cka_test"}))
		if err := finishLifecycleAudit(cmd, lifecycleAuditOptions{Operation: "rotate", Outcome: "succeeded"}); err == nil || !strings.Contains(err.Error(), "persist lifecycle audit outcome") {
			t.Fatalf("finishLifecycleAudit error = %v, want closed-sink refusal", err)
		}
	})
}

func TestDurableAuditSinkRejectsInvalidFilesystemPaths(t *testing.T) {
	dir := t.TempDir()
	configPath := writeLifecycleAuditConfig(t, dir, filepath.Join(dir, "keyring.json"), filepath.Join(dir, "audit.jsonl"), "file", "")

	flags := pathFlags{configFile: configPath}
	if _, err := flags.durableAuditSink("\x00"); err == nil || !strings.Contains(err.Error(), "inspect lifecycle file") {
		t.Fatalf("durableAuditSink error = %v, want invalid protected-path refusal", err)
	}

	for _, tc := range []struct {
		name  string
		left  string
		right string
		want  string
	}{
		{name: "invalid logging path", left: "\x00", right: filepath.Join(dir, "keyring.json"), want: "inspect logging.file"},
		{name: "invalid lifecycle path", left: filepath.Join(dir, "audit.jsonl"), right: "\x00", want: "inspect lifecycle file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sameFilesystemPath(tc.left, tc.right); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("sameFilesystemPath error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNormalizedFilesystemPathRejectsUnavailableWorkingDirectory(t *testing.T) {
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	missingDir := t.TempDir()
	if err := os.Chdir(missingDir); err != nil {
		t.Fatalf("Chdir into temporary directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	if err := os.Remove(missingDir); err != nil {
		t.Fatalf("remove current directory: %v", err)
	}
	if _, err := normalizedFilesystemPath("audit.jsonl"); err == nil {
		t.Fatal("normalizedFilesystemPath succeeded without a working directory")
	}
}

func TestSameFilesystemPathRejectsInvalidSecondPathAfterWorkingDirectoryLoss(t *testing.T) {
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	missingDir := t.TempDir()
	if err := os.Chdir(missingDir); err != nil {
		t.Fatalf("Chdir into temporary directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	if err := os.Remove(missingDir); err != nil {
		t.Fatalf("remove current directory: %v", err)
	}
	if _, err := sameFilesystemPath(filepath.Join(originalDir, "audit.jsonl"), "keyring.json"); err == nil || !strings.Contains(err.Error(), "resolve lifecycle file") {
		t.Fatalf("sameFilesystemPath error = %v, want unavailable-working-directory refusal", err)
	}
}

func TestSameFilesystemPathRecognizesIdenticalPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	same, err := sameFilesystemPath(path, path)
	if err != nil {
		t.Fatalf("sameFilesystemPath: %v", err)
	}
	if !same {
		t.Fatalf("sameFilesystemPath(%q, %q) = false, want true", path, path)
	}
}

func TestLifecycleAuditReasonClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", want: ""},
		{name: "existing keyring", err: domkey.ErrAlreadyExists, want: "keyring_already_exists"},
		{name: "invalid keyring", err: domkey.ErrInvalidKeyring, want: "invalid_keyring"},
		{name: "unsafe permission", err: domkey.ErrUnsafePermission, want: "unsafe_permission"},
		{name: "missing file", err: os.ErrNotExist, want: "file_not_found"},
		{name: "permission denied", err: os.ErrPermission, want: "permission_denied"},
		{name: "missing required flag", err: fmt.Errorf("%w %q not set", errMissingRequiredFlags, "key-id"), want: "missing_required_flag"},
		{name: "missing audit sink", err: fmt.Errorf("%w: %w", errLifecycleAuditSinkUnavailable, os.ErrNotExist), want: "audit_sink_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := lifecycleAuditReason(tc.err); got != tc.want {
				t.Fatalf("lifecycleAuditReason(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestLifecycleCommandsRejectSinkDeletedBeforeIntent(t *testing.T) {
	originalOpen := newDurableAuditFile
	newDurableAuditFile = func(format, path string, includeAllowed, includeBlocked bool) (*audit.Logger, error) {
		logger, err := originalOpen(format, path, includeAllowed, includeBlocked)
		if err != nil {
			return nil, err
		}
		if err := os.Remove(filepath.Clean(path)); err != nil {
			logger.Close()
			return nil, err
		}
		return logger, nil
	}
	t.Cleanup(func() { newDurableAuditFile = originalOpen })

	for _, tc := range []struct {
		operation string
		args      []string
	}{
		{operation: "initialize"},
		{operation: "rotate"},
		{operation: "retire", args: []string{"--key-id", "ck_test", "--epoch", "1"}},
		{operation: "backup", args: []string{"--out", "backup.json"}},
		{operation: "restore", args: []string{"--from", "backup.json"}},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			dir := t.TempDir()
			keyringPath := filepath.Join(dir, "keyring.json")
			auditPath := filepath.Join(dir, "audit.jsonl")
			configPath := writeLifecycleAuditConfig(t, dir, keyringPath, auditPath, "file", "")

			args := append([]string{tc.operation, "--config", configPath}, tc.args...)
			// Assert the invariant, not the message. A deleted sink is caught
			// either when the post-open binding check runs or when the intent
			// write fails, and which one wins depends on the command's flag
			// validation order. Both are refusals; pinning one message makes
			// the test fail on an ordering change that broke nothing.
			_, _, err := execute(t, args...)
			if err == nil {
				t.Fatalf("%s succeeded with a deleted audit sink, want refusal", tc.operation)
			}
			if !strings.Contains(err.Error(), "lifecycle audit") {
				t.Fatalf("%s error = %v, want a lifecycle-audit refusal", tc.operation, err)
			}
			if _, statErr := os.Stat(auditPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s retained deleted audit sink: stat error = %v", tc.operation, statErr)
			}
			if _, statErr := os.Stat(keyringPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s created keyring despite failed intent audit: stat error = %v", tc.operation, statErr)
			}
		})
	}
}

func TestLifecycleAuditReadsStdinConfigOnce(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	configBody := lifecycleAuditConfig(keyringPath, auditPath, "file", "")

	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	if _, err := writeEnd.WriteString(configBody); err != nil {
		t.Fatalf("write stdin config: %v", err)
	}
	if err := writeEnd.Close(); err != nil {
		t.Fatalf("close stdin config: %v", err)
	}
	originalStdin := os.Stdin
	os.Stdin = readEnd
	t.Cleanup(func() {
		os.Stdin = originalStdin
		_ = readEnd.Close()
	})

	stdout, _, err := executeRaw(t, "initialize", "--config", "-")
	if err != nil {
		t.Fatalf("initialize with stdin config: %v", err)
	}
	if got := decodeMetadata(t, stdout); got.Epoch != 1 {
		t.Fatalf("initialized metadata = %+v, want epoch 1", got)
	}
	assertDurableAudit(t, auditPath, "initialize", "succeeded")
}

func TestLifecycleAuditRejectsProtectedFileAliases(t *testing.T) {
	t.Run("config", func(t *testing.T) {
		dir := t.TempDir()
		keyringPath := filepath.Join(dir, "keyring.json")
		configPath := writeLifecycleAuditConfig(t, dir, keyringPath, filepath.Join(dir, "audit.jsonl"), "file", "")
		collisionConfig := writeLifecycleAuditConfig(t, dir, keyringPath, configPath, "file", "")
		before := snapshotTestFile(t, collisionConfig)

		if _, _, err := execute(t, "initialize", "--config", collisionConfig); err == nil {
			t.Fatal("initialize succeeded with logging.file pointing at --config")
		}
		assertTestFileSnapshot(t, collisionConfig, before)
		if _, err := os.Stat(keyringPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("keyring = %v, want no file created", err)
		}
	})

	t.Run("keyring", func(t *testing.T) {
		dir := t.TempDir()
		keyringPath := filepath.Join(dir, "keyring.json")
		setupConfig := writeLifecycleAuditConfig(t, dir, keyringPath, filepath.Join(dir, "audit.jsonl"), "file", "")
		if _, _, err := execute(t, "initialize", "--config", setupConfig); err != nil {
			t.Fatalf("initialize fixture: %v", err)
		}
		before := snapshotTestFile(t, keyringPath)
		collisionConfig := writeLifecycleAuditConfig(t, dir, keyringPath, keyringPath, "file", "")

		if _, _, err := execute(t, "inspect", "--config", collisionConfig); err == nil || !strings.Contains(err.Error(), "must not refer") {
			t.Fatalf("inspect error = %v, want protected-alias refusal", err)
		}
		assertTestFileSnapshot(t, keyringPath, before)
	})

	t.Run("backup output", func(t *testing.T) {
		dir := t.TempDir()
		keyringPath := filepath.Join(dir, "keyring.json")
		backupPath := filepath.Join(dir, "backup.json")
		setupConfig := writeLifecycleAuditConfig(t, dir, keyringPath, filepath.Join(dir, "audit.jsonl"), "file", "")
		if _, _, err := execute(t, "initialize", "--config", setupConfig); err != nil {
			t.Fatalf("initialize fixture: %v", err)
		}
		collisionConfig := writeLifecycleAuditConfig(t, dir, keyringPath, backupPath, "file", "")

		if _, _, err := execute(t, "backup", "--config", collisionConfig, "--out", backupPath); err == nil {
			t.Fatal("backup succeeded with logging.file pointing at its output")
		}
		if _, err := os.Stat(backupPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("backup output = %v, want no file created", err)
		}
	})

	t.Run("backup input", func(t *testing.T) {
		dir := t.TempDir()
		keyringPath := filepath.Join(dir, "keyring.json")
		backupPath := filepath.Join(dir, "backup.json")
		restoredPath := filepath.Join(dir, "restored.json")
		setupConfig := writeLifecycleAuditConfig(t, dir, keyringPath, filepath.Join(dir, "audit.jsonl"), "file", "")
		if _, _, err := execute(t, "initialize", "--config", setupConfig); err != nil {
			t.Fatalf("initialize fixture: %v", err)
		}
		if _, _, err := execute(t, "backup", "--config", setupConfig, "--out", backupPath); err != nil {
			t.Fatalf("backup fixture: %v", err)
		}
		before := snapshotTestFile(t, backupPath)
		collisionConfig := writeLifecycleAuditConfig(t, dir, restoredPath, backupPath, "file", "")

		if _, _, err := execute(t, "restore", "--config", collisionConfig, "--from", backupPath); err == nil {
			t.Fatal("restore succeeded with logging.file pointing at its backup input")
		}
		assertTestFileSnapshot(t, backupPath, before)
		if _, err := os.Stat(restoredPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restored keyring = %v, want no file created", err)
		}
	})

	t.Run("private view", func(t *testing.T) {
		dir := t.TempDir()
		keyringPath := filepath.Join(dir, "keyring.json")
		viewPath := filepath.Join(dir, "view.txt")
		setupConfig := writeLifecycleAuditConfig(t, dir, keyringPath, filepath.Join(dir, "audit.jsonl"), "file", "")
		stdout, _, err := execute(t, "initialize", "--config", setupConfig)
		if err != nil {
			t.Fatalf("initialize fixture: %v", err)
		}
		metadata := decodeMetadata(t, stdout)
		const view = "private transformed evidence"
		if err := os.WriteFile(viewPath, []byte(view), 0o600); err != nil {
			t.Fatalf("write view: %v", err)
		}
		keyring, err := domkey.Load(keyringPath)
		if err != nil {
			t.Fatalf("load keyring: %v", err)
		}
		handle, err := keyring.Open(metadata.ActiveID, metadata.Epoch)
		if err != nil {
			t.Fatalf("open active key: %v", err)
		}
		source := contractreceipt.ProvenanceSource{SourceID: "source-1", Recipe: normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest}}
		commitment, err := contractreceipt.CommitView(handle.Key, source, view)
		if err != nil {
			t.Fatalf("commit view: %v", err)
		}
		before := snapshotTestFile(t, viewPath)
		collisionConfig := writeLifecycleAuditConfig(t, dir, keyringPath, viewPath, "file", "")

		if _, _, err := execute(t, "test", "--config", collisionConfig, "--key-id", handle.KeyID, "--epoch", "1", "--source-id", "source-1", "--commitment", commitment, "--view-file", viewPath); err == nil || !strings.Contains(err.Error(), "must not refer") {
			t.Fatalf("test error = %v, want protected-alias refusal", err)
		}
		assertTestFileSnapshot(t, viewPath, before)
	})
}

func TestLifecycleAuditRejectsSinkSwappedToKeyringAfterPreflight(t *testing.T) {
	requireUnixDurableAuditFile(t)
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	configPath := writeLifecycleAuditConfig(t, dir, keyringPath, auditPath, "file", "")
	if _, _, err := execute(t, "initialize", "--config", configPath); err != nil {
		t.Fatalf("initialize fixture: %v", err)
	}
	before := snapshotTestFile(t, keyringPath)

	originalOpen := newDurableAuditFile
	swapped := false
	newDurableAuditFile = func(format, path string, includeAllowed, includeBlocked bool) (*audit.Logger, error) {
		if filepath.Clean(path) == auditPath && !swapped {
			if err := os.Remove(auditPath); err != nil {
				t.Fatalf("remove audit path before open: %v", err)
			}
			if err := os.Link(keyringPath, auditPath); err != nil {
				t.Fatalf("link keyring as audit path before open: %v", err)
			}
			swapped = true
		}
		return originalOpen(format, path, includeAllowed, includeBlocked)
	}
	t.Cleanup(func() { newDurableAuditFile = originalOpen })

	if _, _, err := execute(t, "rotate", "--config", configPath); err == nil {
		t.Fatal("rotate succeeded after audit sink was swapped to the keyring")
	}
	if !swapped {
		t.Fatal("test did not swap audit path between preflight and open")
	}
	assertTestFileSnapshot(t, keyringPath, before)
}

func TestLifecycleAuditSinkRevalidatesProtectedAliasesBeforeWrite(t *testing.T) {
	requireUnixDurableAuditFile(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	keyringPath := filepath.Join(dir, "keyring.json")
	if err := os.WriteFile(keyringPath, []byte("keyring"), 0o600); err != nil {
		t.Fatalf("write protected keyring: %v", err)
	}
	logger, err := audit.NewDurableFile("json", auditPath, false, false)
	if err != nil {
		t.Fatalf("NewDurableFile: %v", err)
	}
	defer logger.Close()
	if err := logger.RejectDurableFileAliases(keyringPath); err != nil {
		t.Fatalf("initial protected-path check: %v", err)
	}
	if err := os.Remove(keyringPath); err != nil {
		t.Fatalf("remove protected keyring: %v", err)
	}
	if err := os.Link(auditPath, keyringPath); err != nil {
		t.Fatalf("link audit inode to protected path: %v", err)
	}

	sink := &lifecycleAuditSink{logger: logger, protectedPaths: []string{keyringPath}}
	err = sink.writeLifecycleRecord(audit.CommitmentKeyLifecycleEvent{Operation: "rotate", Phase: "intent", Outcome: "pending", OperationID: "cka_alias"})
	if err == nil || !strings.Contains(err.Error(), "must not refer") {
		t.Fatalf("writeLifecycleRecord error = %v, want protected-alias refusal", err)
	}
	if data := mustReadFile(t, auditPath); len(data) != 0 {
		t.Fatalf("audit data = %q, want no lifecycle write after alias refusal", data)
	}
}

func TestLifecycleAuditConfigCachePreservesErrorWrapping(t *testing.T) {
	path := filepath.Join(t.TempDir(), "malformed.yaml")
	if err := os.WriteFile(path, []byte("mode: [\n"), 0o600); err != nil {
		t.Fatalf("write malformed config: %v", err)
	}

	flags := pathFlags{configFile: path}
	_, firstErr := flags.loadConfig()
	_, secondErr := flags.loadConfig()
	if firstErr == nil || secondErr == nil {
		t.Fatalf("load errors = (%v, %v), want two failures", firstErr, secondErr)
	}
	if firstErr.Error() != secondErr.Error() {
		t.Fatalf("cached error = %q, first error = %q", secondErr, firstErr)
	}
}

func TestLifecycleAuditResolvesRelativeLogFileFromConfig(t *testing.T) {
	configDir := t.TempDir()
	runnerDir := t.TempDir()
	configPath := filepath.Join(configDir, "pipelock.yaml")
	if err := os.WriteFile(configPath, []byte("mode: balanced\nlogging:\n  output: file\n  file: audit.jsonl\nevidence_provenance:\n  commitment_keyring_path: state/keyring.json\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(runnerDir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previousDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	if _, _, err := execute(t, "initialize", "--config", configPath); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	assertDurableAudit(t, filepath.Join(configDir, "audit.jsonl"), "initialize", "succeeded")
	if _, err := os.Stat(filepath.Join(runnerDir, "audit.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("working-directory audit file = %v, want no file", err)
	}
}

func TestLifecycleAuditRejectsRelativeKeyringAuditAliasesOutsideConfigDirectory(t *testing.T) {
	configDir := t.TempDir()
	runnerDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(configDir, "state"), 0o700); err != nil {
		t.Fatalf("create keyring state directory: %v", err)
	}
	keyringPath := filepath.Join(configDir, "state", "keyring.json")
	setupConfig := filepath.Join(configDir, "setup.yaml")
	if err := os.WriteFile(setupConfig, []byte(lifecycleAuditConfig("state/keyring.json", "audit.jsonl", "file", "")), 0o600); err != nil {
		t.Fatalf("write setup config: %v", err)
	}
	if _, _, err := execute(t, "initialize", "--config", setupConfig); err != nil {
		t.Fatalf("initialize fixture: %v", err)
	}
	before := snapshotTestFile(t, keyringPath)

	collisionConfig := filepath.Join(configDir, "collision.yaml")
	if err := os.WriteFile(collisionConfig, []byte(lifecycleAuditConfig("state/keyring.json", "state/keyring.json", "file", "")), 0o600); err != nil {
		t.Fatalf("write collision config: %v", err)
	}
	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(runnerDir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previousDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	if _, _, err := execute(t, "inspect", "--config", collisionConfig); err == nil || !strings.Contains(err.Error(), "must not refer") {
		t.Fatalf("inspect error = %v, want protected-alias refusal", err)
	}
	assertTestFileSnapshot(t, keyringPath, before)

	for _, tc := range []struct {
		operation string
		args      []string
	}{
		{operation: "initialize"},
		{operation: "rotate"},
		{operation: "retire", args: []string{"--key-id", "ck_test", "--epoch", "1"}},
		{operation: "backup", args: []string{"--out", filepath.Join(runnerDir, "backup.json")}},
		{operation: "restore", args: []string{"--from", filepath.Join(runnerDir, "backup.json")}},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			args := append([]string{tc.operation, "--config", collisionConfig}, tc.args...)
			if _, _, err := execute(t, args...); err == nil || !strings.Contains(err.Error(), "must not refer") {
				t.Fatalf("%s error = %v, want protected-alias refusal", tc.operation, err)
			}
			assertTestFileSnapshot(t, keyringPath, before)
		})
	}
}

func writeLifecycleAuditConfig(t *testing.T, dir, keyringPath, auditPath, output, includeBlocked string) string {
	t.Helper()
	path := filepath.Join(dir, "pipelock-"+strings.ReplaceAll(filepath.Base(keyringPath), ".", "-")+".yaml")
	if err := os.WriteFile(path, []byte(lifecycleAuditConfig(keyringPath, auditPath, output, includeBlocked)), 0o600); err != nil {
		t.Fatalf("WriteFile config: %v", err)
	}
	return path
}

func lifecycleAuditConfig(keyringPath, auditPath, output, includeBlocked string) string {
	body := "mode: balanced\nlogging:\n  output: " + output + "\n"
	if auditPath != "" {
		body += "  file: " + auditPath + "\n"
	}
	if includeBlocked != "" {
		body += "  include_blocked: " + includeBlocked + "\n"
	}
	return body + "evidence_provenance:\n  commitment_keyring_path: " + keyringPath + "\n"
}

func assertDurableAudit(t *testing.T, path, operation, outcome string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(string(mustReadFile(t, path))), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if event["event"] == "commitment_key_lifecycle" && event["operation"] == operation && event["outcome"] == outcome {
			return
		}
	}
	t.Fatalf("durable audit %s/%s not found in %s", operation, outcome, path)
}

func assertDurableMutationAuditPair(t *testing.T, path, operation, outcome string) {
	t.Helper()
	intentIndex := make(map[string]int)
	for index, line := range strings.Split(strings.TrimSpace(string(mustReadFile(t, path))), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if event["event"] != "commitment_key_lifecycle" || event["operation"] != operation {
			continue
		}
		operationID, _ := event["operation_id"].(string)
		if event["phase"] == "intent" && event["outcome"] == "pending" && operationID != "" {
			intentIndex[operationID] = index
			continue
		}
		if event["phase"] == "outcome" && event["outcome"] == outcome && operationID != "" {
			if intent, ok := intentIndex[operationID]; ok && intent < index {
				return
			}
		}
	}
	t.Fatalf("durable audit %s/%s has no intent-before-outcome pair in %s", operation, outcome, path)
}

func assertMatchingLifecycleRecords(t *testing.T, operation, outcome, stderr, file string) {
	t.Helper()
	stderrRecord := findLifecycleRecord(t, operation, outcome, stderr)
	fileRecord := findLifecycleRecord(t, operation, outcome, file)
	for field, want := range stderrRecord {
		if got := fileRecord[field]; got != want {
			t.Fatalf("file lifecycle record %q = %#v, want stderr value %#v; file=%#v stderr=%#v", field, got, want, fileRecord, stderrRecord)
		}
	}
}

func findLifecycleRecord(t *testing.T, operation, outcome, data string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if (record["event_type"] == "commitment_key_lifecycle" || record["event"] == "commitment_key_lifecycle") && record["operation"] == operation && record["outcome"] == outcome {
			return record
		}
	}
	t.Fatalf("commitment key lifecycle %s/%s record not found in %q", operation, outcome, data)
	return nil
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	return data
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
	if !strings.Contains(cmd.Long, "Windows does not support durable lifecycle audit binding") {
		t.Fatalf("commitment-key help omits Windows lifecycle support boundary: %q", cmd.Long)
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
	return executeInputRaw(t, input, withTestAuditConfig(t, args)...)
}

func executeRaw(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	return executeInputRaw(t, "", args...)
}

func executeInputRaw(t *testing.T, input string, args ...string) (string, string, error) {
	t.Helper()
	return executeCommand(input, args...)
}

func executeCommand(input string, args ...string) (string, string, error) {
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

// withTestAuditConfig keeps legacy --keyring test cases focused on the
// keyring behavior under test. Production mutations require --config so they
// can open the configured durable audit sink before changing key state.
func withTestAuditConfig(t *testing.T, args []string) []string {
	t.Helper()
	for _, arg := range args {
		if arg == "--config" {
			return args
		}
	}
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "--keyring" {
			continue
		}
		keyringPath := filepath.Clean(args[i+1])
		if err := os.MkdirAll(filepath.Dir(keyringPath), 0o750); err != nil {
			t.Fatalf("MkdirAll config directory: %v", err)
		}
		configPath := filepath.Join(filepath.Dir(keyringPath), "test-pipelock.yaml")
		auditPath := filepath.Join(filepath.Dir(keyringPath), "lifecycle-audit.jsonl")
		body := "mode: balanced\nlogging:\n  output: file\n  file: " + auditPath + "\nevidence_provenance:\n  commitment_keyring_path: " + keyringPath + "\n"
		if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
			t.Fatalf("WriteFile config: %v", err)
		}
		out := append([]string{}, args[:i]...)
		out = append(out, "--config", configPath)
		out = append(out, args[i+2:]...)
		return out
	}
	return args
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
