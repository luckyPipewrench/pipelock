// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package commitmentkey

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

	stdout, stderr, err = execute(t, "rotate", "--keyring", path)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	rotated := decodeMetadata(t, stdout)
	if rotated.Epoch != 2 || rotated.ActiveID == first.ActiveID || len(rotated.Keys) != 2 {
		t.Fatalf("rotated metadata = %+v", rotated)
	}
	assertAudit(t, stderr, "rotate", "succeeded")

	ref := fmt.Sprintf("%s:%d", first.ActiveID, first.Epoch)
	_, stderr, err = execute(t, "retire", "--keyring", path, "--key-id", first.ActiveID, "--epoch", "1", "--retained-reference", ref)
	if !errors.Is(err, domkey.ErrRetainedKey) {
		t.Fatalf("retire retained error = %v, want ErrRetainedKey", err)
	}
	assertAudit(t, stderr, "retire", "denied")

	_, stderr, err = execute(t, "backup", "--keyring", path, "--out", backup)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	assertAudit(t, stderr, "backup", "succeeded")
	if err := os.Remove(path); err != nil {
		t.Fatalf("destroy keyring: %v", err)
	}
	_, stderr, err = execute(t, "restore", "--keyring", path, "--from", backup)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	assertAudit(t, stderr, "restore", "succeeded")

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
	stdout, stderr, err = execute(t, "test", "--keyring", path, "--key-id", first.ActiveID, "--epoch", "1", "--source-id", "source-1", "--source-ordinal", "1", "--view", "opened after restore", "--commitment", commitment)
	if err != nil {
		t.Fatalf("test opening: %v", err)
	}
	if !strings.Contains(stdout, `"opened": true`) {
		t.Fatalf("test output = %q", stdout)
	}
	assertAudit(t, stderr, "test", "succeeded")
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
	_, stderr, err := execute(t, "test", "--config", cfgPath, "--key-id", metadata.ActiveID, "--epoch", "1", "--source-id", "source-1", "--view", "value", "--commitment", "hmac-sha256:"+strings.Repeat("0", 64))
	if err == nil || err.Error() != "commitment mismatch" {
		t.Fatalf("test mismatch error = %v", err)
	}
	assertAudit(t, stderr, "test", "denied")
	if _, _, err := execute(t, "inspect", "--keyring", "x", "--config", cfgPath); err == nil {
		t.Fatal("mutually exclusive path flags succeeded")
	}
}

func execute(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	root := &cobra.Command{Use: "pipelock", SilenceUsage: true, SilenceErrors: true}
	root.SetOut(stdout)
	root.SetErr(stderr)
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

func assertAudit(t *testing.T, raw, operation, outcome string) {
	t.Helper()
	var event auditEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &event); err != nil {
		t.Fatalf("decode audit %q: %v", raw, err)
	}
	if event.EventType != "commitment_key_lifecycle" || event.Operation != operation || event.Outcome != outcome || event.Timestamp == "" {
		t.Fatalf("audit event = %+v", event)
	}
}

func assertNoKeyMaterial(t *testing.T, outputs ...string) {
	t.Helper()
	for _, output := range outputs {
		if strings.Contains(output, `"key"`) {
			t.Fatalf("operator output exposed key material field: %s", output)
		}
	}
}
