//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type failAfterWriter struct {
	writes int
	failAt int
}

type failPayloadWriter struct{}

func (failPayloadWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("payload")) {
		return 0, errors.New("forced payload failure")
	}
	return len(p), nil
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes >= w.failAt {
		return 0, errors.New("forced writer failure")
	}
	return len(p), nil
}

func TestBackupState_ErrorPaths(t *testing.T) {
	t.Run("canonical path", func(t *testing.T) {
		dir := t.TempDir()
		dangling := filepath.Join(dir, "missing-target")
		if err := os.Symlink(dangling, filepath.Join(dir, "dangling")); err != nil {
			t.Fatal(err)
		}
		err := BackupState(filepath.Join(dir, "dangling", "state"), filepath.Join(dir, "backup.tar"))
		if err == nil || !strings.Contains(err.Error(), "resolve dashboard state directory") {
			t.Fatalf("BackupState error = %v", err)
		}
	})

	t.Run("archive path cannot be resolved through a file", func(t *testing.T) {
		stateDir := t.TempDir()
		parent := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(parent, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		err := BackupState(stateDir, filepath.Join(parent, "backup.tar"))
		if err == nil || !strings.Contains(err.Error(), "resolve dashboard backup path") {
			t.Fatalf("BackupState error = %v", err)
		}
	})

	t.Run("archive directory is not writable", func(t *testing.T) {
		stateDir := t.TempDir()
		archiveDir := t.TempDir()
		readOnlyMode := os.FileMode(0o500)
		if err := os.Chmod(archiveDir, readOnlyMode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			writableMode := os.FileMode(0o700)
			_ = os.Chmod(archiveDir, writableMode)
		})
		err := BackupState(stateDir, filepath.Join(archiveDir, "backup.tar"))
		if err == nil || !strings.Contains(err.Error(), "write dashboard backup") {
			t.Fatalf("BackupState error = %v", err)
		}
	})
}

func TestWriteTarFile_PropagatesWriterErrors(t *testing.T) {
	t.Run("header", func(t *testing.T) {
		writer := &failAfterWriter{failAt: 1}
		err := writeTarFile(tar.NewWriter(writer), "state.json", []byte("payload"))
		if err == nil || !strings.Contains(err.Error(), "write dashboard backup header") {
			t.Fatalf("writeTarFile error = %v", err)
		}
	})
	t.Run("body", func(t *testing.T) {
		err := writeTarFile(tar.NewWriter(failPayloadWriter{}), "state.json", []byte("payload"))
		if err == nil || !strings.Contains(err.Error(), "write dashboard backup file") {
			t.Fatalf("writeTarFile error = %v", err)
		}
	})
}

func TestReadBackupArchive_ErrorPaths(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		if _, err := readBackupArchive(filepath.Join(t.TempDir(), "missing.tar")); err == nil {
			t.Fatal("missing archive was read")
		}
	})

	t.Run("directory read", func(t *testing.T) {
		if _, err := readBackupArchive(t.TempDir()); err == nil {
			t.Fatal("directory was read as an archive")
		}
	})

	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "oversized.tar")
		file, err := os.Create(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(maxBackupArchiveSize + 1); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := readBackupArchive(path); err == nil || !strings.Contains(err.Error(), "archive exceeds") {
			t.Fatalf("readBackupArchive error = %v", err)
		}
	})
}

func TestDecodeStrictJSON_ErrorPaths(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "duplicate key", data: `{"version":1,"version":1}`},
		{name: "unknown field", data: `{"version":1,"future":true}`},
		{name: "trailing value", data: `{"version":1} {"version":1}`},
		{name: "invalid trailing data", data: `{"version":1} !`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var manifest backupManifest
			if err := decodeStrictJSON([]byte(test.data), &manifest); err == nil {
				t.Fatal("invalid JSON was accepted")
			}
		})
	}
}

func TestRestoreState_RollsBackAfterSecondFileWriteFailure(t *testing.T) {
	stateDir := t.TempDir()
	originalInbox := []byte(`{"version":1,"attempts":[],"dead_letters":[],"dropped":7,"updated_at":"0001-01-01T00:00:00Z"}`)
	inboxPath := filepath.Join(stateDir, DeliveryInboxStateFile)
	if err := os.WriteFile(inboxPath, originalInbox, 0o600); err != nil {
		t.Fatal(err)
	}

	sourceDir := t.TempDir()
	replacementInbox := []byte(`{"version":1,"attempts":[],"dead_letters":[],"dropped":9,"updated_at":"0001-01-01T00:00:00Z"}`)
	if err := os.WriteFile(filepath.Join(sourceDir, DeliveryInboxStateFile), replacementInbox, 0o600); err != nil {
		t.Fatal(err)
	}
	records := make([]ExemptionRecord, 30000)
	for index := range records {
		records[index] = ExemptionRecord{
			ID:      fmt.Sprintf("exm-%05d", index),
			Scope:   fmt.Sprintf("service-%05d.vendor.example", index),
			Owner:   "security",
			Reason:  strings.Repeat("planned maintenance ", 8),
			Created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Expiry:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		}
	}
	exemptions, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, ExemptionStateFile), exemptions, 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "backup.tar")
	if err := BackupState(sourceDir, archive); err != nil {
		t.Fatal(err)
	}

	originalWrite := writeDashboardStateFile
	exemptionWriteFailed := false
	writeDashboardStateFile = func(path string, data []byte, perm os.FileMode) error {
		if filepath.Base(path) == ExemptionStateFile && !exemptionWriteFailed {
			exemptionWriteFailed = true
			return errors.New("forced exemption write failure")
		}
		return originalWrite(path, data, perm)
	}
	t.Cleanup(func() {
		writeDashboardStateFile = originalWrite
	})

	err = RestoreState(stateDir, archive)
	if err == nil || !strings.Contains(err.Error(), ExemptionStateFile) {
		t.Fatalf("RestoreState error = %v", err)
	}
	if !exemptionWriteFailed {
		t.Fatal("forced exemption write failure was not reached")
	}
	after, readErr := os.ReadFile(filepath.Clean(inboxPath))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, originalInbox) {
		t.Fatalf("first state file was not rolled back: %s", after)
	}
	if _, statErr := os.Stat(filepath.Join(stateDir, ExemptionStateFile)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("previously absent state file remains after rollback: %v", statErr)
	}
}

func TestDeliveryValidationAndPending(t *testing.T) {
	when := time.Unix(100, 0).UTC()
	validQueued := DeliveryAttempt{ID: "queued", AlertID: "alert", Status: DeliveryQueued, AttemptedAt: when}
	validFailed := DeliveryAttempt{ID: "failed", AlertID: "alert", Status: DeliveryFailed, AttemptedAt: when, Error: "unavailable"}
	tests := []struct {
		name    string
		attempt DeliveryAttempt
	}{
		{name: "missing identity", attempt: DeliveryAttempt{Status: DeliveryQueued, AttemptedAt: when}},
		{name: "queued with error", attempt: DeliveryAttempt{ID: "x", AlertID: "a", Status: DeliveryQueued, AttemptedAt: when, Error: "bad"}},
		{name: "failed without error", attempt: DeliveryAttempt{ID: "x", AlertID: "a", Status: DeliveryFailed, AttemptedAt: when}},
		{name: "unknown status", attempt: DeliveryAttempt{ID: "x", AlertID: "a", Status: "future", AttemptedAt: when}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateDeliveryAttempt(test.attempt); err == nil {
				t.Fatal("invalid attempt was accepted")
			}
		})
	}

	stateTests := []struct {
		name  string
		state deliveryInboxState
	}{
		{name: "version", state: deliveryInboxState{}},
		{name: "attempt", state: deliveryInboxState{Version: deliveryInboxVersion, Attempts: []DeliveryAttempt{{}}}},
		{name: "dead letter status", state: deliveryInboxState{Version: deliveryInboxVersion, DeadLetters: []DeliveryAttempt{validQueued}}},
	}
	for _, test := range stateTests {
		t.Run("state "+test.name, func(t *testing.T) {
			if err := validateDeliveryState(test.state); err == nil {
				t.Fatal("invalid state was accepted")
			}
		})
	}

	inbox := &DeliveryInbox{state: deliveryInboxState{Attempts: []DeliveryAttempt{validQueued, validFailed, {
		ID: "delivered", AlertID: "alert", Status: DeliveryDelivered, AttemptedAt: when,
	}}}}
	pending := inbox.Pending()
	if len(pending) != 2 || pending[0].ID != "queued" || pending[1].ID != "failed" {
		t.Fatalf("Pending = %#v", pending)
	}
	pending[0].ID = "mutated"
	if inbox.state.Attempts[0].ID != "queued" {
		t.Fatal("Pending returned storage-backed data")
	}
}

func TestDeliveryInbox_NormalizesRetentionAndSaturatesDrops(t *testing.T) {
	t.Parallel()

	when := time.Unix(100, 0).UTC()

	overflowState := func() deliveryInboxState {
		attempts := make([]DeliveryAttempt, maxPersistedDeliveryAttempts+2)
		for index := range attempts {
			attempts[index] = DeliveryAttempt{ID: fmt.Sprintf("attempt-%04d", index), AlertID: "alert-a", Status: DeliveryQueued, AttemptedAt: when.Add(time.Duration(index) * time.Second)}
		}
		deadLetters := make([]DeliveryAttempt, maxPersistedDeadLetters+2)
		for index := range deadLetters {
			deadLetters[index] = DeliveryAttempt{ID: fmt.Sprintf("failed-%04d", index), AlertID: "alert-a", Status: DeliveryFailed, AttemptedAt: when.Add(time.Duration(index) * time.Second), Error: "provider-token unavailable"}
		}
		return deliveryInboxState{
			Version:     deliveryInboxVersion,
			Attempts:    attempts,
			DeadLetters: deadLetters,
			Totals:      &deliveryTotals{Queued: uint64(len(attempts)), Failed: uint64(len(deadLetters)), DeadLetters: uint64(len(deadLetters))},
			Dropped:     ^uint64(0) - 1,
			UpdatedAt:   when,
		}
	}

	t.Run("retention", func(t *testing.T) {
		state := overflowState()
		if err := normalizeDeliveryState(&state); err != nil {
			t.Fatalf("normalizeDeliveryState: %v", err)
		}
		if len(state.Attempts) != maxPersistedDeliveryAttempts || state.Attempts[0].ID != "attempt-0002" {
			t.Fatalf("attempt retention = len %d first %q", len(state.Attempts), state.Attempts[0].ID)
		}
		if len(state.DeadLetters) != maxPersistedDeadLetters || state.DeadLetters[0].ID != "failed-0002" {
			t.Fatalf("dead-letter retention = len %d first %q", len(state.DeadLetters), state.DeadLetters[0].ID)
		}
	})

	t.Run("in-memory saturation", func(t *testing.T) {
		state := overflowState()
		if err := normalizeDeliveryState(&state); err != nil {
			t.Fatalf("normalizeDeliveryState: %v", err)
		}
		inbox := &DeliveryInbox{state: state}
		inbox.pendingDrops.Store(3)
		if got := inbox.Health().Dropped; got != ^uint64(0) {
			t.Fatalf("saturated dropped = %d, want max uint64", got)
		}
	})

	t.Run("full-queue drop saturation", func(t *testing.T) {
		full := &DeliveryInbox{queue: make(chan DeliveryAttempt), dropSignal: make(chan struct{}, 1)}
		full.pendingDrops.Store(^uint64(0))
		if full.Record(DeliveryAttempt{ID: "overflow-drop", AlertID: "alert-a", Status: DeliveryQueued, AttemptedAt: when}) {
			t.Fatal("Record unexpectedly queued on a full inbox")
		}
		if got := full.pendingDrops.Load(); got != ^uint64(0) {
			t.Fatalf("pending dropped wrapped to %d, want max uint64", got)
		}
	})

	t.Run("persisted saturation", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DeliveryInboxStateFile)
		persisted := deliveryInboxState{Version: deliveryInboxVersion, Dropped: ^uint64(0) - 1}
		data, err := json.Marshal(persisted)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		flush := &DeliveryInbox{path: path, state: persisted}
		flush.pendingDrops.Store(3)
		flush.flushDrops()
		if flush.workerErr != nil {
			t.Fatalf("flushDrops: %v", flush.workerErr)
		}
		health, err := LoadDeliveryHealth(path)
		if err != nil {
			t.Fatalf("LoadDeliveryHealth: %v", err)
		}
		if health.Dropped != ^uint64(0) {
			t.Fatalf("persisted dropped = %d, want max uint64", health.Dropped)
		}
	})
}

func TestDeliveryInboxApply_ErrorPaths(t *testing.T) {
	attempt := DeliveryAttempt{ID: "delivery", AlertID: "alert", Status: DeliveryDelivered, AttemptedAt: time.Unix(100, 0).UTC()}

	t.Run("lock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DeliveryInboxStateFile)
		if err := os.Mkdir(path+".lock", 0o700); err != nil {
			t.Fatal(err)
		}
		inbox := &DeliveryInbox{path: path, state: deliveryInboxState{Version: deliveryInboxVersion}}
		inbox.apply(attempt)
		if inbox.workerErr == nil || len(inbox.state.Attempts) != 0 {
			t.Fatalf("apply lock failure: err=%v state=%#v", inbox.workerErr, inbox.state)
		}
	})

	t.Run("reload", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DeliveryInboxStateFile)
		if err := os.WriteFile(path, []byte(`{"version":999}`), 0o600); err != nil {
			t.Fatal(err)
		}
		inbox := &DeliveryInbox{path: path, state: deliveryInboxState{Version: deliveryInboxVersion}}
		inbox.apply(attempt)
		if inbox.workerErr == nil || len(inbox.state.Attempts) != 0 {
			t.Fatalf("apply reload failure: err=%v state=%#v", inbox.workerErr, inbox.state)
		}
	})

	t.Run("persist", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, DeliveryInboxStateFile)
		state := []byte(`{"version":1,"attempts":[],"dead_letters":[],"dropped":0,"updated_at":"0001-01-01T00:00:00Z"}`)
		if err := os.WriteFile(path, state, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".lock", nil, 0o600); err != nil {
			t.Fatal(err)
		}
		readOnlyMode := os.FileMode(0o500)
		if err := os.Chmod(dir, readOnlyMode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			writableMode := os.FileMode(0o700)
			_ = os.Chmod(dir, writableMode)
		})
		inbox := &DeliveryInbox{path: path, state: deliveryInboxState{Version: deliveryInboxVersion}}
		inbox.apply(attempt)
		if inbox.workerErr == nil || len(inbox.state.Attempts) != 0 {
			t.Fatalf("apply persist failure: err=%v state=%#v", inbox.workerErr, inbox.state)
		}
	})
}

func TestDeliveryInboxFlushDrops_ErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, string)
	}{
		{name: "lock", prepare: func(t *testing.T, path string) {
			t.Helper()
			if err := os.Mkdir(path+".lock", 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "reload", prepare: func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, []byte(`{"version":999}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), DeliveryInboxStateFile)
			test.prepare(t, path)
			inbox := &DeliveryInbox{path: path, state: deliveryInboxState{Version: deliveryInboxVersion}}
			inbox.pendingDrops.Store(2)
			inbox.flushDrops()
			if inbox.workerErr == nil || inbox.pendingDrops.Load() != 2 {
				t.Fatalf("flushDrops failure: err=%v pending=%d", inbox.workerErr, inbox.pendingDrops.Load())
			}
		})
	}
}

func TestLoadDeliveryHealth_ErrorPaths(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		if _, err := LoadDeliveryHealth(filepath.Join(t.TempDir(), "missing.json")); err == nil {
			t.Fatal("missing delivery inbox was accepted")
		}
	})
	t.Run("invalid", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "invalid.json")
		if err := os.WriteFile(path, []byte(`{"version":999}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDeliveryHealth(path); err == nil {
			t.Fatal("invalid delivery inbox was accepted")
		}
	})
	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "oversized.json")
		fileMode := os.FileMode(0o600)
		if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxDeliveryInboxFileBytes+1), fileMode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDeliveryHealth(path); err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("oversized delivery inbox error = %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "outside.json")
		if err := os.WriteFile(target, []byte(`{"version":1,"attempts":[],"dead_letters":[],"dropped":0,"updated_at":"0001-01-01T00:00:00Z"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "delivery-inbox-link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDeliveryHealth(link); err == nil {
			t.Fatal("symlinked delivery inbox was accepted")
		}
	})
}

func TestInspectReadModelIndex_ErrorPaths(t *testing.T) {
	t.Run("missing index", func(t *testing.T) {
		if _, _, err := InspectReadModelIndex(filepath.Join(t.TempDir(), "missing.json"), t.TempDir()); err == nil {
			t.Fatal("missing index was accepted")
		}
	})
	t.Run("invalid index", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ReadModelIndexFile)
		if err := os.WriteFile(path, []byte(`{"rebuild_version":999}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := InspectReadModelIndex(path, t.TempDir()); err == nil {
			t.Fatal("invalid index was accepted")
		}
	})
	t.Run("symlink index", func(t *testing.T) {
		sourceDir := t.TempDir()
		target := writeTestReadModel(t, sourceDir)
		link := filepath.Join(t.TempDir(), ReadModelIndexFile)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, _, err := InspectReadModelIndex(link, sourceDir); err == nil {
			t.Fatal("symlinked read-model index was accepted")
		}
	})
	t.Run("missing source directory", func(t *testing.T) {
		indexPath := writeTestReadModel(t, t.TempDir())
		if _, _, err := InspectReadModelIndex(indexPath, filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("missing source directory was accepted")
		}
	})
	t.Run("unsafe source path", func(t *testing.T) {
		sourceDir := t.TempDir()
		indexPath := writeTestReadModel(t, sourceDir)
		index := readIndex(t, indexPath)
		index.Sources[0].File = "../evidence.jsonl"
		data, err := json.Marshal(index)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(indexPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := InspectReadModelIndex(indexPath, sourceDir); err == nil {
			t.Fatal("unsafe source path was accepted")
		}
	})
	t.Run("source verification", func(t *testing.T) {
		sourceDir := t.TempDir()
		indexPath := writeTestReadModel(t, sourceDir)
		sourcePath := filepath.Join(sourceDir, "evidence-agent-0.jsonl")
		if err := os.WriteFile(sourcePath, []byte("not-json\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, fresh, err := InspectReadModelIndex(indexPath, sourceDir); err != nil || fresh {
			t.Fatalf("InspectReadModelIndex fresh = %t, error = %v", fresh, err)
		}
	})
}

func TestRebuildReadModel_ErrorPaths(t *testing.T) {
	t.Run("missing source directory", func(t *testing.T) {
		err := RebuildReadModel(RebuildOptions{SourceDir: filepath.Join(t.TempDir(), "missing"), Output: filepath.Join(t.TempDir(), ReadModelIndexFile)})
		if err == nil || !strings.Contains(err.Error(), "NO SOURCE EVIDENCE") {
			t.Fatalf("RebuildReadModel error = %v", err)
		}
	})
	t.Run("zero rebuild time", func(t *testing.T) {
		sourceDir := t.TempDir()
		writeEvidence(t, sourceDir, testEvidence("agent-a"))
		err := RebuildReadModel(RebuildOptions{SourceDir: sourceDir, Output: filepath.Join(t.TempDir(), ReadModelIndexFile), Now: func() time.Time { return time.Time{} }})
		if err == nil || !strings.Contains(err.Error(), "must not be zero") {
			t.Fatalf("RebuildReadModel error = %v", err)
		}
	})
	t.Run("symlinked evidence", func(t *testing.T) {
		sourceDir := t.TempDir()
		target := filepath.Join(t.TempDir(), "outside.jsonl")
		fileMode := os.FileMode(0o600)
		if err := os.WriteFile(target, []byte(testEvidence("agent-a")), fileMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(sourceDir, "evidence-agent-0.jsonl")); err != nil {
			t.Fatal(err)
		}
		for name, enumerate := range map[string]func(string) ([]string, error){
			"rebuild":      evidencePaths,
			"verification": boundedEvidencePaths,
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := enumerate(sourceDir); err == nil || !strings.Contains(err.Error(), "non-regular") {
					t.Fatalf("symlinked evidence error = %v", err)
				}
			})
		}
		err := RebuildReadModel(RebuildOptions{SourceDir: sourceDir, Output: filepath.Join(t.TempDir(), ReadModelIndexFile)})
		if err == nil || !strings.Contains(err.Error(), "non-regular") {
			t.Fatalf("symlinked evidence error = %v", err)
		}
	})
	t.Run("output parent is a file", func(t *testing.T) {
		sourceDir := t.TempDir()
		writeEvidence(t, sourceDir, testEvidence("agent-a"))
		parent := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(parent, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		err := RebuildReadModel(RebuildOptions{SourceDir: sourceDir, Output: filepath.Join(parent, ReadModelIndexFile)})
		if err == nil || !strings.Contains(err.Error(), "create read-model directory") {
			t.Fatalf("RebuildReadModel error = %v", err)
		}
	})
	t.Run("output directory is not writable", func(t *testing.T) {
		sourceDir := t.TempDir()
		writeEvidence(t, sourceDir, testEvidence("agent-a"))
		outputDir := t.TempDir()
		readOnlyMode := os.FileMode(0o500)
		if err := os.Chmod(outputDir, readOnlyMode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			writableMode := os.FileMode(0o700)
			_ = os.Chmod(outputDir, writableMode)
		})
		err := RebuildReadModel(RebuildOptions{SourceDir: sourceDir, Output: filepath.Join(outputDir, ReadModelIndexFile)})
		if err == nil || !strings.Contains(err.Error(), "write read-model index") {
			t.Fatalf("RebuildReadModel error = %v", err)
		}
	})
}

func TestBuildReadModelIndex_ErrorPaths(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "malformed", data: "not-json\n"},
		{name: "empty", data: ""},
		{name: "mixed sessions", data: testEvidence("agent-a") + testEvidence("agent-b")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "evidence-agent-0.jsonl")
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := buildReadModelIndex([]string{path}, time.Unix(100, 0).UTC()); err == nil {
				t.Fatal("invalid source evidence was accepted")
			}
		})
	}

	t.Run("unreadable source", func(t *testing.T) {
		path := writeEvidence(t, t.TempDir(), testEvidence("agent-a"))
		unreadableMode := os.FileMode(0o000)
		if err := os.Chmod(path, unreadableMode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			readableMode := os.FileMode(0o600)
			_ = os.Chmod(path, readableMode)
		})
		if _, err := buildReadModelIndex([]string{path}, time.Unix(100, 0).UTC()); err == nil {
			t.Fatal("unreadable source evidence was accepted")
		}
	})

	t.Run("oversized source", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "evidence-agent-0.jsonl")
		if err := os.WriteFile(path, bytes.Repeat([]byte{' '}, 8<<20+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := buildReadModelIndex([]string{path}, time.Unix(100, 0).UTC()); err == nil || !strings.Contains(err.Error(), "read limit exceeded") {
			t.Fatalf("oversized source error = %v, want bounded-read rejection", err)
		}
	})

	t.Run("unordered entries and multiple sources", func(t *testing.T) {
		dir := t.TempDir()
		first := filepath.Join(dir, "evidence-agent-a-0.jsonl")
		firstData := strings.Join([]string{
			`{"v":2,"seq":5,"ts":"2026-01-01T00:05:00Z","session_id":"agent-a","type":"request"}`,
			`{"v":2,"seq":2,"ts":"2026-01-01T00:02:00Z","session_id":"agent-a","type":"response"}`,
		}, "\n") + "\n"
		second := filepath.Join(dir, "evidence-agent-b-0.jsonl")
		secondData := strings.Join([]string{
			`{"v":2,"seq":9,"ts":"2026-01-01T00:09:00Z","session_id":"agent-b","type":"request"}`,
			`{"v":2,"seq":1,"ts":"2026-01-01T00:01:00Z","session_id":"agent-b","type":"response"}`,
		}, "\n") + "\n"
		for path, data := range map[string]string{first: firstData, second: secondData} {
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		index, err := buildReadModelIndex([]string{first, second}, time.Unix(100, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		if index.SourceRange.FirstSeq != 1 || index.SourceRange.LastSeq != 9 || index.EntryCount != 4 {
			t.Fatalf("unexpected aggregate range: %#v", index)
		}
	})
}

func writeTestReadModel(t *testing.T, sourceDir string) string {
	t.Helper()
	writeEvidence(t, sourceDir, testEvidence("agent-a"))
	output := filepath.Join(t.TempDir(), ReadModelIndexFile)
	if err := RebuildReadModel(RebuildOptions{SourceDir: sourceDir, Output: output}); err != nil {
		t.Fatal(err)
	}
	return output
}

func writeEvidence(t *testing.T, dir, data string) string {
	t.Helper()
	path := filepath.Join(dir, "evidence-agent-0.jsonl")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testEvidence(sessionID string) string {
	return fmt.Sprintf(`{"v":2,"seq":1,"ts":"2026-01-01T00:00:00Z","session_id":%q,"type":"request"}`+"\n", sessionID)
}

func TestDeliveryInboxClose_Nil(t *testing.T) {
	var inbox *DeliveryInbox
	if err := inbox.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
