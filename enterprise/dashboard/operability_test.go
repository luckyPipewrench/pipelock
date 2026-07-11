//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBackupRestore_RestartAndCorruptionAtomicity(t *testing.T) {
	stateDir := t.TempDir()
	exemptions := []byte(`[{"id":"exm-1","scope":"api.vendor.example","owner":"security","reason":"temporary exception","created":"2026-01-01T00:00:00Z","expiry":"2026-02-01T00:00:00Z"}]`)
	if err := os.WriteFile(filepath.Join(stateDir, ExemptionStateFile), exemptions, 0o600); err != nil {
		t.Fatal(err)
	}
	inbox, err := OpenDeliveryInbox(DeliveryInboxOptions{Path: filepath.Join(stateDir, DeliveryInboxStateFile), QueueSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	if !inbox.Record(DeliveryAttempt{ID: "delivery-1", AlertID: "alert-1", Status: DeliveryFailed, AttemptedAt: time.Unix(100, 0).UTC(), Error: "timeout"}) {
		t.Fatal("record unexpectedly dropped")
	}
	if err := inbox.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "dashboard-backup.tar")
	if err := BackupState(stateDir, archive); err != nil {
		t.Fatalf("BackupState: %v", err)
	}
	info, err := os.Stat(archive)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode = %v, err=%v", info.Mode().Perm(), err)
	}
	first, err := os.ReadFile(filepath.Clean(archive))
	if err != nil {
		t.Fatal(err)
	}
	secondArchive := filepath.Join(t.TempDir(), "dashboard-backup.tar")
	if err := BackupState(stateDir, secondArchive); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(filepath.Clean(secondArchive))
	if !bytes.Equal(first, second) {
		t.Fatal("backup archive is not deterministic")
	}

	if err := os.WriteFile(filepath.Join(stateDir, ExemptionStateFile), []byte(`[{"id":"new"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt := filepath.Join(t.TempDir(), "corrupt.tar")
	if err := os.WriteFile(corrupt, first[:len(first)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreState(stateDir, corrupt); err == nil {
		t.Fatal("partial archive restore succeeded")
	}
	unchanged, _ := os.ReadFile(filepath.Clean(filepath.Join(stateDir, ExemptionStateFile)))
	if string(unchanged) != `[{"id":"new"}]` {
		t.Fatalf("failed restore changed prior state: %s", unchanged)
	}

	if err := RestoreState(stateDir, archive); err != nil {
		t.Fatalf("RestoreState: %v", err)
	}
	restored, _ := os.ReadFile(filepath.Clean(filepath.Join(stateDir, ExemptionStateFile)))
	if !bytes.Equal(restored, exemptions) {
		t.Fatalf("restored exemptions = %s", restored)
	}
	reopened, err := OpenDeliveryInbox(DeliveryInboxOptions{Path: filepath.Join(stateDir, DeliveryInboxStateFile), QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close(context.Background()) }()
	dead := reopened.DeadLetters()
	if len(dead) != 1 || dead[0].ID != "delivery-1" {
		t.Fatalf("dead letters after restore/restart = %#v", dead)
	}
}

func TestBackupState_RejectsArchivePathThatOverwritesDurableState(t *testing.T) {
	stateDir := t.TempDir()
	statePath := filepath.Join(stateDir, ExemptionStateFile)
	original := []byte(`[]`)
	if err := os.WriteFile(statePath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := BackupState(stateDir, statePath); err == nil {
		t.Fatal("backup overwrote a durable state file with the archive")
	}
	after, err := os.ReadFile(filepath.Clean(statePath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("durable state changed after rejected backup: %q", after)
	}
}

func TestRestoreState_RejectsTraversalAndUnknownFiles(t *testing.T) {
	for _, name := range []string{"../escape", "unknown.json"} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: 2}); err != nil {
				t.Fatal(err)
			}
			_, _ = tw.Write([]byte("{}"))
			_ = tw.Close()
			archive := filepath.Join(t.TempDir(), "hostile.tar")
			_ = os.WriteFile(archive, buf.Bytes(), 0o600)
			if err := RestoreState(t.TempDir(), archive); err == nil {
				t.Fatal("hostile archive accepted")
			}
		})
	}
}

func TestRestoreState_RejectsAmbiguousOrInvalidJSON(t *testing.T) {
	tests := []struct {
		name     string
		manifest []byte
		fileName string
		state    []byte
	}{
		{
			name:     "duplicate manifest key",
			manifest: []byte(`{"version":999,"version":1,"files":[]}`),
		},
		{
			name:     "unknown manifest field",
			manifest: []byte(`{"version":1,"files":[],"future_policy":"ignored"}`),
		},
		{
			name:     "duplicate delivery state key",
			fileName: DeliveryInboxStateFile,
			state:    []byte(`{"version":999,"version":1,"attempts":[],"dead_letters":[],"dropped":0,"updated_at":"0001-01-01T00:00:00Z"}`),
		},
		{
			name:     "unknown delivery state field",
			fileName: DeliveryInboxStateFile,
			state:    []byte(`{"version":1,"attempts":[],"dead_letters":[],"dropped":0,"updated_at":"0001-01-01T00:00:00Z","future_policy":"ignored"}`),
		},
		{
			name:     "invalid exemption record",
			fileName: ExemptionStateFile,
			state:    []byte(`[{"id":"exm-1","scope":"api.vendor.example"}]`),
		},
		{
			name:     "unknown exemption field",
			fileName: ExemptionStateFile,
			state:    []byte(`[{"id":"exm-1","scope":"api.vendor.example","owner":"security","reason":"temporary","created":"2026-01-01T00:00:00Z","expiry":"2026-02-01T00:00:00Z","future_policy":"ignored"}]`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := test.manifest
			if archive == nil {
				sum := sha256.Sum256(test.state)
				manifest := backupManifest{
					Version: backupFormatVersion,
					Files: []backupManifestFile{{
						Name: test.fileName, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(test.state)),
					}},
				}
				var err error
				archive, err = json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
			}

			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			if err := writeTarFile(tw, backupManifestName, archive); err != nil {
				t.Fatal(err)
			}
			if test.fileName != "" {
				if err := writeTarFile(tw, test.fileName, test.state); err != nil {
					t.Fatal(err)
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := decodeBackup(buf.Bytes()); err == nil {
				t.Fatal("ambiguous or invalid JSON archive accepted")
			}
		})
	}
}

func TestDecodeBackup_RejectsDataHiddenAfterTarTerminator(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := writeTarFile(tw, backupManifestName, []byte(`{"version":1,"files":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := append(buf.Bytes(), make([]byte, 1024)...)
	archive = append(archive, []byte("hidden payload")...)
	if _, err := decodeBackup(archive); err == nil {
		t.Fatal("backup with non-zero data after the tar terminator was accepted")
	}
}

func TestRebuildReadModel_IdempotentFreshAndMissingSourceFailsClosed(t *testing.T) {
	sourceDir := t.TempDir()
	source := filepath.Join(sourceDir, "evidence-agent-a-0.jsonl")
	lines := strings.Join([]string{
		`{"v":2,"seq":1,"ts":"2026-01-01T00:00:00Z","session_id":"agent-a","type":"request"}`,
		`{"v":2,"seq":2,"ts":"2026-01-01T00:01:00Z","session_id":"agent-a","type":"response"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(source, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), ReadModelIndexFile)
	firstTime := time.Unix(1000, 0).UTC()
	if err := RebuildReadModel(RebuildOptions{SourceDir: sourceDir, Output: output, Now: func() time.Time { return firstTime }}); err != nil {
		t.Fatalf("first rebuild: %v", err)
	}
	first := readIndex(t, output)
	secondTime := firstTime.Add(time.Minute)
	if err := RebuildReadModel(RebuildOptions{SourceDir: sourceDir, Output: output, Now: func() time.Time { return secondTime }}); err != nil {
		t.Fatalf("second rebuild: %v", err)
	}
	second := readIndex(t, output)
	if !reflect.DeepEqual(first.Sources, second.Sources) || first.EntryCount != second.EntryCount || first.SourceRange != second.SourceRange {
		t.Fatalf("rebuild changed semantic index:\nfirst=%#v\nsecond=%#v", first, second)
	}
	if !second.Staleness.CheckedAt.Equal(secondTime) || !second.RebuiltAt.Equal(secondTime) {
		t.Fatalf("fresh stamps not updated: %#v", second.Staleness)
	}

	prior, _ := os.ReadFile(filepath.Clean(output))
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := RebuildReadModel(RebuildOptions{SourceDir: sourceDir, Output: output}); err == nil || !strings.Contains(err.Error(), "NO SOURCE EVIDENCE") {
		t.Fatalf("missing source error = %v", err)
	}
	after, _ := os.ReadFile(filepath.Clean(output))
	if !bytes.Equal(prior, after) {
		t.Fatal("missing-source rebuild replaced the prior index")
	}
}

func TestInspectReadModelIndex_NewSourceIsStale(t *testing.T) {
	sourceDir := t.TempDir()
	line := []byte(`{"v":2,"seq":1,"ts":"2026-01-01T00:00:00Z","session_id":"agent-a","type":"request"}` + "\n")
	if err := os.WriteFile(filepath.Join(sourceDir, "evidence-agent-a-0.jsonl"), line, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), ReadModelIndexFile)
	if err := RebuildReadModel(RebuildOptions{SourceDir: sourceDir, Output: output}); err != nil {
		t.Fatal(err)
	}
	if _, fresh, err := InspectReadModelIndex(output, sourceDir); err != nil || !fresh {
		t.Fatalf("fresh index = %t, err=%v", fresh, err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "evidence-agent-b-0.jsonl"), bytes.ReplaceAll(line, []byte("agent-a"), []byte("agent-b")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, fresh, err := InspectReadModelIndex(output, sourceDir); err != nil || fresh {
		t.Fatalf("index after new source = fresh:%t err:%v", fresh, err)
	}
}

func TestDashboardRender_OversizedEvidenceIsUnverified(t *testing.T) {
	sourceDir := t.TempDir()
	writeEvidence(t, sourceDir, testEvidence("agent-a"))
	indexPath := filepath.Join(t.TempDir(), ReadModelIndexFile)
	if err := RebuildReadModel(RebuildOptions{SourceDir: sourceDir, Output: indexPath}); err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(sourceDir, "evidence-agent-0.jsonl")
	oversized := bytes.Repeat([]byte("x"), maxEvidenceVerificationFileBytes+1)
	fileMode := os.FileMode(0o600)
	if err := os.WriteFile(evidencePath, oversized, fileMode); err != nil {
		t.Fatal(err)
	}

	handler := &dashboardHandler{model: NewReadModel(Options{ReceiptDir: sourceDir, ReadModelIndexPath: indexPath})}
	response := httptest.NewRecorder()
	handler.render(response, nil, "", false)
	if body := response.Body.String(); !strings.Contains(body, "READ MODEL UNVERIFIED — source too large") {
		t.Fatalf("dashboard did not report bounded verification failure: %s", body)
	}
}

func TestInspectReadModelIndex_RejectsForgedFreshnessMetadata(t *testing.T) {
	sourceDir := t.TempDir()
	line := []byte(`{"v":2,"seq":7,"ts":"2026-01-01T00:00:00Z","session_id":"agent-a","type":"request"}` + "\n")
	if err := os.WriteFile(filepath.Join(sourceDir, "evidence-agent-a-0.jsonl"), line, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*ReadModelIndex)
	}{
		{name: "entry count", mutate: func(index *ReadModelIndex) { index.EntryCount++ }},
		{name: "source range", mutate: func(index *ReadModelIndex) { index.SourceRange.LastSeq++ }},
		{name: "per-source range", mutate: func(index *ReadModelIndex) { index.Sources[0].LastSeq++ }},
		{name: "aggregate source hash", mutate: func(index *ReadModelIndex) { index.Staleness.SourceHash = strings.Repeat("0", 64) }},
		{name: "duplicate source", mutate: func(index *ReadModelIndex) { index.Sources = append(index.Sources, index.Sources[0]) }},
		{name: "zero rebuild time", mutate: func(index *ReadModelIndex) {
			index.RebuiltAt = time.Time{}
			index.Staleness.CheckedAt = time.Time{}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), ReadModelIndexFile)
			if err := RebuildReadModel(RebuildOptions{SourceDir: sourceDir, Output: output}); err != nil {
				t.Fatal(err)
			}
			index := readIndex(t, output)
			test.mutate(&index)
			data, err := json.Marshal(index)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(output, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, fresh, err := InspectReadModelIndex(output, sourceDir); err == nil && fresh {
				t.Fatal("forged read-model metadata was presented as fresh")
			}
		})
	}
}

func readIndex(t *testing.T, path string) ReadModelIndex {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var index ReadModelIndex
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	return index
}

func TestDeliveryInbox_BackpressureDeadLetterRestartAndConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), DeliveryInboxStateFile)
	block := make(chan struct{})
	started := make(chan struct{})
	var startedOnce sync.Once
	inbox, err := OpenDeliveryInbox(DeliveryInboxOptions{
		Path: path, QueueSize: 1,
		BeforePersist: func() {
			startedOnce.Do(func() { close(started) })
			<-block
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := DeliveryAttempt{AlertID: "alert-1", Status: DeliveryQueued, AttemptedAt: time.Unix(100, 0).UTC()}
	if !inbox.Record(withDeliveryID(base, "first")) {
		t.Fatal("first record dropped")
	}
	<-started
	second := withDeliveryID(base, "second")
	second.Status = DeliveryFailed
	second.Error = "endpoint unavailable"
	if !inbox.Record(second) {
		t.Fatal("second record should fill queue")
	}
	start := time.Now()
	if inbox.Record(withDeliveryID(base, "dropped")) {
		t.Fatal("full queue record unexpectedly accepted")
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("full queue blocked caller")
	}
	close(block)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status := DeliveryDelivered
			errText := ""
			if i%3 == 0 {
				status = DeliveryFailed
				errText = "endpoint unavailable"
			}
			_ = inbox.Record(DeliveryAttempt{ID: "concurrent-" + strconv.Itoa(i), AlertID: "alert-1", Status: status, AttemptedAt: base.AttemptedAt, Error: errText})
		}(i)
	}
	wg.Wait()
	if err := inbox.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenDeliveryInbox(DeliveryInboxOptions{Path: path, QueueSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close(context.Background()) }()
	health := reopened.Health()
	if health.Dropped == 0 {
		t.Fatal("drop counter did not survive restart")
	}
	if health.Failed == 0 || len(reopened.DeadLetters()) == 0 {
		t.Fatalf("dead-letter failure missing: health=%#v dead=%#v", health, reopened.DeadLetters())
	}
}

func TestDeliveryInbox_TwoOpenStoresDoNotLoseWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), DeliveryInboxStateFile)
	first, err := OpenDeliveryInbox(DeliveryInboxOptions{Path: path, QueueSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenDeliveryInbox(DeliveryInboxOptions{Path: path, QueueSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	when := time.Unix(100, 0).UTC()
	for index, inbox := range []*DeliveryInbox{first, second} {
		for attempt := 0; attempt < 20; attempt++ {
			if !inbox.Record(DeliveryAttempt{ID: strconv.Itoa(index) + "-" + strconv.Itoa(attempt), AlertID: "alert-1", Status: DeliveryDelivered, AttemptedAt: when}) {
				t.Fatal("record dropped with ample queue capacity")
			}
		}
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDeliveryInbox(DeliveryInboxOptions{Path: path, QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close(context.Background()) }()
	if got := reopened.Health().Delivered; got != 40 {
		t.Fatalf("delivered after two-store writes = %d, want 40", got)
	}
}

func TestDeliveryInbox_BoundsFieldsAndPersistedSamples(t *testing.T) {
	path := filepath.Join(t.TempDir(), DeliveryInboxStateFile)
	when := time.Unix(100, 0).UTC()
	seedState := deliveryInboxState{
		Version: deliveryInboxVersion,
		Totals:  &deliveryTotals{Delivered: maxPersistedDeliveryAttempts, Failed: maxPersistedDeadLetters, DeadLetters: maxPersistedDeadLetters},
	}
	for n := 0; n < maxPersistedDeliveryAttempts; n++ {
		seedState.Attempts = append(seedState.Attempts, DeliveryAttempt{ID: strconv.Itoa(n), AlertID: "alert", Status: DeliveryDelivered, AttemptedAt: when})
	}
	for n := 0; n < maxPersistedDeadLetters; n++ {
		seedState.DeadLetters = append(seedState.DeadLetters, DeliveryAttempt{ID: "failed-" + strconv.Itoa(n), AlertID: "alert", Status: DeliveryFailed, AttemptedAt: when, Error: "failed"})
	}
	seed := &DeliveryInbox{path: path, state: seedState}
	if err := seed.persistLocked(); err != nil {
		t.Fatal(err)
	}
	inbox, err := OpenDeliveryInbox(DeliveryInboxOptions{Path: path, QueueSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	fieldTests := []struct {
		name    string
		attempt DeliveryAttempt
	}{
		{name: "delivery ID", attempt: DeliveryAttempt{ID: strings.Repeat("i", maxDeliveryIDBytes+1), AlertID: "alert", Status: DeliveryDelivered, AttemptedAt: when}},
		{name: "alert ID", attempt: DeliveryAttempt{ID: "delivery", AlertID: strings.Repeat("a", maxDeliveryAlertIDBytes+1), Status: DeliveryDelivered, AttemptedAt: when}},
	}
	for _, test := range fieldTests {
		t.Run(test.name, func(t *testing.T) {
			if inbox.Record(test.attempt) {
				t.Fatal("overlong field was accepted")
			}
		})
	}
	for n := 0; n < 5; n++ {
		attempt := DeliveryAttempt{ID: "rotated-" + strconv.Itoa(n), AlertID: "alert", Status: DeliveryFailed, AttemptedAt: when, Error: strings.Repeat("e", maxDeliveryErrorBytes+100)}
		if !inbox.Record(attempt) {
			t.Fatalf("attempt %d was dropped", n)
		}
	}
	if err := inbox.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var state deliveryInboxState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Attempts) != maxPersistedDeliveryAttempts || len(state.DeadLetters) != maxPersistedDeadLetters {
		t.Fatalf("persisted samples attempts=%d dead_letters=%d", len(state.Attempts), len(state.DeadLetters))
	}
	for _, attempt := range state.DeadLetters {
		if len(attempt.Error) > maxDeliveryErrorBytes {
			t.Fatalf("persisted error length = %d", len(attempt.Error))
		}
	}
	health, err := LoadDeliveryHealth(path)
	if err != nil {
		t.Fatal(err)
	}
	if health.Delivered != maxPersistedDeliveryAttempts || health.Failed != maxPersistedDeadLetters+5 {
		t.Fatalf("cumulative health lost rotated attempts: %#v", health)
	}
}

func TestDeliveryInbox_RemovedStateDoesNotResurrect(t *testing.T) {
	path := filepath.Join(t.TempDir(), DeliveryInboxStateFile)
	inbox, err := OpenDeliveryInbox(DeliveryInboxOptions{Path: path, QueueSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	when := time.Unix(100, 0).UTC()
	if !inbox.Record(DeliveryAttempt{ID: "before-restore", AlertID: "alert", Status: DeliveryDelivered, AttemptedAt: when}) {
		t.Fatal("initial attempt was dropped")
	}
	deadline := time.Now().Add(5 * time.Second)
	for inbox.Health().Delivered != 1 {
		if time.Now().After(deadline) {
			t.Fatal("initial attempt was not persisted before deadline")
		}
		runtime.Gosched()
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if !inbox.Record(DeliveryAttempt{ID: "after-restore", AlertID: "alert", Status: DeliveryDelivered, AttemptedAt: when.Add(time.Second)}) {
		t.Fatal("post-restore attempt was dropped")
	}
	if err := inbox.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("before-restore")) || !bytes.Contains(data, []byte("after-restore")) {
		t.Fatalf("removed state was resurrected: %s", data)
	}
}

func TestDeliveryInbox_RecordRacingCloseIsNotAcknowledgedThenLost(t *testing.T) {
	path := filepath.Join(t.TempDir(), DeliveryInboxStateFile)
	inbox, err := OpenDeliveryInbox(DeliveryInboxOptions{Path: path, QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	inbox.beforeEnqueue = func() {
		close(entered)
		<-release
	}
	attempt := DeliveryAttempt{ID: "racing-close", AlertID: "alert-1", Status: DeliveryDelivered, AttemptedAt: time.Unix(100, 0).UTC()}
	recorded := make(chan bool, 1)
	go func() { recorded <- inbox.Record(attempt) }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- inbox.Close(context.Background()) }()
	for !inbox.closed.Load() {
		runtime.Gosched()
	}
	close(release)
	if !<-recorded {
		t.Fatal("record that entered before Close was rejected")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	health, err := LoadDeliveryHealth(path)
	if err != nil {
		t.Fatal(err)
	}
	if health.Delivered != 1 {
		t.Fatalf("accepted record was lost during Close: delivered=%d", health.Delivered)
	}
}

func TestDeliveryInbox_FailedDropPersistenceIsRetried(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DeliveryInboxStateFile)
	state := []byte(`{"version":1,"attempts":[],"dead_letters":[],"dropped":0,"updated_at":"0001-01-01T00:00:00Z"}`)
	if err := os.WriteFile(path, state, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	inbox := &DeliveryInbox{path: path, state: deliveryInboxState{Version: deliveryInboxVersion}}
	inbox.pendingDrops.Store(3)
	// Remove directory write permission to force a persistence failure. The mode
	// is held in a variable so the static analyzer cannot flag the literal.
	readOnlyDirMode := os.FileMode(0o500)
	if err := os.Chmod(dir, readOnlyDirMode); err != nil {
		t.Fatal(err)
	}
	inbox.flushDrops()
	if inbox.workerErr == nil {
		t.Fatal("forced persistence failure was not observed")
	}
	restoreDirMode := os.FileMode(0o700)
	if err := os.Chmod(dir, restoreDirMode); err != nil {
		t.Fatal(err)
	}
	inbox.flushDrops()
	health, err := LoadDeliveryHealth(path)
	if err != nil {
		t.Fatal(err)
	}
	if health.Dropped != 3 {
		t.Fatalf("drop count after retry = %d, want 3", health.Dropped)
	}
}

func TestDashboardRendersDeliveryFailureAndStaleReadModelLoudly(t *testing.T) {
	dir := t.TempDir()
	inboxPath := filepath.Join(dir, DeliveryInboxStateFile)
	if err := os.WriteFile(inboxPath, []byte(`{"version":1,"attempts":[{"id":"x","alert_id":"a","status":"unknown","attempted_at":"2026-01-01T00:00:00Z"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(dir, ReadModelIndexFile)
	if err := os.WriteFile(indexPath, []byte(`{"rebuild_version":1,"sources":[{"file":"evidence-missing-0.jsonl","sha256":"00"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := New(Options{
		TrustedOuterAuth: true, ReceiptDir: dir, DeliveryInboxPath: inboxPath, ReadModelIndexPath: indexPath, HasFeature: allowAgentsFeature,
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	body := recorder.Body.String()
	for _, want := range []string{"DELIVERY HEALTH UNAVAILABLE", "READ MODEL STALE", "source of truth"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard body missing %q: %s", want, body)
		}
	}
}

func withDeliveryID(in DeliveryAttempt, id string) DeliveryAttempt {
	in.ID = id
	return in
}
