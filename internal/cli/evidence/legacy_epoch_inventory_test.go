// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	legacyreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestVerifyLegacyInventoryRoundTripAndSourceDrift(t *testing.T) {
	dir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := receiptForCompactV1(t, privateKey, 0, legacyreceipt.GenesisHash, "legacy-inventory-valid")
	entry := legacyInventoryTestEntry(t, 0, recorder.GenesisHash, "action_receipt", signed)
	source := filepath.Join(dir, "evidence-proxy-0.jsonl")
	sourceBytes := legacyInventoryTestLine(t, entry)
	if err := os.WriteFile(source, sourceBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := buildLegacyInventory(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Epochs[0].Assurance; got != "receipts_strictly_verified" {
		t.Fatalf("assurance = %q, want receipts_strictly_verified", got)
	}
	data, err := marshalLegacyInventory(doc)
	if err != nil {
		t.Fatal(err)
	}
	inventory := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(inventory, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	opts := verifyLegacyInventoryOptions{receiptDir: dir, sessionID: "proxy", inventoryFile: inventory, inventorySHA256: hex.EncodeToString(digest[:])}
	cmd := &cobra.Command{}
	cmd.SetOut(new(bytes.Buffer))
	if err := runVerifyLegacyEpochInventory(cmd, opts); err != nil {
		t.Fatalf("verify unchanged inventory: %v", err)
	}
	originalLock := compactAcquireLock
	compactAcquireLock = func(string) (*recorder.EvidenceCeremonyLock, error) { return nil, errors.New("injected verify lock") }
	err = runVerifyLegacyEpochInventory(cmd, opts)
	compactAcquireLock = originalLock
	if err == nil || !strings.Contains(err.Error(), "injected verify lock") {
		t.Fatalf("verify lock error = %v", err)
	}
	originalMarshal := legacyInventoryMarshal
	legacyInventoryMarshal = func(legacyInventoryDocument) ([]byte, error) { return nil, errors.New("injected verify marshal") }
	err = runVerifyLegacyEpochInventory(cmd, opts)
	legacyInventoryMarshal = originalMarshal
	if err == nil || !strings.Contains(err.Error(), "injected verify marshal") {
		t.Fatalf("verify marshal error = %v", err)
	}
	drift := legacyInventoryTestEntry(t, 0, recorder.GenesisHash, "capture", map[string]string{"drift": "recorded"})
	if err := os.WriteFile(source, append(sourceBytes, legacyInventoryTestLine(t, drift)...), 0o600); err != nil {
		t.Fatal(err)
	}
	err = runVerifyLegacyEpochInventory(cmd, opts)
	if err == nil || !strings.Contains(err.Error(), "differs from full recomputation") {
		t.Fatalf("verify drifted source error = %v, want exact-recomputation refusal", err)
	}
	if err := os.WriteFile(source, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = runVerifyLegacyEpochInventory(cmd, opts)
	if err == nil || !strings.Contains(err.Error(), "parse source shard") {
		t.Fatalf("verify malformed source error = %v", err)
	}
}

func TestRunInventoryLegacyEpochsPublishesCanonicalOutput(t *testing.T) {
	dir := t.TempDir()
	entry := legacyInventoryTestEntry(t, 0, recorder.GenesisHash, "capture", map[string]string{"safe": "value"})
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), legacyInventoryTestLine(t, entry), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "inventory.json")
	cmd := &cobra.Command{}
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	if err := runInventoryLegacyEpochs(cmd, legacyInventoryOptions{receiptDir: dir, sessionID: "proxy", outFile: out}); err != nil {
		t.Fatalf("runInventoryLegacyEpochs: %v", err)
	}
	// #nosec G304 -- out is a test-owned path below t.TempDir.
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if !strings.Contains(stdout.String(), hex.EncodeToString(digest[:])) {
		t.Fatalf("stdout = %q, want published digest", stdout.String())
	}
	if err := runInventoryLegacyEpochs(cmd, legacyInventoryOptions{receiptDir: dir, sessionID: "proxy", outFile: out}); err == nil || !strings.Contains(err.Error(), "create --out") {
		t.Fatalf("second publication error = %v, want exclusive-create refusal", err)
	}
	if err := runInventoryLegacyEpochs(cmd, legacyInventoryOptions{receiptDir: dir, sessionID: "", outFile: filepath.Join(t.TempDir(), "bad.json")}); err == nil || !strings.Contains(err.Error(), "--session") {
		t.Fatalf("missing session error = %v", err)
	}
	if err := runInventoryLegacyEpochs(cmd, legacyInventoryOptions{receiptDir: dir, sessionID: "proxy", outFile: filepath.Join(dir, "inside.json")}); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("inside output error = %v", err)
	}
}

func TestRunInventoryLegacyEpochsFailsClosedAtPublicationBoundaries(t *testing.T) {
	dir := t.TempDir()
	entry := legacyInventoryTestEntry(t, 0, recorder.GenesisHash, "capture", map[string]string{"safe": "value"})
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), legacyInventoryTestLine(t, entry), 0o600); err != nil {
		t.Fatal(err)
	}
	originalWrite := legacyInventoryWrite
	originalFileSync := legacyInventoryFileSync
	originalMarshal := legacyInventoryMarshal
	originalParentMatches := legacyInventoryParentMatches
	originalDirectorySync := inspectSyncDirectory
	originalLock := compactAcquireLock
	restore := func() {
		legacyInventoryWrite = originalWrite
		legacyInventoryFileSync = originalFileSync
		legacyInventoryMarshal = originalMarshal
		legacyInventoryParentMatches = originalParentMatches
		inspectSyncDirectory = originalDirectorySync
		compactAcquireLock = originalLock
	}
	t.Cleanup(restore)
	tests := []struct {
		name, want string
		inject     func()
	}{
		{name: "write", want: "write --out", inject: func() {
			legacyInventoryWrite = func(*os.File, []byte) (int, error) { return 0, errors.New("injected write") }
		}},
		{name: "file sync", want: "sync --out", inject: func() { legacyInventoryFileSync = func(*os.File) error { return errors.New("injected file sync") } }},
		{name: "directory sync", want: "sync --out parent", inject: func() {
			inspectSyncDirectory = func(*inspectOutput) error { return errors.New("injected directory sync") }
		}},
		{name: "parent identity error", want: "verify --out parent identity", inject: func() {
			legacyInventoryParentMatches = func(*inspectOutput, string) (bool, error) { return false, errors.New("injected identity") }
		}},
		{name: "parent changed", want: "parent changed", inject: func() {
			legacyInventoryParentMatches = func(*inspectOutput, string) (bool, error) { return false, nil }
		}},
		{name: "marshal", want: "injected marshal", inject: func() {
			legacyInventoryMarshal = func(legacyInventoryDocument) ([]byte, error) { return nil, errors.New("injected marshal") }
		}},
		{name: "lock", want: "lock stopped", inject: func() {
			compactAcquireLock = func(string) (*recorder.EvidenceCeremonyLock, error) { return nil, errors.New("injected lock") }
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			restore()
			tc.inject()
			cmd := &cobra.Command{}
			cmd.SetOut(new(bytes.Buffer))
			err := runInventoryLegacyEpochs(cmd, legacyInventoryOptions{receiptDir: dir, sessionID: "proxy", outFile: filepath.Join(t.TempDir(), "inventory.json")})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyLegacyInventoryRejectsMalformedPinsBeforeEnumeration(t *testing.T) {
	dir := t.TempDir()
	cmd := &cobra.Command{}
	cmd.SetOut(new(bytes.Buffer))
	missingRoot := filepath.Join(t.TempDir(), "missing-root")
	err := runVerifyLegacyEpochInventory(cmd, verifyLegacyInventoryOptions{receiptDir: missingRoot, sessionID: "proxy", inventoryFile: "unused", inventorySHA256: strings.Repeat("0", 64)})
	if err == nil {
		t.Fatal("missing evidence root accepted")
	}
	write := func(t *testing.T, data []byte) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "inventory.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tests := []struct {
		name, digest, want string
		data               []byte
		missing            bool
	}{
		{name: "short digest", digest: "aa", data: []byte("{}\n"), want: "64-character"},
		{name: "non-hex digest", digest: strings.Repeat("z", 64), data: []byte("{}\n"), want: "hexadecimal"},
		{name: "digest mismatch", digest: strings.Repeat("0", 64), data: []byte("{}\n"), want: "does not match"},
		{name: "duplicate keys", data: []byte(`{"version":1,"version":1}` + "\n"), want: "duplicate"},
		{name: "invalid json", data: []byte("{\n"), want: "decode --inventory"},
		{name: "unknown field", data: []byte(`{"version":1,"kind":"pipelock-legacy-epoch-inventory","session_id":"proxy","unknown":true}` + "\n"), want: "decode --inventory"},
		{name: "trailing json", data: []byte(`{"version":1,"kind":"pipelock-legacy-epoch-inventory","session_id":"proxy"} {}` + "\n"), want: "trailing"},
		{name: "wrong identity", data: []byte(`{"version":2,"kind":"wrong","session_id":"proxy"}` + "\n"), want: "identity"},
		{name: "oversized inventory", data: bytes.Repeat([]byte{' '}, int(recorder.MaxEvidenceReadFileBytes)+1), want: "exceeds"},
		{name: "missing file", digest: strings.Repeat("0", 64), want: "read --inventory", missing: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "missing.json")
			if !tc.missing {
				path = write(t, tc.data)
			}
			digest := tc.digest
			if digest == "" {
				sum := sha256.Sum256(tc.data)
				digest = hex.EncodeToString(sum[:])
			}
			err := runVerifyLegacyEpochInventory(cmd, verifyLegacyInventoryOptions{receiptDir: dir, sessionID: "proxy", inventoryFile: path, inventorySHA256: digest})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAddLegacyInventoryEntryClassifiesBranches(t *testing.T) {
	epoch := legacyInventoryEpoch{Assurance: "receipts_strictly_verified", CheckpointStatus: "none", SignerRuns: []legacySignerRun{}, SourceMappings: []legacySourceMapping{}, Anomalies: []legacyInventoryAnomaly{}}
	seen := make(map[string]struct{})
	first := legacyInventoryTestEntry(t, 2, "wrong-genesis", "capture", map[string]string{"safe": "value"})
	first.Hash = "wrong-hash"
	if err := addLegacyInventoryEntry(&epoch, "a.jsonl", 0, 10, first, seen); err != nil {
		t.Fatal(err)
	}
	second := legacyInventoryTestEntry(t, 1, "wrong-prev", "capture", map[string]string{"safe": "value"})
	if err := addLegacyInventoryEntry(&epoch, "b.jsonl", 0, 11, second, seen); err != nil {
		t.Fatal(err)
	}
	signedCheckpoint := legacyInventoryTestEntry(t, 2, second.Hash, "checkpoint", recorder.CheckpointDetail{Signature: "observed"})
	if err := addLegacyInventoryEntry(&epoch, "b.jsonl", 11, 12, signedCheckpoint, seen); err != nil {
		t.Fatal(err)
	}
	endorsement := legacyInventoryTestEntry(t, 3, signedCheckpoint.Hash, "rotation_endorsement", map[string]string{"observed": "only"})
	if err := addLegacyInventoryEntry(&epoch, "b.jsonl", 23, 13, endorsement, seen); err != nil {
		t.Fatal(err)
	}
	unknown := legacyInventoryTestEntry(t, 4, endorsement.Hash, "future_type", map[string]string{"observed": "only"})
	if err := addLegacyInventoryEntry(&epoch, "b.jsonl", 36, 14, unknown, seen); err != nil {
		t.Fatal(err)
	}
	if epoch.RotationEndorsements != 1 || epoch.CheckpointStatus != "signed_observed" || epoch.outerIntegrityFailures == 0 {
		t.Fatalf("classification = %#v", epoch)
	}
	finalizeLegacyEpoch(&epoch)
	if epoch.Assurance != "broken" {
		t.Fatalf("assurance = %q, want broken", epoch.Assurance)
	}
	outerOnly := legacyInventoryEpoch{}
	finalizeLegacyEpoch(&outerOnly)
	if outerOnly.Assurance != "outer_verified" {
		t.Fatalf("outer-only assurance = %q", outerOnly.Assurance)
	}
}

func TestLegacyInventoryBoundsFailClosed(t *testing.T) {
	t.Run("anomalies", func(t *testing.T) {
		epoch := legacyInventoryEpoch{Anomalies: make([]legacyInventoryAnomaly, maxLegacyInventoryAnomalies)}
		err := addLegacyAnomaly(&epoch, "sequence_gap", "a.jsonl", 0, 1, false)
		if err == nil || !strings.Contains(err.Error(), "anomalies") {
			t.Fatalf("error = %v, want anomalies bound", err)
		}
	})

	t.Run("signer runs", func(t *testing.T) {
		epoch := legacyInventoryEpoch{SignerRuns: make([]legacySignerRun, maxLegacyInventoryRuns)}
		entry := legacyInventoryTestEntry(t, 0, recorder.GenesisHash, "action_receipt", json.RawMessage(`{"signer_key":"`+strings.Repeat("c", 64)+`"}`))
		err := addLegacyReceipt(&epoch, "a.jsonl", 0, entry, make(map[string]struct{}))
		if err == nil || !strings.Contains(err.Error(), "signer runs") {
			t.Fatalf("error = %v, want signer-runs bound", err)
		}
	})

	t.Run("epochs", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "evidence-proxy-0.jsonl")
		entry := legacyInventoryTestEntry(t, 0, recorder.GenesisHash, "capture", map[string]string{"safe": "value"})
		line := legacyInventoryTestLine(t, entry)
		wire := bytes.Repeat(line, maxLegacyInventoryEpochs+1)
		if err := os.WriteFile(path, wire, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := buildLegacyInventory(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "epochs") {
			t.Fatalf("error = %v, want epochs bound", err)
		}
	})
}

func TestBuildLegacyInventoryRecordsSignerReentryAndEpochs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence-proxy-0.jsonl")
	var wire []byte
	prev := recorder.GenesisHash
	for seq, key := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("a", 64)} {
		detail := json.RawMessage(`{"signer_key":"` + key + `"}`)
		entry := legacyInventoryTestEntry(t, uint64(seq), prev, "action_receipt", detail)
		prev = entry.Hash
		wire = append(wire, legacyInventoryTestLine(t, entry)...)
	}
	checkpoint := legacyInventoryTestEntry(t, 0, recorder.GenesisHash, "checkpoint", recorder.CheckpointDetail{})
	wire = append(wire, legacyInventoryTestLine(t, checkpoint)...)
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}

	doc, err := buildLegacyInventory(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
	if err != nil {
		t.Fatalf("buildLegacyInventory: %v", err)
	}
	if len(doc.Epochs) != 2 {
		t.Fatalf("epochs = %d, want 2", len(doc.Epochs))
	}
	first := doc.Epochs[0]
	if len(first.SignerRuns) != 3 || signerRunKey(first.SignerRuns[0]) != signerRunKey(first.SignerRuns[2]) {
		t.Fatalf("signer runs = %#v, want A-B-A", first.SignerRuns)
	}
	if !legacyInventoryHasAnomaly(first, "signer_key_reentry") || first.Assurance != "observed_only" {
		t.Fatalf("first epoch assurance/anomalies = %q %#v", first.Assurance, first.Anomalies)
	}
	second := doc.Epochs[1]
	if second.CheckpointStatus != "unsigned_observed" || !legacyInventoryHasAnomaly(second, "unsigned_checkpoint") {
		t.Fatalf("checkpoint = %q %#v", second.CheckpointStatus, second.Anomalies)
	}
	if len(first.SourceMappings) != 1 || first.SourceMappings[0].Bytes >= int64(len(wire)) {
		t.Fatalf("first epoch mapping does not bind only its byte range: %#v", first.SourceMappings)
	}
	if len(first.SourceFiles) != 1 || first.SourceFiles[0].SHA256 != doc.SourceFiles[0].SHA256 {
		t.Fatalf("epoch source file digest missing: %#v", first.SourceFiles)
	}
}

func TestVerifyLegacyInventoryRejectsHandTruncatedRun(t *testing.T) {
	dir := t.TempDir()
	keyA, keyB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	first := legacyInventoryTestEntry(t, 0, recorder.GenesisHash, "action_receipt", json.RawMessage(`{"signer_key":"`+keyA+`"}`))
	second := legacyInventoryTestEntry(t, 1, first.Hash, "action_receipt", json.RawMessage(`{"signer_key":"`+keyB+`"}`))
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), append(legacyInventoryTestLine(t, first), legacyInventoryTestLine(t, second)...), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := buildLegacyInventory(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	doc.Epochs[0].SignerRuns = doc.Epochs[0].SignerRuns[:1]
	data, err := marshalLegacyInventory(doc)
	if err != nil {
		t.Fatal(err)
	}
	inventory := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(inventory, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	cmd := &cobra.Command{}
	cmd.SetOut(new(bytes.Buffer))
	err = runVerifyLegacyEpochInventory(cmd, verifyLegacyInventoryOptions{receiptDir: dir, sessionID: "proxy", inventoryFile: inventory, inventorySHA256: hex.EncodeToString(digest[:])})
	if err == nil || !strings.Contains(err.Error(), "differs from full recomputation") {
		t.Fatalf("runVerifyLegacyEpochInventory error = %v, want exact-recomputation refusal", err)
	}
}

func TestBuildLegacyInventoryRejectsUnterminatedShard(t *testing.T) {
	dir := t.TempDir()
	entry := legacyInventoryTestEntry(t, 0, recorder.GenesisHash, "capture", map[string]string{"safe": "value"})
	line := legacyInventoryTestLine(t, entry)
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), bytes.TrimSuffix(line, []byte{'\n'}), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := buildLegacyInventory(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
	if err == nil || !strings.Contains(err.Error(), "does not end in newline") {
		t.Fatalf("buildLegacyInventory error = %v, want unterminated-shard refusal", err)
	}
	cmd := &cobra.Command{}
	cmd.SetOut(new(bytes.Buffer))
	err = runInventoryLegacyEpochs(cmd, legacyInventoryOptions{receiptDir: dir, sessionID: "proxy", outFile: filepath.Join(t.TempDir(), "inventory.json")})
	if err == nil || !strings.Contains(err.Error(), "does not end in newline") {
		t.Fatalf("runInventoryLegacyEpochs error = %v, want unterminated-shard refusal", err)
	}
}

func TestLegacyInventoryPathValidationBranches(t *testing.T) {
	if _, err := resolveLegacyInventoryLocation(filepath.Join(t.TempDir(), "missing"), "", "proxy"); err == nil {
		t.Fatal("missing evidence root accepted")
	}
	dir := t.TempDir()
	if _, err := resolveLegacyInventoryLocation(dir, "../escape", "proxy"); err == nil {
		t.Fatal("escaping location accepted")
	}
	if _, _, err := resolveLegacyInventoryOutput("", dir); err == nil || !strings.Contains(err.Error(), "--out") {
		t.Fatalf("empty output error = %v", err)
	}
	if _, _, err := resolveLegacyInventoryOutput(filepath.Join(t.TempDir(), "missing-parent", "inventory.json"), dir); err == nil || !strings.Contains(err.Error(), "parent") {
		t.Fatalf("missing parent error = %v", err)
	}
	if _, err := buildLegacyInventory(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy"); err == nil || !strings.Contains(err.Error(), "no evidence shards") {
		t.Fatalf("empty source error = %v", err)
	}
	overlong := append(bytes.Repeat([]byte{'x'}, recorder.MaxEntryLineBytes+1), '\n')
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), overlong, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildLegacyInventory(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("overlong source error = %v", err)
	}
}

func legacyInventoryTestEntry(t *testing.T, seq uint64, prev, entryType string, detail any) recorder.Entry {
	t.Helper()
	rawDetail, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	entry := recorder.Entry{Version: 1, Sequence: seq, Timestamp: time.Unix(1, 0).UTC(), SessionID: "proxy", Type: entryType, Transport: "test", Summary: "inventory fixture", Detail: detail, RawDetail: rawDetail, PrevHash: prev}
	entry.Hash = recorder.ComputeHash(entry)
	if entry.Hash == "" {
		t.Fatal("empty recorder hash")
	}
	return entry
}

func legacyInventoryTestLine(t *testing.T, entry recorder.Entry) []byte {
	t.Helper()
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func legacyInventoryHasAnomaly(epoch legacyInventoryEpoch, kind string) bool {
	for _, anomaly := range epoch.Anomalies {
		if anomaly.Kind == kind {
			return true
		}
	}
	return false
}
