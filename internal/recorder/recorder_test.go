// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	testSessionID  = "test-session"
	testTransport  = "fetch"
	testType       = "request"
	testCheckpoint = "checkpoint"
)

func TestRecorder_HashChain(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             false,
		CheckpointInterval: 100,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	// Record 3 entries
	for i := range 3 {
		err := rec.Record(recorder.Entry{
			SessionID: testSessionID,
			Type:      testType,
			Transport: testTransport,
			Summary:   fmt.Sprintf("request %d", i),
		})
		if err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read back and verify chain
	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-test-session-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	// 3 entries + 1 final checkpoint
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 entries, got %d", len(entries))
	}

	if entries[0].PrevHash != recorder.GenesisHash {
		t.Errorf("first entry PrevHash = %q, want %q", entries[0].PrevHash, recorder.GenesisHash)
	}
	if entries[0].Hash != entries[1].PrevHash {
		t.Error("chain break between entries 0 and 1")
	}
	if entries[1].Hash != entries[2].PrevHash {
		t.Error("chain break between entries 1 and 2")
	}

	// Verify all hashes are correct
	for _, e := range entries {
		computed := recorder.ComputeHash(e)
		if e.Hash != computed {
			t.Errorf("hash mismatch at seq %d: got %s, computed %s", e.Sequence, e.Hash, computed)
		}
	}

	// Full chain verification
	if err := recorder.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestRecorder_Redaction(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)
	defer sc.Close()

	recCfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             true,
		CheckpointInterval: 100,
	}
	rec, err := recorder.New(recCfg, sc.ScanTextForDLP, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	// Record entry with a fake AWS key in detail
	// Build fake cred at runtime to avoid gosec G101
	fakeKey := "AK" + "IA" + "IOSFODNN7EXAMPLE"
	err = rec.Record(recorder.Entry{
		SessionID: testSessionID,
		Type:      testType,
		Transport: testTransport,
		Summary:   "request with secret",
		Detail:    map[string]string{"url": "https://example.com/?key=" + fakeKey},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-test-session-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	// At least the data entry (plus possibly a checkpoint)
	if len(entries) < 1 {
		t.Fatal("expected at least 1 entry")
	}

	detailJSON, _ := json.Marshal(entries[0].Detail)
	detailStr := string(detailJSON)
	if strings.Contains(detailStr, fakeKey) {
		t.Error("secret should be redacted from detail")
	}
	if !strings.Contains(detailStr, "[REDACTED:") {
		t.Error("detail should contain redaction marker")
	}
	if !strings.Contains(detailStr, `"redacted":true`) {
		t.Error("detail should be wrapped in redaction envelope")
	}
}

func TestRecorder_RedactionDisabled(t *testing.T) {
	dir := t.TempDir()
	recCfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             false,
		CheckpointInterval: 100,
	}
	rec, err := recorder.New(recCfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	secret := "my-secret-value-12345"
	err = rec.Record(recorder.Entry{
		SessionID: testSessionID,
		Type:      testType,
		Transport: testTransport,
		Summary:   "no redaction",
		Detail:    map[string]string{"data": secret},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-test-session-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(entries) < 1 {
		t.Fatal("expected at least 1 entry")
	}
	detailJSON, _ := json.Marshal(entries[0].Detail)
	if !strings.Contains(string(detailJSON), secret) {
		t.Error("with redaction disabled, secret should be preserved")
	}
}

func TestRecorder_SignedCheckpoint(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             false,
		CheckpointInterval: 3,
		SignCheckpoints:    true,
	}
	rec, err := recorder.New(cfg, nil, priv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Record 3 entries to trigger checkpoint
	for i := range 3 {
		if err := rec.Record(recorder.Entry{
			SessionID: "s1",
			Type:      testType,
			Transport: testTransport,
			Summary:   fmt.Sprintf("r%d", i),
		}); err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-s1-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}

	// Find checkpoint entries
	var foundCheckpoint bool
	for _, e := range entries {
		if e.Type != testCheckpoint {
			continue
		}
		foundCheckpoint = true

		// Unmarshal the checkpoint detail
		detailJSON, err := json.Marshal(e.Detail)
		if err != nil {
			t.Fatalf("marshal detail: %v", err)
		}
		var cpDetail recorder.CheckpointDetail
		if err := json.Unmarshal(detailJSON, &cpDetail); err != nil {
			t.Fatalf("unmarshal checkpoint detail: %v", err)
		}
		if cpDetail.Signature == "" {
			t.Error("checkpoint should have a signature")
			continue
		}

		sig, err := hex.DecodeString(cpDetail.Signature)
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}

		// The signature is over the PrevHash of the checkpoint entry
		// (which represents the chain state just before the checkpoint)
		if !ed25519.Verify(pub, []byte(e.PrevHash), sig) {
			t.Error("checkpoint signature verification failed")
		}
	}
	if !foundCheckpoint {
		t.Error("no checkpoint entry found")
	}
}

func TestRecorder_UnsignedCheckpoint(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             false,
		CheckpointInterval: 2,
		SignCheckpoints:    false,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := range 2 {
		if err := rec.Record(recorder.Entry{
			SessionID: "s1",
			Type:      testType,
			Summary:   fmt.Sprintf("r%d", i),
		}); err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-s1-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}

	for _, e := range entries {
		if e.Type != testCheckpoint {
			continue
		}
		detailJSON, _ := json.Marshal(e.Detail)
		var cpDetail recorder.CheckpointDetail
		if err := json.Unmarshal(detailJSON, &cpDetail); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if cpDetail.Signature != "" {
			t.Error("unsigned checkpoint should have empty signature")
		}
	}
}

func TestRecorder_Retention(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             false,
		CheckpointInterval: 100,
		RetentionDays:      1,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Create an old evidence file
	oldFile := filepath.Join(dir, "evidence-old-session-0.jsonl")
	if err := os.WriteFile(oldFile, []byte(`{"v":1}`+"\n"), filePermissions); err != nil {
		t.Fatal(err)
	}
	// Set modification time to 2 days ago
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(oldFile, old, old); err != nil {
		t.Fatal(err)
	}

	// Create a recent evidence file
	recentFile := filepath.Join(dir, "evidence-recent-session-0.jsonl")
	if err := os.WriteFile(recentFile, []byte(`{"v":1}`+"\n"), filePermissions); err != nil {
		t.Fatal(err)
	}

	removed, err := rec.ExpireOldFiles()
	if err != nil {
		t.Fatalf("ExpireOldFiles: %v", err)
	}
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}

	// Verify old file is gone, recent file remains
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Error("old file should be removed")
	}
	if _, err := os.Stat(recentFile); err != nil {
		t.Error("recent file should still exist")
	}

	_ = rec.Close()
}

func TestRecorder_RetentionDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 100,
		RetentionDays:      0,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	removed, err := rec.ExpireOldFiles()
	if err != nil {
		t.Fatalf("ExpireOldFiles: %v", err)
	}
	if removed != 0 {
		t.Errorf("expected 0 removed with retention disabled, got %d", removed)
	}
}

func TestRecorder_FileRotation(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             false,
		CheckpointInterval: 100,
		MaxEntriesPerFile:  3,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Write enough entries to force rotation
	for i := range 5 {
		if err := rec.Record(recorder.Entry{
			SessionID: "s1",
			Type:      testType,
			Transport: testTransport,
			Summary:   fmt.Sprintf("entry %d", i),
		}); err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Should have multiple JSONL files
	dirEntries, _ := os.ReadDir(dir)
	jsonlCount := 0
	for _, de := range dirEntries {
		if strings.HasSuffix(de.Name(), ".jsonl") {
			jsonlCount++
		}
	}
	if jsonlCount < 2 {
		t.Errorf("expected at least 2 JSONL files after rotation, got %d", jsonlCount)
	}
}

func TestRecorder_RawEscrow(t *testing.T) {
	dir := t.TempDir()

	// Generate X25519 key pair
	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             true,
		CheckpointInterval: 100,
		RawEscrow:          true,
		EscrowPublicKey:    hex.EncodeToString(recipientPub[:]),
	}

	// Use a mock redact function that always redacts
	redactFn := func(_ context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{
			Clean: false,
			Matches: []scanner.TextDLPMatch{
				{PatternName: "AWS Access Key"},
			},
		}
	}

	rec, err := recorder.New(cfg, redactFn, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	secret := "my-secret-data"
	err = rec.Record(recorder.Entry{
		SessionID: testSessionID,
		Type:      testType,
		Transport: testTransport,
		Summary:   "escrow test",
		Detail:    map[string]string{"secret": secret},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify escrow file exists
	dirEntries, _ := os.ReadDir(dir)
	var escrowFile string
	for _, de := range dirEntries {
		if strings.HasSuffix(de.Name(), ".raw.enc") {
			escrowFile = filepath.Join(dir, de.Name())
			break
		}
	}
	if escrowFile == "" {
		t.Fatal("no escrow file found")
	}

	// Verify entry has RawRef
	var jsonlFile string
	for _, de := range dirEntries {
		if strings.HasSuffix(de.Name(), ".jsonl") {
			jsonlFile = filepath.Join(dir, de.Name())
			break
		}
	}
	entries, err := recorder.ReadEntries(jsonlFile)
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(entries) < 1 {
		t.Fatal("expected at least 1 entry")
	}
	if entries[0].RawRef == "" {
		t.Error("entry should have RawRef pointing to escrow file")
	}

	// Decrypt the escrow file
	payload, err := os.ReadFile(filepath.Clean(escrowFile))
	if err != nil {
		t.Fatalf("reading escrow: %v", err)
	}

	const keySize = 32
	const nonceSize = 24
	if len(payload) < keySize+nonceSize+box.Overhead {
		t.Fatal("escrow payload too short")
	}

	var ephPub [keySize]byte
	copy(ephPub[:], payload[:keySize])
	rest := payload[keySize:]

	var nonce [nonceSize]byte
	copy(nonce[:], rest[:nonceSize])

	decrypted, ok := box.Open(nil, rest[nonceSize:], &nonce, &ephPub, recipientPriv)
	if !ok {
		t.Fatal("failed to decrypt escrow")
	}

	if !strings.Contains(string(decrypted), secret) {
		t.Error("decrypted escrow should contain original secret")
	}
}

func TestRecorder_RawEscrowInvalidKey(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:         true,
		Dir:             dir,
		RawEscrow:       true,
		EscrowPublicKey: "not-hex",
	}

	_, err := recorder.New(cfg, nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid escrow key")
	}
}

func TestRecorder_RawEscrowWrongKeyLength(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:         true,
		Dir:             dir,
		RawEscrow:       true,
		EscrowPublicKey: hex.EncodeToString([]byte("too-short")),
	}

	_, err := recorder.New(cfg, nil, nil)
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
}

func TestRecorder_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 100,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("second Close should be idempotent: %v", err)
	}
}

func TestRecorder_RecordAfterClose(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 100,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err = rec.Record(recorder.Entry{
		SessionID: testSessionID,
		Type:      testType,
		Summary:   "after close",
	})
	if err == nil {
		t.Fatal("expected error when recording after close")
	}
}

func TestRecorder_DefaultCheckpointInterval(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled: true,
		Dir:     dir,
		// CheckpointInterval left at 0 -- should use default
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	// Should not panic or error with default interval
	err = rec.Record(recorder.Entry{
		SessionID: testSessionID,
		Type:      testType,
		Summary:   "test",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
}

func TestRecorder_NilDetail(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             true,
		CheckpointInterval: 100,
	}

	// Redact function that should not be called for nil detail
	redactFn := func(_ context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: true}
	}

	rec, err := recorder.New(cfg, redactFn, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	err = rec.Record(recorder.Entry{
		SessionID: testSessionID,
		Type:      testType,
		Summary:   "nil detail",
		Detail:    nil,
	})
	if err != nil {
		t.Fatalf("Record with nil detail: %v", err)
	}
}

func TestComputeFileHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")
	content := []byte("test content\n")
	if err := os.WriteFile(path, content, filePermissions); err != nil {
		t.Fatal(err)
	}

	hash, err := recorder.ComputeFileHash(path)
	if err != nil {
		t.Fatalf("ComputeFileHash: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	// Same file should produce same hash
	hash2, err := recorder.ComputeFileHash(path)
	if err != nil {
		t.Fatalf("second ComputeFileHash: %v", err)
	}
	if hash != hash2 {
		t.Error("same file should produce same hash")
	}
}

func TestComputeFileHash_NotFound(t *testing.T) {
	_, err := recorder.ComputeFileHash("/nonexistent/file")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestRecorder_RedactionCleanResult(t *testing.T) {
	dir := t.TempDir()

	// Redact function that always returns clean (no matches)
	cleanFn := func(_ context.Context, _ string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: true}
	}

	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             true,
		CheckpointInterval: 100,
	}
	rec, err := recorder.New(cfg, cleanFn, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	// Detail should be preserved when DLP says clean
	detail := map[string]string{"safe": "content"}
	err = rec.Record(recorder.Entry{
		SessionID: testSessionID,
		Type:      testType,
		Transport: testTransport,
		Summary:   "clean content",
		Detail:    detail,
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-test-session-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(entries) < 1 {
		t.Fatal("expected at least 1 entry")
	}
	detailJSON, _ := json.Marshal(entries[0].Detail)
	if !strings.Contains(string(detailJSON), "content") {
		t.Error("clean detail should be preserved")
	}
}

func TestRecorder_RedactionMarshalError(t *testing.T) {
	dir := t.TempDir()

	// Redact function — won't be called since marshal of channel fails
	redactFn := func(_ context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: false, Matches: []scanner.TextDLPMatch{
			{PatternName: "test"},
		}}
	}

	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             true,
		CheckpointInterval: 100,
	}
	rec, err := recorder.New(cfg, redactFn, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	// Use a type that json.Marshal can handle but is interesting
	err = rec.Record(recorder.Entry{
		SessionID: testSessionID,
		Type:      testType,
		Transport: testTransport,
		Summary:   "marshal test",
		Detail:    map[string]int{"count": 42},
	})
	if err != nil {
		t.Fatalf("Record should succeed: %v", err)
	}
}

func TestRecorder_EscrowWithoutKey(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		RawEscrow:          true,
		EscrowPublicKey:    "", // No key provided
		CheckpointInterval: 100,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	// Should still record without error (escrow silently skipped)
	err = rec.Record(recorder.Entry{
		SessionID: testSessionID,
		Type:      testType,
		Transport: testTransport,
		Summary:   "no escrow key",
		Detail:    map[string]string{"data": "value"},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
}

func TestRecorder_ConcurrentRecords(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             false,
		CheckpointInterval: 100,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const goroutines = 10
	const entriesPerGoroutine = 5
	errs := make(chan error, goroutines*entriesPerGoroutine)
	var wg sync.WaitGroup

	for g := range goroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := range entriesPerGoroutine {
				err := rec.Record(recorder.Entry{
					SessionID: testSessionID,
					Type:      testType,
					Transport: testTransport,
					Summary:   fmt.Sprintf("goroutine %d entry %d", id, j),
				})
				if err != nil {
					errs <- err
				}
			}
		}(g)
	}

	wg.Wait()
	close(errs)
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for err := range errs {
		t.Errorf("concurrent Record error: %v", err)
	}
}

func TestRecorder_RetentionRemovesEscrowFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:       true,
		Dir:           dir,
		RetentionDays: 1,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	// Create old escrow file
	oldEscrow := filepath.Join(dir, "evidence-old-0.raw.enc")
	if err := os.WriteFile(oldEscrow, []byte("encrypted"), filePermissions); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(oldEscrow, old, old); err != nil {
		t.Fatal(err)
	}

	removed, err := rec.ExpireOldFiles()
	if err != nil {
		t.Fatalf("ExpireOldFiles: %v", err)
	}
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
}

func TestRecorder_ExpireIgnoresNonEvidenceFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:       true,
		Dir:           dir,
		RetentionDays: 1,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	// Create an old non-evidence file
	otherFile := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(otherFile, []byte("notes"), filePermissions); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(otherFile, old, old); err != nil {
		t.Fatal(err)
	}

	removed, err := rec.ExpireOldFiles()
	if err != nil {
		t.Fatalf("ExpireOldFiles: %v", err)
	}
	if removed != 0 {
		t.Error("should not remove non-evidence files")
	}
}

func TestRecorder_NewInvalidDir(t *testing.T) {
	cfg := recorder.Config{
		Enabled: true,
		Dir:     "/proc/nonexistent/impossible/path",
	}
	_, err := recorder.New(cfg, nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid directory")
	}
}

func TestRecorder_RawEscrowPerEntry(t *testing.T) {
	dir := t.TempDir()

	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Always-redact function so every entry gets escrow written
	redactFn := func(_ context.Context, _ string) scanner.TextDLPResult {
		return scanner.TextDLPResult{
			Clean: false,
			Matches: []scanner.TextDLPMatch{
				{PatternName: "test-pattern"},
			},
		}
	}

	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             true,
		CheckpointInterval: 1000, // High to avoid auto-checkpoints
		RawEscrow:          true,
		EscrowPublicKey:    hex.EncodeToString(recipientPub[:]),
	}

	rec, err := recorder.New(cfg, redactFn, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const entryCount = 3
	secrets := make([]string, entryCount)
	for i := range entryCount {
		secrets[i] = fmt.Sprintf("secret-payload-%d", i)
		err := rec.Record(recorder.Entry{
			SessionID: testSessionID,
			Type:      testType,
			Transport: testTransport,
			Summary:   fmt.Sprintf("entry %d", i),
			Detail:    map[string]string{"data": secrets[i]},
		})
		if err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read entries to get RawRefs
	var jsonlFile string
	dirEntries, _ := os.ReadDir(dir)
	for _, de := range dirEntries {
		if strings.HasSuffix(de.Name(), ".jsonl") {
			jsonlFile = filepath.Join(dir, de.Name())
			break
		}
	}
	if jsonlFile == "" {
		t.Fatal("no JSONL file found")
	}

	entries, err := recorder.ReadEntries(jsonlFile)
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}

	// Verify each data entry has a unique escrow file with correct content
	const keySize = 32
	const nonceSize = 24
	seenFiles := make(map[string]bool)
	dataIdx := 0
	for _, e := range entries {
		if e.Type == testCheckpoint {
			continue
		}
		if e.RawRef == "" {
			t.Errorf("entry seq %d: missing RawRef", e.Sequence)
			continue
		}
		if seenFiles[e.RawRef] {
			t.Errorf("entry seq %d: RawRef %q duplicates a previous entry", e.Sequence, e.RawRef)
		}
		seenFiles[e.RawRef] = true

		escrowPath := filepath.Join(dir, e.RawRef)
		payload, err := os.ReadFile(filepath.Clean(escrowPath))
		if err != nil {
			t.Errorf("entry seq %d: reading escrow %s: %v", e.Sequence, e.RawRef, err)
			continue
		}

		if len(payload) < keySize+nonceSize+box.Overhead {
			t.Errorf("entry seq %d: escrow payload too short", e.Sequence)
			continue
		}

		var ephPub [keySize]byte
		copy(ephPub[:], payload[:keySize])
		rest := payload[keySize:]
		var nonce [nonceSize]byte
		copy(nonce[:], rest[:nonceSize])

		decrypted, ok := box.Open(nil, rest[nonceSize:], &nonce, &ephPub, recipientPriv)
		if !ok {
			t.Errorf("entry seq %d: failed to decrypt escrow", e.Sequence)
			continue
		}

		if !strings.Contains(string(decrypted), secrets[dataIdx]) {
			t.Errorf("entry seq %d: decrypted escrow does not contain %q, got %q",
				e.Sequence, secrets[dataIdx], string(decrypted))
		}
		dataIdx++
	}

	if len(seenFiles) != entryCount {
		t.Errorf("expected %d unique escrow files, got %d", entryCount, len(seenFiles))
	}
}

// filePermissions for test file creation.
const filePermissions = 0o600
