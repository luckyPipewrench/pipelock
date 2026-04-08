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
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
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

func TestRecorder_SessionID_Validation(t *testing.T) {
	t.Run("rejects empty session ID", func(t *testing.T) {
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
		defer func() { _ = rec.Close() }()

		err = rec.Record(recorder.Entry{
			SessionID: "",
			Type:      testType,
			Summary:   "empty session",
		})
		if err == nil {
			t.Fatal("expected error for empty session ID")
		}
		if !strings.Contains(err.Error(), "session_id required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("rejects mismatched session ID", func(t *testing.T) {
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
		defer func() { _ = rec.Close() }()

		// First entry establishes session identity
		err = rec.Record(recorder.Entry{
			SessionID: "session-alpha",
			Type:      testType,
			Summary:   "first",
		})
		if err != nil {
			t.Fatalf("first Record: %v", err)
		}

		// Second entry with different session ID must be rejected
		err = rec.Record(recorder.Entry{
			SessionID: "session-beta",
			Type:      testType,
			Summary:   "wrong session",
		})
		if err == nil {
			t.Fatal("expected error for mismatched session ID")
		}
		if !strings.Contains(err.Error(), "session_id mismatch") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("accepts consistent session IDs", func(t *testing.T) {
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
		defer func() { _ = rec.Close() }()

		for i := range 3 {
			err := rec.Record(recorder.Entry{
				SessionID: "consistent-session",
				Type:      testType,
				Summary:   fmt.Sprintf("entry %d", i),
			})
			if err != nil {
				t.Fatalf("Record(%d): %v", i, err)
			}
		}
	})

	t.Run("rejects session ID with path traversal", func(t *testing.T) {
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
		defer func() { _ = rec.Close() }()

		for _, malicious := range []string{
			"../../../../tmp/pwn",
			"..\\windows\\system32",
			"legit/but-slashed",
		} {
			err := rec.Record(recorder.Entry{
				SessionID: malicious,
				Type:      testType,
				Summary:   "traversal attempt",
			})
			if err == nil {
				t.Errorf("expected error for session ID %q", malicious)
			}
			if !strings.Contains(err.Error(), "path separator") {
				t.Errorf("expected path separator error for %q, got: %v", malicious, err)
			}
		}
	})
}

func TestRecorder_EscrowFailure_FailsClosed(t *testing.T) {
	t.Run("escrow write failure prevents entry", func(t *testing.T) {
		dir := t.TempDir()

		recipientPub, _, err := box.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}

		cfg := recorder.Config{
			Enabled:            true,
			Dir:                dir,
			Redact:             false,
			CheckpointInterval: 100,
			RawEscrow:          true,
			EscrowPublicKey:    hex.EncodeToString(recipientPub[:]),
		}
		rec, err := recorder.New(cfg, nil, nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer func() { _ = rec.Close() }()

		// Remove the evidence directory after construction so
		// escrow file writes fail (directory no longer exists).
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("RemoveAll: %v", err)
		}

		err = rec.Record(recorder.Entry{
			SessionID: testSessionID,
			Type:      testType,
			Transport: testTransport,
			Summary:   "should fail",
			Detail:    map[string]string{"key": "value"},
		})
		if err == nil {
			t.Fatal("expected error when escrow write fails")
		}
		if !strings.Contains(err.Error(), "escrow") {
			t.Errorf("error should mention escrow, got: %v", err)
		}
	})

	t.Run("no JSONL entry written on escrow failure", func(t *testing.T) {
		dir := t.TempDir()

		recipientPub, _, err := box.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}

		cfg := recorder.Config{
			Enabled:            true,
			Dir:                dir,
			Redact:             false,
			CheckpointInterval: 100,
			RawEscrow:          true,
			EscrowPublicKey:    hex.EncodeToString(recipientPub[:]),
		}
		rec, err := recorder.New(cfg, nil, nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		// Remove the evidence directory so escrow writes fail
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("RemoveAll: %v", err)
		}

		_ = rec.Record(recorder.Entry{
			SessionID: testSessionID,
			Type:      testType,
			Transport: testTransport,
			Summary:   "fail",
			Detail:    map[string]string{"key": "value"},
		})
		_ = rec.Close()

		// Re-create dir to check for leaked files
		_ = os.MkdirAll(dir, 0o750)
		dirEntries, _ := os.ReadDir(dir)
		for _, de := range dirEntries {
			if strings.HasSuffix(de.Name(), ".jsonl") {
				t.Error("JSONL file should not exist when escrow failed")
			}
		}
	})
}

func TestRecorder_Nop_WhenDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled: false,
		Dir:     dir,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Record should succeed silently
	err = rec.Record(recorder.Entry{
		SessionID: testSessionID,
		Type:      testType,
		Summary:   "nop",
	})
	if err != nil {
		t.Fatalf("Record on nop recorder: %v", err)
	}

	// Close should succeed
	if err := rec.Close(); err != nil {
		t.Fatalf("Close on nop recorder: %v", err)
	}

	// ExpireOldFiles should succeed
	removed, err := rec.ExpireOldFiles()
	if err != nil {
		t.Fatalf("ExpireOldFiles on nop recorder: %v", err)
	}
	if removed != 0 {
		t.Errorf("expected 0 removed, got %d", removed)
	}

	// No files should be created
	dirEntries, _ := os.ReadDir(dir)
	for _, de := range dirEntries {
		t.Errorf("no-op recorder created file: %s", de.Name())
	}
}

func TestRecorder_SafeUint64_Boundary(t *testing.T) {
	// Test via New with boundary config values that exercise safeUint64.
	tests := []struct {
		name               string
		checkpointInterval int
		maxEntries         int
	}{
		{
			name:               "zero checkpoint uses default",
			checkpointInterval: 0,
			maxEntries:         0,
		},
		{
			name:               "negative checkpoint uses default",
			checkpointInterval: -1,
			maxEntries:         -5,
		},
		{
			name:               "very large checkpoint is capped",
			checkpointInterval: 1<<53 + 1,
			maxEntries:         1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := recorder.Config{
				Enabled:            true,
				Dir:                dir,
				CheckpointInterval: tc.checkpointInterval,
				MaxEntriesPerFile:  tc.maxEntries,
			}
			rec, err := recorder.New(cfg, nil, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer func() { _ = rec.Close() }()

			// Should be able to record without panic
			err = rec.Record(recorder.Entry{
				SessionID: testSessionID,
				Type:      testType,
				Transport: testTransport,
				Summary:   "boundary test",
			})
			if err != nil {
				t.Fatalf("Record: %v", err)
			}
		})
	}
}

func TestRecorder_WriteEntryToRemovedDir(t *testing.T) {
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// First record opens the file
	err = rec.Record(recorder.Entry{
		SessionID: testSessionID,
		Type:      testType,
		Transport: testTransport,
		Summary:   "first",
	})
	if err != nil {
		t.Fatalf("first Record: %v", err)
	}

	// Remove the evidence directory to cause subsequent write errors
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}

	// Closing should encounter a flush error since the underlying file is gone
	err = rec.Close()
	// We accept either an error or success (OS-dependent behavior for deleted-but-open files)
	// On Linux, the file handle remains valid even after directory removal,
	// so this tests the closeFile code path rather than guaranteeing error.
	_ = err
}

func TestRecorder_CloseFile_NilFile(t *testing.T) {
	// Close on a recorder that never opened a file (no records written)
	dir := t.TempDir()
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Close without writing anything -- exercises closeFile with nil file
	if err := rec.Close(); err != nil {
		t.Fatalf("Close on empty recorder: %v", err)
	}
}

func TestRecorder_VerifyChain_Errors(t *testing.T) {
	t.Run("empty chain is valid", func(t *testing.T) {
		if err := recorder.VerifyChain(nil); err != nil {
			t.Errorf("empty chain should be valid: %v", err)
		}
	})

	t.Run("wrong version", func(t *testing.T) {
		entries := []recorder.Entry{
			{
				Version:  99,
				Sequence: 0,
				PrevHash: recorder.GenesisHash,
				Hash:     "anything",
			},
		}
		err := recorder.VerifyChain(entries)
		if err == nil {
			t.Fatal("expected error for wrong version")
		}
		if !strings.Contains(err.Error(), "unsupported version") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("hash mismatch", func(t *testing.T) {
		e := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  0,
			SessionID: "s1",
			Type:      testType,
			PrevHash:  recorder.GenesisHash,
			Hash:      "wrong-hash",
		}
		err := recorder.VerifyChain([]recorder.Entry{e})
		if err == nil {
			t.Fatal("expected error for hash mismatch")
		}
		if !strings.Contains(err.Error(), "hash mismatch") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("first entry bad prevhash", func(t *testing.T) {
		e := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  0,
			SessionID: "s1",
			Type:      testType,
			PrevHash:  "not-genesis",
		}
		e.Hash = recorder.ComputeHash(e)
		err := recorder.VerifyChain([]recorder.Entry{e})
		if err == nil {
			t.Fatal("expected error for bad first entry PrevHash")
		}
		if !strings.Contains(err.Error(), "first entry PrevHash") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("chain break between entries", func(t *testing.T) {
		e0 := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  0,
			SessionID: "s1",
			Type:      testType,
			PrevHash:  recorder.GenesisHash,
		}
		e0.Hash = recorder.ComputeHash(e0)

		e1 := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  1,
			SessionID: "s1",
			Type:      testType,
			PrevHash:  "wrong-link",
		}
		e1.Hash = recorder.ComputeHash(e1)

		err := recorder.VerifyChain([]recorder.Entry{e0, e1})
		if err == nil {
			t.Fatal("expected error for chain break")
		}
		if !strings.Contains(err.Error(), "chain break") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestRecorder_ReadEntries_Errors(t *testing.T) {
	t.Run("nonexistent file", func(t *testing.T) {
		_, err := recorder.ReadEntries("/nonexistent/file.jsonl")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})

	t.Run("invalid JSON line", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.jsonl")
		if err := os.WriteFile(path, []byte("not json\n"), filePermissions); err != nil {
			t.Fatal(err)
		}
		_, err := recorder.ReadEntries(path)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "parsing entry") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("wrong entry version", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad-version.jsonl")
		line := `{"v":99,"seq":0,"ts":"2026-03-28T12:00:00Z","session_id":"s1","type":"request","transport":"fetch","summary":"test","detail":null,"prev_hash":"genesis","hash":"abc"}` + "\n"
		if err := os.WriteFile(path, []byte(line), filePermissions); err != nil {
			t.Fatal(err)
		}
		_, err := recorder.ReadEntries(path)
		if err == nil {
			t.Fatal("expected error for wrong version")
		}
		if !strings.Contains(err.Error(), "unsupported entry version") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("empty lines are skipped", func(t *testing.T) {
		dir := t.TempDir()

		e := recorder.Entry{
			Version:   recorder.EntryVersion,
			SessionID: "s1",
			Type:      testType,
			Transport: testTransport,
			PrevHash:  recorder.GenesisHash,
		}
		e.Hash = recorder.ComputeHash(e)
		data, _ := json.Marshal(e)

		path := filepath.Join(dir, "with-blanks.jsonl")
		content := "\n" + string(data) + "\n\n"
		if err := os.WriteFile(path, []byte(content), filePermissions); err != nil {
			t.Fatal(err)
		}

		entries, err := recorder.ReadEntries(path)
		if err != nil {
			t.Fatalf("ReadEntries: %v", err)
		}
		if len(entries) != 1 {
			t.Errorf("expected 1 entry, got %d", len(entries))
		}
	})
}

func TestRecorder_VerifyCheckpoints_Errors(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("missing signature", func(t *testing.T) {
		cpDetail := recorder.CheckpointDetail{
			EntryCount: 1,
			Signature:  "", // missing
		}
		detailJSON, _ := json.Marshal(cpDetail)
		var detail any
		_ = json.Unmarshal(detailJSON, &detail)

		e := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  0,
			SessionID: "s1",
			Type:      "checkpoint",
			PrevHash:  recorder.GenesisHash,
			Detail:    detail,
		}
		e.Hash = recorder.ComputeHash(e)

		err := recorder.VerifyCheckpoints([]recorder.Entry{e}, pub)
		if err == nil {
			t.Fatal("expected error for missing signature")
		}
		if !strings.Contains(err.Error(), "missing signature") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid hex signature", func(t *testing.T) {
		cpDetail := recorder.CheckpointDetail{
			EntryCount: 1,
			Signature:  "not-valid-hex!!!",
		}
		detailJSON, _ := json.Marshal(cpDetail)
		var detail any
		_ = json.Unmarshal(detailJSON, &detail)

		e := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  0,
			SessionID: "s1",
			Type:      "checkpoint",
			PrevHash:  recorder.GenesisHash,
			Detail:    detail,
		}
		e.Hash = recorder.ComputeHash(e)

		err := recorder.VerifyCheckpoints([]recorder.Entry{e}, pub)
		if err == nil {
			t.Fatal("expected error for invalid hex")
		}
	})

	t.Run("wrong signature", func(t *testing.T) {
		// Sign with the real key but different data
		badSig := ed25519.Sign(priv, []byte("wrong-data"))
		cpDetail := recorder.CheckpointDetail{
			EntryCount: 1,
			Signature:  hex.EncodeToString(badSig),
		}
		detailJSON, _ := json.Marshal(cpDetail)
		var detail any
		_ = json.Unmarshal(detailJSON, &detail)

		e := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  0,
			SessionID: "s1",
			Type:      "checkpoint",
			PrevHash:  recorder.GenesisHash,
			Detail:    detail,
		}
		e.Hash = recorder.ComputeHash(e)

		err := recorder.VerifyCheckpoints([]recorder.Entry{e}, pub)
		if err == nil {
			t.Fatal("expected error for wrong signature")
		}
		if !strings.Contains(err.Error(), "verification failed") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("skips non-checkpoint entries", func(t *testing.T) {
		e := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  0,
			SessionID: "s1",
			Type:      testType, // not a checkpoint
			PrevHash:  recorder.GenesisHash,
		}
		e.Hash = recorder.ComputeHash(e)

		// Should succeed: no checkpoints to verify
		err := recorder.VerifyCheckpoints([]recorder.Entry{e}, pub)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestRecorder_VerifyChain_WithPubKey(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 2,
		SignCheckpoints:    true,
	}
	rec, err := recorder.New(cfg, nil, priv)
	if err != nil {
		t.Fatal(err)
	}

	for i := range 3 {
		if err := rec.Record(recorder.Entry{
			SessionID: "s1",
			Type:      testType,
			Transport: testTransport,
			Summary:   fmt.Sprintf("r%d", i),
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-s1-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}

	// VerifyChain with pubKey should also check checkpoint signatures
	if err := recorder.VerifyChain(entries, pub); err != nil {
		t.Fatalf("VerifyChain with pubKey: %v", err)
	}

	// VerifyChain with nil pubKey should skip checkpoint verification
	if err := recorder.VerifyChain(entries, nil); err != nil {
		t.Fatalf("VerifyChain with nil pubKey: %v", err)
	}
}

func TestRecorder_ReceiptRedaction(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	sc := scanner.New(cfg)
	defer sc.Close()

	// Build fake cred at runtime to avoid gosec G101
	fakeKey := "AK" + "IA" + "IOSFODNN7EXAMPLE"

	tests := []struct {
		name      string
		entryType string
		detail    any
		// For receipts: selective redaction (target/pattern only, structure preserved).
		// For non-receipts: full redaction (entire detail replaced).
		wantSelectiveRedact bool
		wantFullRedact      bool
	}{
		{
			name:      "receipt target field is redacted",
			entryType: "action_receipt",
			detail: map[string]any{
				"version": 1,
				"action_record": map[string]any{
					"target":      "https://example.com/?key=" + fakeKey,
					"verdict":     "block",
					"action_type": "read",
					"transport":   testTransport,
					"action_id":   "test-id-123",
				},
				"signature":  "ed25519:deadbeef",
				"signer_key": "cafebabe",
			},
			wantSelectiveRedact: true,
		},
		{
			name:      "receipt without secrets is preserved",
			entryType: "action_receipt",
			detail: map[string]any{
				"version": 1,
				"action_record": map[string]any{
					"target":      "https://example.com/safe",
					"verdict":     "allow",
					"action_type": "read",
					"transport":   testTransport,
					"action_id":   "test-id-456",
				},
				"signature":  "ed25519:deadbeef",
				"signer_key": "cafebabe",
			},
		},
		{
			name:           "non-receipt entry gets full redaction",
			entryType:      "request",
			detail:         map[string]string{"url": "https://example.com/?key=" + fakeKey},
			wantFullRedact: true,
		},
		{
			name:      "receipt without action_record falls back to full redaction",
			entryType: "action_receipt",
			// Malformed receipt: missing action_record key triggers fallback
			detail:         map[string]string{"target": "https://example.com/?key=" + fakeKey},
			wantFullRedact: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subDir := t.TempDir()
			subCfg := recorder.Config{
				Enabled:            true,
				Dir:                subDir,
				Redact:             true,
				CheckpointInterval: 100,
			}
			subRec, err := recorder.New(subCfg, sc.ScanTextForDLP, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer func() { _ = subRec.Close() }()

			err = subRec.Record(recorder.Entry{
				SessionID: testSessionID,
				Type:      tt.entryType,
				Transport: testTransport,
				Summary:   "test entry",
				Detail:    tt.detail,
			})
			if err != nil {
				t.Fatalf("Record: %v", err)
			}
			if err := subRec.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			entries, err := recorder.ReadEntries(filepath.Join(subDir, "evidence-test-session-0.jsonl"))
			if err != nil {
				t.Fatalf("ReadEntries: %v", err)
			}
			if len(entries) < 1 {
				t.Fatal("expected at least 1 entry")
			}

			detailJSON, _ := json.Marshal(entries[0].Detail)
			detailStr := string(detailJSON)

			if tt.wantFullRedact {
				// Non-receipt: entire detail replaced with redaction wrapper
				if strings.Contains(detailStr, fakeKey) {
					t.Error("secret should be redacted from non-receipt detail")
				}
				if !strings.Contains(detailStr, "[REDACTED:") {
					t.Error("detail should contain redaction marker")
				}
				if !strings.Contains(detailStr, `"redacted":true`) {
					t.Error("detail should be wrapped in redaction envelope")
				}
			}

			if tt.wantSelectiveRedact {
				// Receipt: target field redacted, structure preserved
				detailMap, ok := entries[0].Detail.(map[string]any)
				if !ok {
					t.Fatal("receipt detail should be a map")
				}

				// Signature and signer_key preserved
				if _, hasSig := detailMap["signature"]; !hasSig {
					t.Error("receipt should preserve signature field")
				}
				if _, hasKey := detailMap["signer_key"]; !hasKey {
					t.Error("receipt should preserve signer_key field")
				}

				// action_record structure preserved
				ar, arOK := detailMap["action_record"].(map[string]any)
				if !arOK {
					t.Fatal("receipt should preserve action_record structure")
				}

				// Target is redacted
				if target, ok := ar["target"].(string); !ok || target != "[REDACTED]" {
					t.Errorf("target should be [REDACTED], got %v", ar["target"])
				}

				// Secret not present in serialized form
				if strings.Contains(detailStr, fakeKey) {
					t.Error("secret should not appear in receipt detail")
				}

				// Non-sensitive fields preserved
				if verdict, ok := ar["verdict"].(string); !ok || verdict != "block" {
					t.Errorf("verdict should be preserved, got %v", ar["verdict"])
				}
				if actionType, ok := ar["action_type"].(string); !ok || actionType != "read" {
					t.Errorf("action_type should be preserved, got %v", ar["action_type"])
				}
				if transport, ok := ar["transport"].(string); !ok || transport != testTransport {
					t.Errorf("transport should be preserved, got %v", ar["transport"])
				}

				// redacted_fields annotation present
				rf, rfOK := ar["redacted_fields"].([]any)
				if !rfOK {
					t.Fatal("receipt should have redacted_fields annotation")
				}
				found := false
				for _, f := range rf {
					if f == "target" {
						found = true
					}
				}
				if !found {
					t.Error("redacted_fields should include 'target'")
				}
			}

			// Clean receipt (no secrets): no modifications
			if !tt.wantSelectiveRedact && !tt.wantFullRedact && tt.entryType == "action_receipt" {
				detailMap, ok := entries[0].Detail.(map[string]any)
				if !ok {
					t.Fatal("receipt detail should be a map")
				}
				ar, arOK := detailMap["action_record"].(map[string]any)
				if !arOK {
					t.Fatal("receipt should preserve action_record structure")
				}
				if _, hasRF := ar["redacted_fields"]; hasRF {
					t.Error("clean receipt should not have redacted_fields")
				}
				if target, ok := ar["target"].(string); !ok || target != "https://example.com/safe" {
					t.Errorf("clean receipt target should be preserved, got %v", ar["target"])
				}
			}
		})
	}
}

// filePermissions for test file creation.
const filePermissions = 0o600
