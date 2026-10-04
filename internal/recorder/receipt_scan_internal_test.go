// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestInternalReceiptWriteWithoutAttestationScansAtBoundary(t *testing.T) {
	dir := t.TempDir()
	var scans int
	rec, err := New(Config{Enabled: true, Dir: dir, Redact: true}, func(_ context.Context, text string) scanner.TextDLPResult {
		scans++
		return scanner.TextDLPResult{Clean: !strings.Contains(text, "test-sensitive-value")}
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	rec.mu.Lock()
	_, err = rec.prepareAndWriteEntryLocked(Entry{
		SessionID: "internal-scan", Type: recorderTypeReceipt,
		Detail: map[string]string{"value": "test-sensitive-value"},
	}, true)
	rec.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "refusing to record unverifiable redaction") {
		t.Fatalf("dirty detail error = %v", err)
	}

	rec.mu.Lock()
	_, err = rec.prepareAndWriteEntryLocked(Entry{
		SessionID: "internal-scan", Type: recorderTypeReceipt,
		Detail: map[string]string{"value": "safe"},
	}, true)
	rec.mu.Unlock()
	if err != nil {
		t.Fatalf("clean detail: %v", err)
	}
	if scans != 2 {
		t.Fatalf("DLP scans = %d, want one per internal attempt", scans)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	entries, err := ReadEntries(filepath.Join(dir, "evidence-internal-scan-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want only clean receipt", len(entries))
	}
	if err := VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}
