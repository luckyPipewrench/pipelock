// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const receiptEntryType = "action_receipt"

// readAllEntries reads all JSONL evidence files from a directory.
func readAllEntries(t *testing.T, dir string) []recorder.Entry {
	t.Helper()
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var all []recorder.Entry
	for _, de := range dirEntries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".jsonl") {
			continue
		}
		entries, err := recorder.ReadEntries(filepath.Join(dir, de.Name()))
		if err != nil {
			t.Fatalf("ReadEntries(%s): %v", de.Name(), err)
		}
		all = append(all, entries...)
	}
	return all
}

// TestProxy_ReceiptEmission_FetchBlock boots a proxy with a recorder and receipt
// emitter, sends a request to a blocklisted domain, and verifies that a signed
// action receipt entry is written to the flight recorder.
func TestProxy_ReceiptEmission_FetchBlock(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKey := priv.Public().(ed25519.PublicKey)

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}

	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "test-config-hash",
		Principal:  "test-principal",
		Actor:      "test-actor",
	})

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.Blocklist = []string{"evil.example.com"}

	logger := audit.NewNop()
	sc := scanner.New(cfg)

	p, pErr := New(cfg, logger, sc, metrics.New(),
		WithRecorder(rec),
		WithReceiptEmitter(emitter),
	)
	if pErr != nil {
		t.Fatalf("proxy.New: %v", pErr)
	}

	handler := p.buildHandler(p.buildMux())
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://evil.example.com/steal", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	entries := readAllEntries(t, dir)

	var receiptEntry *recorder.Entry
	for i := range entries {
		if entries[i].Type == receiptEntryType {
			receiptEntry = &entries[i]
			break
		}
	}

	if receiptEntry == nil {
		var types []string
		for _, e := range entries {
			types = append(types, e.Type)
		}
		t.Fatalf("no action_receipt entry found in %d entries (types: %v)", len(entries), types)
	}

	detailJSON, err := json.Marshal(receiptEntry.Detail)
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}

	r, err := receipt.Unmarshal(detailJSON)
	if err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}

	if err := receipt.Verify(r); err != nil {
		t.Fatalf("receipt verification failed: %v", err)
	}

	if r.ActionRecord.Verdict != "block" {
		t.Errorf("expected verdict block, got %q", r.ActionRecord.Verdict)
	}
	if r.ActionRecord.ActionType != receipt.ActionRead {
		t.Errorf("expected action_type read, got %q", r.ActionRecord.ActionType)
	}
	if r.ActionRecord.Transport != "fetch" {
		t.Errorf("expected transport fetch, got %q", r.ActionRecord.Transport)
	}
	if r.ActionRecord.PolicyHash != "test-config-hash" {
		t.Errorf("expected policy_hash test-config-hash, got %q", r.ActionRecord.PolicyHash)
	}

	if err := receipt.VerifyWithKey(r, r.SignerKey); err != nil {
		t.Fatalf("receipt verification with key failed: %v", err)
	}
	_ = pubKey // used indirectly via priv.Public()
}

// TestProxy_ReceiptEmission_FetchAllow verifies that allowed requests also
// produce receipts.
func TestProxy_ReceiptEmission_FetchAllow(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello world"))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}

	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "test-hash",
		Principal:  "test",
		Actor:      "test",
	})

	cfg := config.Defaults()
	cfg.Internal = nil

	logger := audit.NewNop()
	sc := scanner.New(cfg)

	p, pErr := New(cfg, logger, sc, metrics.New(),
		WithRecorder(rec),
		WithReceiptEmitter(emitter),
	)
	if pErr != nil {
		t.Fatalf("proxy.New: %v", pErr)
	}

	handler := p.buildHandler(p.buildMux())
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+upstream.URL+"/hello", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	entries := readAllEntries(t, dir)

	var found bool
	for _, e := range entries {
		if e.Type == receiptEntryType {
			detailJSON, mErr := json.Marshal(e.Detail)
			if mErr != nil {
				t.Fatalf("marshal detail: %v", mErr)
			}
			r, uErr := receipt.Unmarshal(detailJSON)
			if uErr != nil {
				t.Fatalf("unmarshal receipt: %v", uErr)
			}
			if r.ActionRecord.Verdict == "allow" {
				found = true
				if err := receipt.Verify(r); err != nil {
					t.Fatalf("receipt verification failed: %v", err)
				}
				break
			}
		}
	}

	if !found {
		t.Fatal("no allow receipt found in entries")
	}
}

// TestProxy_NilEmitter_NoReceipt verifies that no receipts are emitted when
// the emitter is nil (no signing key configured).
func TestProxy_NilEmitter_NoReceipt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, nil)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.Blocklist = []string{"evil.example.com"}

	logger := audit.NewNop()
	sc := scanner.New(cfg)

	// No WithReceiptEmitter — emitter is nil
	p, pErr := New(cfg, logger, sc, metrics.New(), WithRecorder(rec))
	if pErr != nil {
		t.Fatalf("proxy.New: %v", pErr)
	}

	handler := p.buildHandler(p.buildMux())
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://evil.example.com/steal", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	entries := readAllEntries(t, dir)

	for _, e := range entries {
		if e.Type == receiptEntryType {
			t.Fatal("unexpected action_receipt entry when emitter is nil")
		}
	}
}
