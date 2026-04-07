// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
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
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestFlightRecorder_BlockedRequestCreatesEvidence(t *testing.T) {
	t.Parallel()

	evidenceDir := t.TempDir()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                evidenceDir,
		CheckpointInterval: 100,
		MaxEntriesPerFile:  1000,
	}, nil, nil)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p, pErr := New(cfg, logger, sc, metrics.New(), WithRecorder(rec))
	if pErr != nil {
		t.Fatalf("proxy.New: %v", pErr)
	}

	// pastebin.com is on the default blocklist — request should be blocked.
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://pastebin.com/raw/abc", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !resp.Blocked {
		t.Fatal("expected blocked=true")
	}

	// Close recorder to flush.
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	// Verify evidence files were created in the directory.
	entries, err := os.ReadDir(evidenceDir)
	if err != nil {
		t.Fatalf("reading evidence dir: %v", err)
	}

	var jsonlFiles []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			jsonlFiles = append(jsonlFiles, e.Name())
		}
	}
	if len(jsonlFiles) == 0 {
		t.Fatal("expected at least one .jsonl evidence file, got none")
	}

	// Read the first evidence file and verify it contains a decision entry.
	data, err := os.ReadFile(filepath.Clean(filepath.Join(evidenceDir, jsonlFiles[0])))
	if err != nil {
		t.Fatalf("reading evidence file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatal("evidence file is empty")
	}

	// Parse the first entry and verify it's a decision.
	var entry recorder.Entry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parsing evidence entry: %v", err)
	}

	if entry.Type != "decision" {
		t.Errorf("expected entry type %q, got %q", "decision", entry.Type)
	}
	if entry.SessionID != "proxy" {
		t.Errorf("expected session_id %q, got %q", "proxy", entry.SessionID)
	}
	if entry.Transport != "fetch" {
		t.Errorf("expected transport %q, got %q", "fetch", entry.Transport)
	}
	if !strings.Contains(entry.Summary, config.ActionBlock) {
		t.Errorf("expected summary to contain %q, got %q", config.ActionBlock, entry.Summary)
	}
}

func TestFlightRecorder_NilRecorder_NoOp(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	// No WithRecorder option — recorder is nil.
	p, pErr := New(cfg, logger, sc, metrics.New())
	if pErr != nil {
		t.Fatalf("proxy.New: %v", pErr)
	}

	// This should not panic even though recorder is nil.
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://pastebin.com/raw/abc", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestFlightRecorder_DisabledRecorder_NoOp(t *testing.T) {
	t.Parallel()

	// Create a disabled recorder (cfg.Enabled = false).
	rec, err := recorder.New(recorder.Config{
		Enabled: false,
	}, nil, nil)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p, pErr := New(cfg, logger, sc, metrics.New(), WithRecorder(rec))
	if pErr != nil {
		t.Fatalf("proxy.New: %v", pErr)
	}

	// Should not panic with a disabled (nop) recorder.
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://pastebin.com/raw/abc", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestFlightRecorder_CleanRequest_NoEvidence(t *testing.T) {
	t.Parallel()

	evidenceDir := t.TempDir()

	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello world"))
	}))
	defer backend.Close()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.FetchProxy.TimeoutSeconds = 5

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                evidenceDir,
		CheckpointInterval: 100,
		MaxEntriesPerFile:  1000,
	}, nil, nil)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p, pErr := New(cfg, logger, sc, metrics.New(), WithRecorder(rec))
	if pErr != nil {
		t.Fatalf("proxy.New: %v", pErr)
	}

	// Allowed request should not create evidence entries.
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+backend.URL+"/text", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for clean request, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Close and check: no evidence files should be written for a clean request.
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	entries, err := os.ReadDir(evidenceDir)
	if err != nil {
		t.Fatalf("reading evidence dir: %v", err)
	}

	var jsonlFiles []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			jsonlFiles = append(jsonlFiles, e.Name())
		}
	}
	if len(jsonlFiles) != 0 {
		t.Errorf("expected no evidence files for clean request, got %d", len(jsonlFiles))
	}
}
