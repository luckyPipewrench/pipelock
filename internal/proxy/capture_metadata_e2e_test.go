// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestCaptureMetadata_FetchPath_RoundTrip exercises a real Proxy with a
// real capture.Writer wired in, drives a fetch request through the
// handler, and asserts that every metadata field the LL pipeline depends
// on (session_id, effective_action, config_hash, profile, agent) survives
// from the proxy call site through the writer's worker into the recorder
// JSONL on disk.
//
// This is the regression that locks in the SessionID-empty bug fix
// (3c90945) and the caller-side ConfigHash + Profile + EffectiveAction
// stamping (1e73278). Without those, the writer drops every entry as
// "empty session ID" or shadow rejects deltas as "invalid:
// original_verdict".
func TestCaptureMetadata_FetchPath_RoundTrip(t *testing.T) {
	t.Parallel()

	// Upstream that returns a tiny clean payload — the fetch path scans the
	// URL, writes a URLVerdictRecord through the capture observer, and on
	// allow proceeds to fetch the body. We only care about the
	// URLVerdictRecord write here.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := testScannerConfig()
	logger := audit.NewNop()
	sc := scanner.New(cfg)
	defer sc.Close()
	m := metrics.New()

	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	captureDir := t.TempDir()
	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:           true,
			Dir:               captureDir,
			MaxEntriesPerFile: 100,
		},
		QueueSize:    64,
		BuildVersion: "test",
		BuildSHA:     "test-sha",
	})
	if err != nil {
		t.Fatalf("capture.NewWriter: %v", err)
	}
	WithCaptureObserver(w)(p)

	// Drive a fetch through the handler. The URL points at the httptest
	// upstream; the URL itself is clean so the verdict resolves to allow.
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+upstream.URL, nil)
	rec := httptest.NewRecorder()
	p.handleFetch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fetch handler: status %d, want 200", rec.Code)
	}

	// Drain + close the writer so all queued entries flush to disk.
	if err := w.Close(); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	// Find the recorder JSONL inside the capture dir. Schema:
	//   <captureDir>/<sanitized session id>/evidence-<sid>-<seq>.jsonl
	// Find the first session subdir and the first JSONL inside it.
	sessions, err := os.ReadDir(captureDir)
	if err != nil {
		t.Fatalf("read capture dir: %v", err)
	}
	var jsonlPath string
	for _, sd := range sessions {
		if !sd.IsDir() || sd.Name() == "capture-meta" {
			continue
		}
		sessDir := filepath.Join(captureDir, sd.Name())
		entries, derr := os.ReadDir(sessDir)
		if derr != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".jsonl") {
				continue
			}
			jsonlPath = filepath.Join(sessDir, e.Name())
			break
		}
		if jsonlPath != "" {
			break
		}
	}
	if jsonlPath == "" {
		t.Fatalf("no recorder JSONL found in capture dir %s — drops likely (regression)", captureDir)
	}

	// Read the first capture entry. It is a recorder.Entry with the
	// CaptureSummary in Detail.
	fh, err := os.Open(filepath.Clean(jsonlPath))
	if err != nil {
		t.Fatalf("open capture jsonl: %v", err)
	}
	defer func() { _ = fh.Close() }()
	scanLine := bufio.NewScanner(fh)
	scanLine.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	if !scanLine.Scan() {
		t.Fatalf("empty capture jsonl")
	}
	var envelope struct {
		Type      string                 `json:"type"`
		EventKind string                 `json:"event_kind"`
		SessionID string                 `json:"session_id"`
		TraceID   string                 `json:"trace_id"`
		Detail    map[string]interface{} `json:"detail"`
	}
	if err := json.Unmarshal(scanLine.Bytes(), &envelope); err != nil {
		t.Fatalf("decode capture entry: %v", err)
	}

	// The entry's outer envelope must carry session_id and an event kind
	// derived from the capture surface. Empty session_id was the original
	// bug — assert non-empty.
	if envelope.SessionID == "" {
		t.Errorf("capture entry session_id empty — SessionID stamping regressed")
	}
	if envelope.Type != "capture" {
		t.Errorf("capture entry type = %q, want capture", envelope.Type)
	}
	if envelope.EventKind == "" {
		t.Errorf("capture entry event_kind empty — surface stamping regressed")
	}

	// CaptureSummary fields the LL pipeline depends on. effective_action
	// must be a non-empty action string so shadow can compute a non-empty
	// original_verdict. config_hash + profile must be populated so
	// downstream replay can reconstruct the contract a rule was scanned
	// against.
	requireString := func(field string) {
		t.Helper()
		v, ok := envelope.Detail[field]
		if !ok {
			t.Errorf("capture detail missing %q field", field)
			return
		}
		s, ok := v.(string)
		if !ok {
			t.Errorf("capture detail %q is %T, want string", field, v)
			return
		}
		if s == "" {
			t.Errorf("capture detail %q is empty — caller-side stamping regressed", field)
		}
	}
	requireString("effective_action")
	requireString("config_hash")
	requireString("profile")
	requireString("agent")

	// session_id_original is omitted on the clean path (path-safe agent + IP).
	// It only appears when the writer had to hash an unsafe or overlength key
	// for the on-disk directory name, in which case it preserves the raw
	// logical key for incident-response correlation. The fetch path uses the
	// anonymous agent + 127.0.0.1, which is path-safe, so the field must be
	// absent from this entry.
	if v, ok := envelope.Detail["session_id_original"]; ok {
		if s, _ := v.(string); s != "" {
			t.Errorf("session_id_original = %q, want absent on path-safe key (would leak client IP into every record otherwise)", s)
		}
	}
}
