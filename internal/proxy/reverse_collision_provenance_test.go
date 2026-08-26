// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestReverseIdentityCollisionCarriesProvenance drives the real reverse-proxy
// handler and reads the audit log it writes.
//
// The identity-collision event is the one event whose whole subject is a
// suspicious agent label, and it was built from a request context that did not
// yet carry the provenance grade, so it reported unknown even when the
// deployment had a bound identity. That is the wrong direction for the one
// record an investigator reads to decide whether a name can be trusted.
func TestReverseIdentityCollisionCarriesProvenance(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.New("json", "file", logPath, true, true)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	// The collision check returns early when a bound default identity exists
	// (internal/edition/edition.go, boundDefaultIdentity), so this event is
	// only reachable on a listener WITHOUT one. That is exactly the deployment
	// where the grade matters most: the label is caller-supplied, and the log
	// has to say so rather than say nothing.
	cfg.DefaultAgentIdentity = ""
	cfg.BindDefaultAgentIdentity = false

	sc := scanner.MustNew(cfg)
	defer sc.Close()
	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	handler := NewReverseProxy(
		upstreamURL, &cfgPtr, &scPtr, logger, metrics.New(), killswitch.New(cfg), nil, nil,
	)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://reverse.example/resource", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	// Self-declaring a reserved control actor is what triggers the collision.
	req.Header.Set("X-Pipelock-Agent", "pipelock")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	logger.Close()

	entry := findAuditEvent(t, logPath, "agent_identity")
	got, _ := entry["agent_auth"].(string)
	if got == "" || got == string(envelope.ActorAuthUnknown) {
		t.Fatalf("collision event reported no usable provenance (agent_auth=%q); "+
			"the resolved grade must reach this event", got)
	}
	if envelope.NormalizeActorAuth(got).TrustedForIdentity() {
		t.Fatalf("a self-declared collision must not carry a trusted grade, got %q", got)
	}
}

// findAuditEvent returns the first JSON audit line whose scanner field matches.
func findAuditEvent(t *testing.T, path, scannerName string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var entry map[string]any
		if err := json.Unmarshal(sc.Bytes(), &entry); err != nil {
			continue
		}
		if entry["scanner"] == scannerName {
			return entry
		}
	}
	t.Fatalf("no audit event with scanner=%q in:\n%s", scannerName, data)
	return nil
}
