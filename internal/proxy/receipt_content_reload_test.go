// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// The receipt detector is the recorder's own generation, fixed at
// construction; a reload replaces only the request scanner. A policy hash the
// reloaded configuration computes is a generated digest: a pattern in the
// recorder's detector that matches it must neither refuse the reload nor
// alter the hash signed into receipts.
func TestProxy_ReloadKeepsComputedPolicyHashOutOfReceiptDetector(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "receipt.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatal(err)
	}
	newCfg := func(blocked ...string) *config.Config {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		cfg.FlightRecorder.SigningKeyPath = keyPath
		cfg.FetchProxy.Monitoring.Blocklist = blocked
		return cfg
	}
	cfg, reloadCfg := newCfg(), newCfg("evil.example.com")
	reloadHash := reloadCfg.CanonicalPolicyHash()

	// The recorder's detector generation matches the reloaded hash; the
	// request scanners do not.
	recCfg := newCfg()
	recCfg.CanaryTokens = config.CanaryTokens{Enabled: true, Tokens: []config.CanaryToken{{Name: "reload_hash", Value: reloadHash}}}
	recScanner := scanner.MustNew(recCfg)
	t.Cleanup(recScanner.Close)
	recDir := t.TempDir()
	rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: recDir, Redact: true, CheckpointInterval: 1000}, recScanner, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	emitter := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: cfg.CanonicalPolicyHash(), Principal: "local", Actor: "pipelock"})
	if emitter.InitError() != nil {
		t.Fatal(emitter.InitError())
	}
	p, err := New(cfg, audit.NewNop(), scanner.MustNew(cfg), metrics.New(), WithRecorder(rec), WithReceiptEmitter(emitter), WithReceiptKeyPath(keyPath))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Reload(reloadCfg, scanner.MustNew(reloadCfg)) {
		t.Fatal("reload refused a computed policy hash")
	}

	w := httptest.NewRecorder()
	p.buildHandler(p.buildMux()).ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url=https://evil.example.com/exfil", nil))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	for _, e := range readAllEntries(t, recDir) {
		if e.Type != receiptEntryType {
			continue
		}
		raw, err := json.Marshal(e.Detail)
		if err != nil {
			t.Fatal(err)
		}
		r, err := receipt.Unmarshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		if r.ActionRecord.Target == "" || r.ActionRecord.SessionControl != nil {
			continue
		}
		if r.ActionRecord.PolicyHash != reloadHash {
			t.Fatalf("signed policy hash = %q, want the computed hash intact", r.ActionRecord.PolicyHash)
		}
		return
	}
	t.Fatal("no action receipt after reload")
}
