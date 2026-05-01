// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const testEnvelopeDirectoryUse = "pipelock-mediation"

func TestEnvelopeWellKnownDirectory(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	enableEnvelopeSigning(t, cfg, writeEnvelopeKey(t))

	p, err := New(cfg, audit.NewNop(), scanner.New(cfg), metrics.New())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(p.Close)

	req := httptest.NewRequest(http.MethodGet, envelope.WellKnownPath, nil)
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", got)
	}
	var dir envelope.Directory
	if err := json.Unmarshal(rec.Body.Bytes(), &dir); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(dir.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(dir.Keys))
	}
	key := dir.Keys[0]
	if key.KeyID != config.DefaultEnvelopeSignKeyID {
		t.Fatalf("keyid = %q", key.KeyID)
	}
	if key.Algorithm != "ed25519" || key.Use != testEnvelopeDirectoryUse || len(key.PublicKey) != 64 {
		t.Fatalf("unexpected key directory entry: %+v", key)
	}
}

func TestEnvelopeWellKnownDirectoryUnsignedNotFound(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.MediationEnvelope.Enabled = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate: %v", err)
	}

	p, err := New(cfg, audit.NewNop(), scanner.New(cfg), metrics.New())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(p.Close)

	req := httptest.NewRequest(http.MethodGet, envelope.WellKnownPath, nil)
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
