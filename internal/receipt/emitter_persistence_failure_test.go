// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestEmitterRuntimeHealthFailureIsStickyAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()

	metrics := &stubMetrics{}
	e := NewEmitter(EmitterConfig{
		Recorder:  rec,
		PrivKey:   priv,
		Principal: testPrincipal,
		Actor:     testActor,
		Metrics:   metrics,
	})
	if e == nil {
		t.Fatal("NewEmitter returned nil")
	}

	first := errors.New("durable evidence transport failed")
	e.MarkUnhealthy(first)
	e.MarkUnhealthy(errors.New("later failure must not replace root cause"))
	if !errors.Is(e.HealthError(), first) {
		t.Fatalf("HealthError = %v, want first failure", e.HealthError())
	}

	err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
	})
	if !errors.Is(err, first) {
		t.Fatalf("Emit error = %v, want sticky health failure", err)
	}
	if got := metrics.snapshot(); len(got) != 1 || got[0] != FailReasonUnavailable {
		t.Fatalf("failure reasons = %v, want [%q]", got, FailReasonUnavailable)
	}
	if snapshot, ok := e.HealthSnapshot(); !ok || snapshot.ChainSeq != 0 || !snapshot.LastEmit.IsZero() {
		t.Fatalf("health snapshot after blocked emit = %+v, ok=%v", snapshot, ok)
	}

	var nilEmitter *Emitter
	nilEmitter.MarkUnhealthy(first)
	if err := nilEmitter.HealthError(); err != nil {
		t.Fatalf("nil HealthError = %v, want nil", err)
	}
	if _, ok := nilEmitter.HealthSnapshot(); ok {
		t.Fatal("nil HealthSnapshot reported available")
	}
}

func TestEmitterMalformedPersistedEvidenceBricksEmission(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence-proxy-0.jsonl")
	if err := os.WriteFile(path, []byte("{malformed\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()
	metrics := &stubMetrics{}
	e := NewEmitter(EmitterConfig{
		Recorder:  rec,
		PrivKey:   priv,
		Principal: testPrincipal,
		Actor:     testActor,
		Metrics:   metrics,
	})
	if e == nil {
		t.Fatal("NewEmitter returned nil")
	}
	if err := e.InitError(); err == nil || !strings.Contains(err.Error(), "reading existing evidence file") {
		t.Fatalf("InitError = %v, want malformed persisted evidence rejection", err)
	}

	err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
	})
	if err == nil || !strings.Contains(err.Error(), "resume receipt chain") {
		t.Fatalf("Emit error = %v, want fail-closed resume error", err)
	}
	if got := metrics.snapshot(); len(got) != 1 || got[0] != FailReasonChainInit {
		t.Fatalf("failure reasons = %v, want [%q]", got, FailReasonChainInit)
	}
	snapshot, ok := e.HealthSnapshot()
	if !ok || !snapshot.InitErr || snapshot.ChainSeq != 0 {
		t.Fatalf("health snapshot = %+v, ok=%v", snapshot, ok)
	}
}
