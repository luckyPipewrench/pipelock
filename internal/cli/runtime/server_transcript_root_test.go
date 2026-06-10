// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// evidenceDirContains reports whether any evidence file in dir contains the
// given substring. Used to assert a transcript_root entry was written without
// coupling the test to the recorder's on-disk entry schema.
func evidenceDirContains(t *testing.T, dir, substr string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read evidence dir: %v", err)
	}
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, de.Name())))
		if err != nil {
			t.Fatalf("read evidence file %s: %v", de.Name(), err)
		}
		if strings.Contains(string(data), substr) {
			return true
		}
	}
	return false
}

// TestServer_SealTranscriptRoot_NoRecorderIsNoOp proves the seal is a safe no-op
// when no recorder/emitter is wired (the on-by-default-but-inert case: enabled
// with no dir). Shutdown must not panic or error when there is nothing to seal.
func TestServer_SealTranscriptRoot_NoRecorderIsNoOp(t *testing.T) {
	// Default config has flight_recorder enabled but no dir, so no emitter is
	// built and liveReceiptEmitter() returns nil.
	s, _ := newTestServer(t, func(o *ServerOpts) {
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
	})
	if e := s.liveReceiptEmitter(); e != nil {
		t.Fatalf("expected nil live emitter with no recorder dir, got %v", e)
	}
	// Must not panic.
	s.sealTranscriptRoot()
}

// TestServer_SealTranscriptRoot_SecondSealLogsError covers the error branch of
// sealTranscriptRoot: once the chain is sealed, a second seal returns
// ErrRootAlreadyEmitted, which must be logged (best-effort) rather than panic or
// propagate. Uses the live emitter directly (no full shutdown needed).
func TestServer_SealTranscriptRoot_SecondSealLogsError(t *testing.T) {
	recorderDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "flight-recorder.key")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  dir: " + strconv.Quote(recorderDir),
		"  signing_key_path: " + strconv.Quote(keyPath),
		"",
	}, "\n"))

	s, _ := newTestServer(t, func(o *ServerOpts) {
		o.ConfigFile = cfgPath
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
	})

	e := s.liveReceiptEmitter()
	if e == nil {
		t.Fatal("live receipt emitter is nil; recorder did not wire a signed emitter")
	}
	if err := e.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: "forward",
		Method:    http.MethodGet,
		Target:    "https://example.com/",
	}); err != nil {
		t.Fatalf("seed Emit: %v", err)
	}

	s.sealTranscriptRoot() // first seal succeeds
	s.sealTranscriptRoot() // second seal: ErrRootAlreadyEmitted -> logged, not fatal

	if !evidenceDirContains(t, recorderDir, "transcript_root") {
		t.Fatal("first seal did not write a transcript_root")
	}
}

// TestServer_GracefulShutdownSealsTranscriptRoot proves F4: a clean shutdown
// wires EmitTranscriptRoot, sealing the receipt chain with a transcript_root
// (the completeness anchor). Without this, a chain truncated by a clean exit
// verifies as VALID with no signal that the tail is missing.
//
// Scope note (clean-exit-only): this covers the graceful path. A SIGKILL kills
// the process before any deferred seal runs, so the tail is truncated with no
// root - that case needs an external/periodic anchor and is intentionally not
// closed here (and is not testable in-process, since killing the test process
// would take the test with it).
func TestServer_GracefulShutdownSealsTranscriptRoot(t *testing.T) {
	recorderDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "flight-recorder.key")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("save signing key: %v", err)
	}

	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  dir: " + strconv.Quote(recorderDir),
		"  signing_key_path: " + strconv.Quote(keyPath),
		"",
	}, "\n"))

	s, buf := newTestServer(t, func(o *ServerOpts) {
		o.ConfigFile = cfgPath
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
	})

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { errCh <- s.Start(ctx) }()

	waitForServerCancel(t, s)
	waitForServerOutput(t, buf, "flight recorder enabled")

	// Seed at least one receipt so the transcript root is non-trivial
	// (EmitTranscriptRoot is a no-op on an empty chain). Use the LIVE emitter -
	// the same instance the proxy decision paths emit through.
	e := s.liveReceiptEmitter()
	if e == nil {
		t.Fatal("live receipt emitter is nil; recorder did not wire a signed emitter")
	}
	if err := e.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: "forward",
		Method:    http.MethodGet,
		Target:    "https://example.com/",
	}); err != nil {
		t.Fatalf("seed Emit: %v", err)
	}

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case startErr := <-errCh:
		if startErr != nil {
			t.Fatalf("Start returned error after Shutdown: %v", startErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return within 5s of Shutdown")
	}

	if !evidenceDirContains(t, recorderDir, "transcript_root") {
		t.Fatalf("graceful shutdown did not seal a transcript_root in %s", recorderDir)
	}
}
