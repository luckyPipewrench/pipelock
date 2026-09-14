// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestReleaseAssuranceCloseRejectsSubstitutedRecordersDirectory(t *testing.T) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		t.Skip("directory syncing is unsupported on this platform")
	}
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })

	emitter := NewEmitter(rec, priv, "0123456789abcdef0123456789abcdef", 30)
	if emitter == nil {
		t.Fatal("NewEmitter returned nil")
	}
	if err := emitter.EmitOpen(); err != nil {
		t.Fatalf("EmitOpen: %v", err)
	}

	recorders := filepath.Join(emitter.Dir(), "recorders")
	stream := filepath.Join(recorders, "pipelock.jsonl")
	if err := os.Remove(stream); err != nil {
		t.Fatalf("remove open record stream: %v", err)
	}
	if err := os.Remove(recorders); err != nil {
		t.Fatalf("remove recorders directory: %v", err)
	}
	if err := os.Symlink("/dev/null", recorders); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if target, err := os.Readlink(recorders); err != nil || target != "/dev/null" {
		t.Fatalf("recorders substitution target = %q, %v", target, err)
	}

	closeErr := emitter.EmitClose()
	if closeErr == nil || !strings.Contains(closeErr.Error(), "sync closed native AEL stream directory") {
		t.Fatalf("EmitClose after recorders substitution = %v, want directory sync failure", closeErr)
	}
	if !emitter.closed {
		t.Fatal("failed close did not seal the lifecycle state")
	}
	if emitter.lastErr == nil || !errors.Is(closeErr, emitter.lastErr) {
		t.Fatalf("failed close did not retain the directory sync failure: %v", emitter.lastErr)
	}
	if err := emitter.EmitHeartbeat(); err == nil || !strings.Contains(err.Error(), "native AEL emitter unhealthy") {
		t.Fatalf("EmitHeartbeat after failed close = %v, want sticky unhealthy failure", err)
	}
}
