// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestEmitStartupSessionOpenFailureDisablesLaterLifecycleWrites(t *testing.T) {
	wantErr := errors.New("session open failed")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	defer func() { _ = rec.Close() }()
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv})
	beforeStartupSessionOpenForTest = func(*receipt.Emitter) error { return wantErr }
	t.Cleanup(func() { beforeStartupSessionOpenForTest = nil })

	err = emitStartupSessionOpen(e)
	if !errors.Is(err, wantErr) {
		t.Fatalf("emitStartupSessionOpen() error = %v, want %v", err, wantErr)
	}
	if !errors.Is(e.HealthError(), wantErr) {
		t.Fatalf("HealthError() = %v, want %v", e.HealthError(), wantErr)
	}
	if receiptEmitterReady(e) {
		t.Fatal("receiptEmitterReady() = true after session_open failure")
	}
}

func TestEmitStartupSessionOpenEmitterFailureDisablesLaterLifecycleWrites(t *testing.T) {
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv})
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	err = emitStartupSessionOpen(e)
	if err == nil {
		t.Fatal("emitStartupSessionOpen() error = nil, want closed-recorder failure")
	}
	if !errors.Is(e.HealthError(), err) {
		t.Fatalf("HealthError() = %v, want emitted error %v", e.HealthError(), err)
	}
	if receiptEmitterReady(e) {
		t.Fatal("receiptEmitterReady() = true after emitter session_open failure")
	}
}
