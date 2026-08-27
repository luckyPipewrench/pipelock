// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestEmitterNativeAELLifecycle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, HeartbeatSeconds: 30})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if err := e.EmitDurable(EmitOpts{ActionID: NewActionID(), Method: "GET", Target: "https://api.vendor.example/data", Verdict: config.ActionAllow, Transport: "fetch"}); err != nil {
		t.Fatalf("EmitDurable: %v", err)
	}
	if err := e.EmitHeartbeat(); err != nil {
		t.Fatalf("EmitHeartbeat: %v", err)
	}
	if err := e.EmitSessionClose("test complete"); err != nil {
		t.Fatalf("EmitSessionClose: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(e.nativeAEL.Dir(), "recorders", "pipelock.jsonl"))
	if err != nil {
		t.Fatalf("read native AEL stream: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	want := []string{"open", "activity", "heartbeat", "close"}
	if len(lines) != len(want) {
		t.Fatalf("AEL record count = %d, want %d", len(lines), len(want))
	}
	for index, line := range lines {
		payload, decodeErr := base64.RawURLEncoding.DecodeString(strings.Split(line, ".")[0])
		if decodeErr != nil {
			t.Fatalf("decode record %d: %v", index, decodeErr)
		}
		var record struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(payload, &record); err != nil {
			t.Fatalf("unmarshal record %d: %v", index, err)
		}
		if record.Type != want[index] {
			t.Fatalf("record %d type = %q, want %q", index, record.Type, want[index])
		}
	}
}

func TestEmitterCloseNativeAELForRotation(t *testing.T) {
	t.Parallel()
	var nilEmitter *Emitter
	if err := nilEmitter.CloseNativeAEL(); err != nil {
		t.Fatalf("nil CloseNativeAEL: %v", err)
	}
	bareEmitter := &Emitter{}
	if err := bareEmitter.emitNativeAEL(ActionRecord{}, nil, false); err != nil {
		t.Fatalf("emitNativeAEL without native emitter: %v", err)
	}

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, HeartbeatSeconds: 30})
	if err := e.CloseNativeAEL(); err != nil {
		t.Fatalf("CloseNativeAEL before open: %v", err)
	}
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if err := e.CloseNativeAEL(); err != nil {
		t.Fatalf("CloseNativeAEL: %v", err)
	}
	if err := e.EmitDurable(EmitOpts{ActionID: NewActionID(), Method: "GET", Target: "https://api.vendor.example/data", Verdict: config.ActionAllow, Transport: "fetch"}); err == nil || !strings.Contains(err.Error(), "emitting native AEL record") {
		t.Fatalf("receipt after native close error = %v", err)
	}
	if err := e.CloseNativeAEL(); err == nil || !strings.Contains(err.Error(), "run is closed") {
		t.Fatalf("second CloseNativeAEL error = %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
