// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	if err := nilEmitter.AbortNativeAEL(); err != nil {
		t.Fatalf("nil AbortNativeAEL: %v", err)
	}
	bareEmitter := &Emitter{}
	if err := bareEmitter.AbortNativeAEL(); err != nil {
		t.Fatalf("bare AbortNativeAEL: %v", err)
	}
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

func TestEmitterRetireNativeAELRejectsStaleAndAlreadyAdmittedHeartbeats(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, HeartbeatSeconds: 30})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}

	admitted := make(chan struct{})
	release := make(chan struct{})
	e.beforeChainLockForTest = func() {
		close(admitted)
		<-release
	}
	heartbeatErr := make(chan error, 1)
	go func() { heartbeatErr <- e.EmitHeartbeat() }()
	<-admitted
	e.beforeChainLockForTest = nil
	if err := e.RetireNativeAEL(); err != nil {
		t.Fatalf("RetireNativeAEL: %v", err)
	}
	close(release)
	if err := <-heartbeatErr; err == nil || !strings.Contains(err.Error(), "retired after signer rotation") {
		t.Fatalf("already-admitted heartbeat error = %v", err)
	}
	if err := e.EmitHeartbeat(); err == nil || !strings.Contains(err.Error(), "retired after signer rotation") {
		t.Fatalf("stale heartbeat error = %v", err)
	}
}

func TestEmitterNativeAELFailureQuarantinesWithoutLifecycleSuccess(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	t.Cleanup(func() { _ = rec.Close() })
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, HeartbeatSeconds: 30})
	if err := e.nativeAEL.Abort(); err != nil {
		t.Fatalf("Abort native AEL: %v", err)
	}
	if err := e.EmitSessionOpen(); err == nil || !strings.Contains(err.Error(), "emitting native AEL record") {
		t.Fatalf("EmitSessionOpen error = %v, want native AEL failure", err)
	}
	if e.sessionOpenEmitted || e.openNonce != "" {
		t.Fatalf("failed native open advanced lifecycle: emitted=%t nonce=%q", e.sessionOpenEmitted, e.openNonce)
	}
	if e.HealthError() == nil {
		t.Fatal("failed native open did not quarantine receipt emitter")
	}
	if err := e.EmitSessionOpen(); err == nil || !strings.Contains(err.Error(), "receipt emitter unhealthy") {
		t.Fatalf("retry error = %v, want quarantined emitter", err)
	}
}

func TestEmitterNativeAELInitializationFailureQuarantinesAfterReceiptPersistence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		setup func(*testing.T, string) (string, func())
	}{
		{
			name: "regular_file_root",
			setup: func(t *testing.T, dir string) (string, func()) {
				t.Helper()
				root := filepath.Join(dir, "ael")
				if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
					t.Fatalf("write AEL root file: %v", err)
				}
				return "", func() {
					if err := os.Remove(root); err != nil {
						t.Fatalf("remove test-created AEL root file: %v", err)
					}
				}
			},
		},
		{
			name: "symlink_root",
			setup: func(t *testing.T, dir string) (string, func()) {
				t.Helper()
				outside := t.TempDir()
				root := filepath.Join(dir, "ael")
				if err := os.Symlink(outside, root); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				return outside, func() {
					if err := os.Remove(root); err != nil {
						t.Fatalf("remove test-created AEL root symlink: %v", err)
					}
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			outside, repairRoot := tc.setup(t, dir)
			pub, priv := generateTestKey(t)
			rec := newTestRecorder(t, dir, priv)
			t.Cleanup(func() { _ = rec.Close() })
			metrics := &stubMetrics{}
			e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor, HeartbeatSeconds: 30, Metrics: metrics})
			if e == nil {
				t.Fatal("NewEmitter returned nil")
			}
			if err := e.InitError(); err != nil {
				t.Fatalf("InitError = %v, want nil: native AEL errors surface through the first lifecycle emission", err)
			}

			firstErr := e.EmitSessionOpen()
			if firstErr == nil || !strings.Contains(firstErr.Error(), "emitting native AEL record") || !strings.Contains(firstErr.Error(), "refuse non-directory or symlink") {
				t.Fatalf("EmitSessionOpen error = %v, want native AEL root refusal", firstErr)
			}
			if e.sessionOpenEmitted || e.openNonce != "" {
				t.Fatalf("failed native AEL open advanced lifecycle: emitted=%t nonce=%q", e.sessionOpenEmitted, e.openNonce)
			}
			if e.HealthError() == nil {
				t.Fatal("native AEL initialization failure did not quarantine receipt emitter")
			}
			if got := metrics.snapshot(); len(got) != 1 || got[0] != FailReasonAEL {
				t.Fatalf("failure reasons = %v, want [%q]", got, FailReasonAEL)
			}

			for _, emit := range []struct {
				name string
				call func() error
			}{
				{name: "repeat_open", call: e.EmitSessionOpen},
				{name: "normal_durable_action", call: func() error {
					return e.EmitDurable(EmitOpts{ActionID: NewActionID(), Method: "GET", Target: "https://api.vendor.example/data", Verdict: config.ActionAllow, Transport: "fetch"})
				}},
			} {
				t.Run(emit.name, func(t *testing.T) {
					err := emit.call()
					if err == nil || !strings.Contains(err.Error(), "receipt emitter unhealthy") || !errors.Is(err, firstErr) {
						t.Fatalf("emission error = %v, want quarantined emitter with original native AEL failure", err)
					}
				})
			}
			persisted := readAllReceiptsFromDir(t, dir, pub)
			if len(persisted) != 1 || !isSessionOpenControl(persisted[0].ActionRecord.SessionControl) {
				t.Fatalf("persisted receipts = %#v, want exactly the first session_open", persisted)
			}
			repairRoot()
			if err := e.EmitDurable(EmitOpts{ActionID: NewActionID(), Method: "GET", Target: "https://api.vendor.example/after-repair", Verdict: config.ActionAllow, Transport: "fetch"}); err == nil || !strings.Contains(err.Error(), "receipt emitter unhealthy") || !errors.Is(err, firstErr) {
				t.Fatalf("old emitter action after root repair error = %v, want sticky native AEL failure", err)
			}

			recovered := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor, HeartbeatSeconds: 30})
			if recovered == nil {
				t.Fatal("recovered NewEmitter returned nil")
			}
			t.Cleanup(func() { _ = recovered.AbortNativeAEL() })
			if err := recovered.InitError(); err != nil {
				t.Fatalf("recovered InitError: %v", err)
			}
			if err := recovered.EmitSessionOpen(); err != nil {
				t.Fatalf("recovered EmitSessionOpen: %v", err)
			}
			if err := recovered.EmitDurable(EmitOpts{ActionID: NewActionID(), Method: "GET", Target: "https://api.vendor.example/recovered", Verdict: config.ActionAllow, Transport: "fetch"}); err != nil {
				t.Fatalf("recovered EmitDurable: %v", err)
			}
			if err := recovered.EmitSessionClose("recovered"); err != nil {
				t.Fatalf("recovered EmitSessionClose: %v", err)
			}
			if recovered.nativeAEL == nil || !recovered.nativeAEL.Opened() {
				t.Fatal("recovered emitter did not open a native AEL stream")
			}
			recoveredAELDir := recovered.nativeAEL.Dir()

			if err := rec.Close(); err != nil {
				t.Fatalf("Close recorder: %v", err)
			}
			receipts := readAllReceiptsFromDir(t, dir, pub)
			if len(receipts) != 4 || !isSessionOpenControl(receipts[0].ActionRecord.SessionControl) {
				t.Fatalf("persisted receipts = %#v, want preserved first session_open and recovered lifecycle", receipts)
			}
			if result := VerifyChain(receipts, hex.EncodeToString(pub)); !result.Valid {
				t.Fatalf("recovered receipt chain = %s", result.Error)
			}
			raw, err := os.ReadFile(filepath.Clean(filepath.Join(recoveredAELDir, "recorders", "pipelock.jsonl")))
			if err != nil {
				t.Fatalf("read recovered native AEL stream: %v", err)
			}
			if lines := strings.Split(strings.TrimSpace(string(raw)), "\n"); len(lines) != 3 {
				t.Fatalf("recovered native AEL record count = %d, want open, activity, close", len(lines))
			}
			if outside != "" {
				if entries, err := os.ReadDir(outside); err != nil {
					t.Fatalf("ReadDir outside: %v", err)
				} else if len(entries) != 0 {
					t.Fatalf("unsafe AEL root target received artifacts: %v", entries)
				}
			}
		})
	}
}
