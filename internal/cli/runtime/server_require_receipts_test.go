// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestNewServer_RequireReceiptsWithoutEmitterFailsClosed pins the startup
// guard: require_receipts escalates a missing receipt to a block, so an
// inert recorder (no dir / no signing key) would fail-close every request
// with receipt_emission_failed. NewServer must refuse to start instead of
// bringing up a silently all-blocking proxy.
func TestNewServer_RequireReceiptsWithoutEmitterFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		section []string
	}{
		{
			name: "no_dir",
			section: []string{
				"flight_recorder:",
				"  enabled: true",
				"  require_receipts: true",
			},
		},
		{
			name: "dir_without_signing_key",
			section: []string{
				"flight_recorder:",
				"  enabled: true",
				"  require_receipts: true",
				"  dir: " + strconv.Quote(t.TempDir()),
			},
		},
		{
			name: "recorder_disabled",
			section: []string{
				"flight_recorder:",
				"  enabled: false",
				"  require_receipts: true",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := writeServerTestConfig(t, strings.Join(append([]string{"mode: balanced"}, tc.section...), "\n")+"\n")
			s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
			if err == nil {
				s.cleanup()
				t.Fatal("expected NewServer to fail when require_receipts is set without a live signed emitter")
			}
			if !strings.Contains(err.Error(), "require_receipts") {
				t.Fatalf("error = %q, want it to mention require_receipts", err)
			}
		})
	}
}

// TestNewServer_RequireReceiptsWithLiveEmitterStarts proves the guard is not
// over-broad: with a real recorder dir + signing key the emitter is live, so
// require_receipts is a valid configuration and NewServer succeeds.
func TestNewServer_RequireReceiptsWithLiveEmitterStarts(t *testing.T) {
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
		"  require_receipts: true",
		"  dir: " + strconv.Quote(recorderDir),
		"  signing_key_path: " + strconv.Quote(keyPath),
		"",
	}, "\n"))

	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatalf("NewServer with live signed emitter and require_receipts: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })
	if s.receiptEmitter == nil {
		t.Fatal("receiptEmitter nil despite configured recorder + signing key")
	}
}

func TestNewServer_RequireReceiptsWithBrickedEmitterFails(t *testing.T) {
	recorderDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "flight-recorder.key")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	seedTamperedReceiptTail(t, recorderDir, priv)

	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  require_receipts: true",
		"  dir: " + strconv.Quote(recorderDir),
		"  signing_key_path: " + strconv.Quote(keyPath),
		"",
	}, "\n"))

	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err == nil {
		s.cleanup()
		t.Fatal("expected NewServer to fail when require_receipts has a bricked emitter")
	}
	if !strings.Contains(err.Error(), "require_receipts") || !strings.Contains(err.Error(), "resume") {
		t.Fatalf("error = %q, want require_receipts and resume context", err)
	}
}

func seedTamperedReceiptTail(t *testing.T, dir string, priv ed25519.PrivateKey) {
	t.Helper()
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "test",
		Principal:  "test",
		Actor:      "test",
	})
	if err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   "allow",
		Transport: "fetch",
		Method:    http.MethodGet,
		Target:    "https://example.com",
	}); err != nil {
		t.Fatalf("seed Emit: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	tamperLastActionReceipt(t, dir)
}

func tamperLastActionReceipt(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var target string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".jsonl") {
			target = filepath.Join(dir, entry.Name())
		}
	}
	if target == "" {
		t.Fatal("no evidence file found")
	}
	raw, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal([]byte(lines[i]), &entry); err != nil {
			continue
		}
		var entryType string
		if err := json.Unmarshal(entry["type"], &entryType); err != nil || entryType != "action_receipt" {
			continue
		}
		rcpt, err := receipt.Unmarshal(entry["detail"])
		if err != nil {
			t.Fatalf("receipt.Unmarshal: %v", err)
		}
		rcpt.ActionRecord.Verdict = "block"
		detail, err := receipt.Marshal(rcpt)
		if err != nil {
			t.Fatalf("receipt.Marshal: %v", err)
		}
		entry["detail"] = detail
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		lines[i] = string(line)
		if err := os.WriteFile(filepath.Clean(target), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return
	}
	t.Fatal("no action_receipt entry found")
}
