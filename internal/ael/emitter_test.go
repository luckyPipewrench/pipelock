// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestEmitterWritesDirectlySignedClosedChain(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}

	const runID = "0123456789abcdef0123456789abcdef"
	emitter := NewEmitter(rec, priv, runID, 30)
	if emitter == nil {
		t.Fatal("NewEmitter returned nil")
	}
	now := time.Date(2026, time.August, 27, 1, 2, 3, 0, time.UTC)
	emitter.now = func() time.Time {
		value := now
		now = now.Add(time.Second)
		return value
	}
	if err := emitter.EmitOpen(); err != nil {
		t.Fatalf("EmitOpen: %v", err)
	}
	if err := emitter.EmitActivity(Activity{Class: "read", ID: "action-1", Direction: "in"}, true); err != nil {
		t.Fatalf("EmitActivity: %v", err)
	}
	if err := emitter.EmitHeartbeat(); err != nil {
		t.Fatalf("EmitHeartbeat: %v", err)
	}
	if err := emitter.EmitClose(); err != nil {
		t.Fatalf("EmitClose: %v", err)
	}
	if err := rec.Record(recorder.Entry{SessionID: "proxy", Type: "decision", Summary: "discovery control"}); err != nil {
		t.Fatalf("Record discovery control: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	locations, err := recorder.DiscoverEvidenceLocations(dir)
	if err != nil {
		t.Fatalf("DiscoverEvidenceLocations: %v", err)
	}
	if len(locations) != 1 || locations[0].ID != "" {
		t.Fatalf("native AEL subtree changed recorder discovery: %+v", locations)
	}

	lines := readAELLines(t, emitter.Dir())
	if len(lines) != 4 {
		t.Fatalf("AEL record count = %d, want 4", len(lines))
	}
	manifestBytes, err := os.ReadFile(filepath.Join(emitter.Dir(), "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var gotManifest map[string]any
	if err := json.Unmarshal(manifestBytes, &gotManifest); err != nil {
		t.Fatalf("manifest JSON: %v", err)
	}
	if strings.HasSuffix(string(manifestBytes), "\n") {
		t.Fatal("manifest has trailing bytes and is not canonical")
	}
	// Encoding the decoded controlled-shape map must reproduce the exact bytes.
	canonicalManifest, err := json.Marshal(gotManifest)
	if err != nil {
		t.Fatalf("re-marshal manifest: %v", err)
	}
	if string(canonicalManifest) != string(manifestBytes) {
		t.Fatalf("manifest is not canonical: %s", manifestBytes)
	}
	wantTypes := []string{"open", "activity", "heartbeat", "close"}
	prev := zeroHash
	var previousPayload []byte
	for index, line := range lines {
		parts := strings.Split(line, ".")
		if len(parts) != 2 {
			t.Fatalf("line %d has %d compact parts, want 2", index, len(parts))
		}
		payload, decodeErr := base64.RawURLEncoding.DecodeString(parts[0])
		if decodeErr != nil {
			t.Fatalf("decode payload %d: %v", index, decodeErr)
		}
		sig, decodeErr := base64.RawURLEncoding.DecodeString(parts[1])
		if decodeErr != nil {
			t.Fatalf("decode signature %d: %v", index, decodeErr)
		}
		if !ed25519.Verify(pub, payload, sig) {
			t.Fatalf("record %d signature does not verify over exact payload bytes", index)
		}
		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatalf("unmarshal payload %d: %v", index, err)
		}
		if decoded["type"] != wantTypes[index] {
			t.Fatalf("record %d type = %v, want %q", index, decoded["type"], wantTypes[index])
		}
		if decoded["seq"] != float64(index) {
			t.Fatalf("record %d seq = %v", index, decoded["seq"])
		}
		if decoded["prev"] != prev {
			t.Fatalf("record %d prev = %v, want %s", index, decoded["prev"], prev)
		}
		if index > 0 {
			sum := sha256.Sum256(previousPayload)
			if decoded["prev"] != hex.EncodeToString(sum[:]) {
				t.Fatalf("record %d does not hash the previous payload", index)
			}
		}
		previousPayload = payload
		sum := sha256.Sum256(payload)
		prev = hex.EncodeToString(sum[:])
	}

	var closePayload map[string]any
	closeBytes, _ := base64.RawURLEncoding.DecodeString(strings.Split(lines[3], ".")[0])
	if err := json.Unmarshal(closeBytes, &closePayload); err != nil {
		t.Fatalf("unmarshal close: %v", err)
	}
	if closePayload["count"] != float64(4) {
		t.Fatalf("close count = %v, want 4", closePayload["count"])
	}
	headSum := sha256.Sum256(previousPayloadForLine(t, lines[2]))
	if closePayload["head"] != hex.EncodeToString(headSum[:]) {
		t.Fatalf("close head = %v, want heartbeat hash", closePayload["head"])
	}
}

func TestEmitterPersistenceFailureIsSticky(t *testing.T) {
	t.Parallel()
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
	emitter := NewEmitter(rec, priv, "fedcba9876543210fedcba9876543210", 30)
	if emitter == nil {
		t.Fatal("NewEmitter returned nil")
	}
	if err := emitter.file.Close(); err != nil {
		t.Fatalf("close record stream: %v", err)
	}
	firstErr := emitter.EmitOpen()
	if firstErr == nil || !strings.Contains(firstErr.Error(), "persist native AEL open") {
		t.Fatalf("EmitOpen error = %v", firstErr)
	}
	secondErr := emitter.EmitHeartbeat()
	if secondErr == nil || !strings.Contains(secondErr.Error(), "native AEL emitter unhealthy") {
		t.Fatalf("EmitHeartbeat after persistence failure = %v", secondErr)
	}
}

func TestNewEmitterRejectsNonPipelockRunID(t *testing.T) {
	t.Parallel()
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
	if emitter := NewEmitter(rec, priv, "../../escape", 30); emitter != nil {
		t.Fatal("NewEmitter accepted a path-shaped run ID")
	}
}

func TestNewEmitterConcurrentSharedRoot(t *testing.T) {
	t.Parallel()
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

	const count = 16
	emitters := make([]*Emitter, count)
	var wg sync.WaitGroup
	for index := range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			run := fmt.Sprintf("%032x", index+1)
			emitters[index] = NewEmitter(rec, priv, run, 30)
		}()
	}
	wg.Wait()
	for index, emitter := range emitters {
		if emitter == nil {
			t.Fatalf("NewEmitter %d returned nil", index)
		}
		if err := emitter.EmitOpen(); err != nil {
			t.Fatalf("EmitOpen %d: %v", index, err)
		}
		if err := emitter.EmitClose(); err != nil {
			t.Fatalf("EmitClose %d: %v", index, err)
		}
	}
}

func TestNewEmitterRefusesSymlinkArtifactRoot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "ael")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	emitter := NewEmitter(rec, priv, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 30)
	if emitter == nil {
		t.Fatal("NewEmitter returned nil")
	}
	if err := emitter.EmitOpen(); err == nil || !strings.Contains(err.Error(), "refuse non-directory or symlink") {
		t.Fatalf("EmitOpen error = %v, want symlink refusal", err)
	}
	if entries, readErr := os.ReadDir(outside); readErr != nil {
		t.Fatalf("ReadDir outside: %v", readErr)
	} else if len(entries) != 0 {
		t.Fatalf("symlink target received artifacts: %v", entries)
	}
}

func TestEmitterLifecycleRefusalsAndBounds(t *testing.T) {
	t.Parallel()
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
	emitter := NewEmitter(rec, priv, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", -1)
	if emitter == nil {
		t.Fatal("NewEmitter returned nil")
	}
	if emitter.hmax != 0 || emitter.htol != 0 {
		t.Fatalf("negative heartbeat normalized to hmax=%d htol=%d", emitter.hmax, emitter.htol)
	}
	if err := emitter.EmitHeartbeat(); err == nil || !strings.Contains(err.Error(), "not open") {
		t.Fatalf("heartbeat before open error = %v", err)
	}
	if err := emitter.EmitActivity(Activity{}, false); err == nil || !strings.Contains(err.Error(), "class and id") {
		t.Fatalf("empty activity error = %v", err)
	}
	if err := emitter.EmitActivity(Activity{Class: "read", ID: "id", Direction: "sideways"}, false); err == nil || !strings.Contains(err.Error(), "invalid AEL activity direction") {
		t.Fatalf("invalid direction error = %v", err)
	}
	if err := emitter.EmitOpen(); err != nil {
		t.Fatalf("EmitOpen: %v", err)
	}
	if !emitter.Opened() {
		t.Fatal("Opened = false after open")
	}
	if err := emitter.EmitOpen(); err == nil || !strings.Contains(err.Error(), "already open") {
		t.Fatalf("duplicate open error = %v", err)
	}
	if err := emitter.EmitActivity(Activity{Class: "actuate", ID: "id", Direction: "internal"}, false); err != nil {
		t.Fatalf("EmitActivity internal: %v", err)
	}
	if err := emitter.emit("activity", map[string]any{"unsupported": make(chan int)}, false); err == nil || !strings.Contains(err.Error(), "marshal canonical AEL payload") {
		t.Fatalf("unsupported canonical payload error = %v", err)
	}
	if err := emitter.EmitClose(); err != nil {
		t.Fatalf("EmitClose: %v", err)
	}
	if err := emitter.EmitHeartbeat(); err == nil || !strings.Contains(err.Error(), "run is closed") {
		t.Fatalf("heartbeat after close error = %v", err)
	}

	bounded := NewEmitter(rec, priv, "cccccccccccccccccccccccccccccccc", 10)
	if bounded == nil {
		t.Fatal("bounded NewEmitter returned nil")
	}
	bounded.opened = true
	bounded.seq = maxSafeInt + 1
	if err := bounded.EmitHeartbeat(); err == nil || !strings.Contains(err.Error(), "safe-integer") {
		t.Fatalf("unsafe sequence error = %v", err)
	}
}

func TestEmitterNilAndFilesystemRefusals(t *testing.T) {
	t.Parallel()
	var nilEmitter *Emitter
	if nilEmitter.Dir() != "" || nilEmitter.Opened() {
		t.Fatal("nil emitter reported state")
	}
	if err := nilEmitter.EmitOpen(); err != nil {
		t.Fatalf("nil EmitOpen: %v", err)
	}
	if emitter := NewEmitter(nil, nil, "dddddddddddddddddddddddddddddddd", 1); emitter != nil {
		t.Fatal("NewEmitter accepted nil recorder and key")
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
	if emitter := NewEmitter(rec, priv[:ed25519.SeedSize], "dddddddddddddddddddddddddddddddd", 1); emitter != nil {
		t.Fatal("NewEmitter accepted short private key")
	}
	const duplicateRun = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	first := NewEmitter(rec, priv, duplicateRun, 1)
	if first == nil {
		t.Fatal("first NewEmitter returned nil")
	}
	second := NewEmitter(rec, priv, duplicateRun, 1)
	if second == nil {
		t.Fatal("second NewEmitter returned nil")
	}
	if err := second.EmitOpen(); err == nil || !strings.Contains(err.Error(), "create AEL run directory") {
		t.Fatalf("duplicate run error = %v", err)
	}

	filePath := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ensureDirectory(filePath); err == nil || !strings.Contains(err.Error(), "refuse non-directory") {
		t.Fatalf("ensureDirectory file error = %v", err)
	}
	if err := ensureDirectory(filepath.Join(filePath, "child")); err == nil {
		t.Fatal("ensureDirectory below file succeeded")
	}
	if err := ensureDirectory(filepath.Join(t.TempDir(), "missing-parent", "child")); err == nil {
		t.Fatal("ensureDirectory with missing parent succeeded")
	}
	if err := writeExclusive(filePath, []byte("replacement"), 0o600); err == nil {
		t.Fatal("writeExclusive replaced an existing file")
	}
	if err := syncDirectory(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("syncDirectory accepted a missing path")
	}
}

func TestInitializeArtifactFailureStages(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tests := []struct {
		name        string
		failMkdir   int
		failWrite   int
		failOpen    bool
		failSync    int
		wantMessage string
	}{
		{name: "run directory", failMkdir: 1, wantMessage: "create AEL run directory"},
		{name: "child directory", failMkdir: 2, wantMessage: "create AEL keys directory"},
		{name: "key publication", failWrite: 1, wantMessage: "publish AEL key"},
		{name: "manifest publication", failWrite: 2, wantMessage: "write AEL manifest"},
		{name: "record stream", failOpen: true, wantMessage: "create AEL record stream"},
		{name: "directory sync", failSync: 1, wantMessage: "sync AEL artifact directory"},
	}
	for index, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ops := systemArtifactOps
			mkdirCalls := 0
			ops.mkdir = func(path string, mode os.FileMode) error {
				mkdirCalls++
				if mkdirCalls == tc.failMkdir {
					return errors.New("injected mkdir failure")
				}
				return os.Mkdir(path, mode)
			}
			writeCalls := 0
			ops.writeExclusive = func(path string, data []byte, mode os.FileMode) error {
				writeCalls++
				if writeCalls == tc.failWrite {
					return errors.New("injected write failure")
				}
				return writeExclusive(path, data, mode)
			}
			ops.openFile = func(path string, flags int, mode os.FileMode) (*os.File, error) {
				if tc.failOpen {
					return nil, errors.New("injected open failure")
				}
				// #nosec G304 -- path is built below this test's temporary directory.
				return os.OpenFile(path, flags, mode)
			}
			syncCalls := 0
			ops.syncDirectory = func(path string) error {
				syncCalls++
				if syncCalls == tc.failSync {
					return errors.New("injected sync failure")
				}
				return syncDirectory(path)
			}
			emitter := &Emitter{
				run:   fmt.Sprintf("%032x", index+100),
				keyID: strings.Repeat("a", 64),
			}
			err := emitter.initializeArtifactWithOps(dir, pub, ops)
			if err == nil || !strings.Contains(err.Error(), tc.wantMessage) {
				t.Fatalf("initializeArtifactWithOps error = %v, want %q", err, tc.wantMessage)
			}
		})
	}
}

func readAELLines(t *testing.T, dir string) []string {
	t.Helper()
	// #nosec G304 -- dir is the emitter-owned directory returned by the test.
	raw, err := os.ReadFile(filepath.Join(dir, "recorders", "pipelock.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func previousPayloadForLine(t *testing.T, line string) []byte {
	t.Helper()
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(line, ".")[0])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return payload
}
