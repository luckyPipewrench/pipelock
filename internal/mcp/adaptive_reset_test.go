// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

// TestConsumeAdaptiveResetFile_RejectsSameUIDFile pins the authority boundary:
// a regular owner-only file is not sufficient when the wrapped agent shares
// the proxy UID.
func TestConsumeAdaptiveResetFile_RejectsSameUIDFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reset")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logW bytes.Buffer

	if consumeAdaptiveResetFile(path, &logW) {
		t.Fatalf("same-UID reset file must not be honored, log=%q", logW.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("rejected reset file must be removed (err=%v)", err)
	}
	if !strings.Contains(logW.String(), "independent operator") {
		t.Fatalf("same-UID rejection was not operator-visible: %q", logW.String())
	}
	// The removed file remains a no-op on a later check.
	if consumeAdaptiveResetFile(path, &logW) {
		t.Fatalf("missing file must not trigger a reset")
	}
}

// TestConsumeAdaptiveResetFile_RejectsGroupOrWorldAccessible is the bypass test:
// a reset file the wrapped agent could have written (group/world-accessible)
// must NOT be honored, and must be removed so it cannot persist.
func TestConsumeAdaptiveResetFile_RejectsGroupOrWorldAccessible(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not security-meaningful on Windows")
	}
	for _, mode := range []os.FileMode{0o660, 0o666, 0o604, 0o640, 0o620} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "reset")
			if err := os.WriteFile(path, []byte("x"), mode); err != nil {
				t.Fatal(err)
			}
			// WriteFile honors umask; force the exact mode.
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			var logW bytes.Buffer
			if consumeAdaptiveResetFile(path, &logW) {
				t.Fatalf("mode %o must NOT be honored (agent-writable bypass)", mode)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("an unsafe reset file must be removed, not left to persist")
			}
			if logW.Len() == 0 {
				t.Fatalf("expected a warning for the rejected reset file")
			}
		})
	}
}

// TestConsumeAdaptiveResetFile_RejectsSymlink ensures a symlink (which could
// redirect the unlink or mask ownership) is ignored.
func TestConsumeAdaptiveResetFile_RejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "reset")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	var logW bytes.Buffer
	if consumeAdaptiveResetFile(link, &logW) {
		t.Fatalf("a symlink reset file must not be honored")
	}
}

// TestConsumeAdaptiveResetFile_EmptyAndMissing are no-ops.
func TestConsumeAdaptiveResetFile_EmptyAndMissing(t *testing.T) {
	var logW bytes.Buffer
	if consumeAdaptiveResetFile("", &logW) {
		t.Fatalf("empty path must be a no-op")
	}
	if consumeAdaptiveResetFile(filepath.Join(t.TempDir(), "nope"), &logW) {
		t.Fatalf("missing file must be a no-op")
	}
	if logW.Len() != 0 {
		t.Fatalf("no-op cases must not warn, got %q", logW.String())
	}
}

// resettableRecorder is a mockRecorder that also satisfies adaptiveResetter, so
// ForwardScanned can clear its escalation when the operator reset file appears.
type resettableRecorder struct {
	mockRecorder
	resetCalls int
}

func (r *resettableRecorder) Reset() (prevScore float64, prevLevel int) {
	r.resetCalls++
	prevScore, prevLevel = r.score, r.level
	r.score = 0
	r.level = 0
	return prevScore, prevLevel
}

func blockAllCriticalCfg() *config.AdaptiveEnforcement {
	return &config.AdaptiveEnforcement{
		Enabled:             true,
		EscalationThreshold: 5.0,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: ptrBool(true)},
		},
	}
}

// TestForwardScanned_AdaptiveResetFile_SameUIDDoesNotClearAirlock proves that
// a wrapped agent cannot clear its own airlock with an indistinguishable 0600
// control file.
func TestForwardScanned_AdaptiveResetFile_SameUIDDoesNotClearAirlock(t *testing.T) {
	sc := newAdaptiveTestScanner()
	defer sc.Close()

	rec := &resettableRecorder{mockRecorder: mockRecorder{level: 3}}
	resetPath := filepath.Join(t.TempDir(), "reset")
	if err := os.WriteFile(resetPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cleanResp := makeResponse(1, "clean safe content") + "\n"
	var outBuf, logBuf bytes.Buffer
	if _, err := ForwardScanned(
		transport.NewStdioReader(strings.NewReader(cleanResp)),
		transport.NewStdioWriter(&outBuf),
		&logBuf, nil,
		buildTestOpts(sc, withRec(rec), withAdaptive(blockAllCriticalCfg()), withResetFile(resetPath)),
	); err != nil {
		t.Fatalf("ForwardScanned: %v", err)
	}

	if rec.resetCalls != 0 {
		t.Fatalf("same-UID reset file must not call Reset, got %d calls", rec.resetCalls)
	}
	if !strings.Contains(outBuf.String(), "-32001") {
		t.Fatalf("same-UID reset file must leave the airlock active:\n%s", outBuf.String())
	}
	if _, err := os.Stat(resetPath); !os.IsNotExist(err) {
		t.Fatalf("rejected reset file must be removed")
	}
	if !strings.Contains(logBuf.String(), "independent operator") {
		t.Fatalf("expected an operator-authority rejection, got:\n%s", logBuf.String())
	}
}

// TestForwardScanned_AdaptiveResetFile_BypassFileDoesNotClear is the bypass
// test: a reset file the wrapped agent could have written (group/world-
// accessible) must NOT clear the airlock — the clean response stays denied.
func TestForwardScanned_AdaptiveResetFile_BypassFileDoesNotClear(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not security-meaningful on Windows")
	}
	sc := newAdaptiveTestScanner()
	defer sc.Close()

	rec := &resettableRecorder{mockRecorder: mockRecorder{level: 3}}
	resetPath := filepath.Join(t.TempDir(), "reset")
	if err := os.WriteFile(resetPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Deliberately group/world-accessible: simulates a file the wrapped agent
	// could have written. A mode variable avoids gosec's octal-literal flag
	// without a lint-suppression directive; the permissive mode is the whole
	// point of the test.
	agentWritable := os.FileMode(0o666)
	if err := os.Chmod(resetPath, agentWritable); err != nil {
		t.Fatal(err)
	}

	cleanResp := makeResponse(1, "clean safe content") + "\n"
	var outBuf, logBuf bytes.Buffer
	if _, err := ForwardScanned(
		transport.NewStdioReader(strings.NewReader(cleanResp)),
		transport.NewStdioWriter(&outBuf),
		&logBuf, nil,
		buildTestOpts(sc, withRec(rec), withAdaptive(blockAllCriticalCfg()), withResetFile(resetPath)),
	); err != nil {
		t.Fatalf("ForwardScanned: %v", err)
	}

	if rec.resetCalls != 0 {
		t.Fatalf("an agent-writable reset file must NOT trigger a reset, got %d calls", rec.resetCalls)
	}
	if !strings.Contains(outBuf.String(), "-32001") {
		t.Fatalf("airlock should still deny the response (bypass file ignored), got:\n%s", outBuf.String())
	}
}
