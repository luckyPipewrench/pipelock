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
)

func TestConsumeToolDriftResetFileAcceptsSignedDelegationOnce(t *testing.T) {
	authority, privateKey := newAdaptiveResetAuthority(t)
	path := filepath.Join(t.TempDir(), "drift-reset")
	writeAdaptiveResetDelegation(t, path, privateKey, authority, ResetKindDrift, 7, strings.Repeat("1", 32))

	var logW bytes.Buffer
	if got := consumeToolDriftResetFile(path, authority, newResetAtomicEpoch(resetAuthorityEpoch(7)), &logW).Result; got != ResetAuthorityAccepted {
		t.Fatalf("consume result = %q, want accepted; log=%q", got, logW.String())
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("accepted drift delegation remained: %v", err)
	}
	if !strings.Contains(logW.String(), "result=accepted") || !strings.Contains(logW.String(), "epoch=7") {
		t.Fatalf("accepted drift reset was not audited: %q", logW.String())
	}

	writeAdaptiveResetDelegation(t, path, privateKey, authority, ResetKindDrift, 7, strings.Repeat("1", 32))
	if got := consumeToolDriftResetFile(path, authority, newResetAtomicEpoch(resetAuthorityEpoch(7)), &logW).Result; got != ResetAuthorityReplayed {
		t.Fatalf("replay result = %q, want replayed", got)
	}
}

func TestConsumeToolDriftResetFileRejectsWrongKindAndUnreadablePath(t *testing.T) {
	authority, privateKey := newAdaptiveResetAuthority(t)

	t.Run("wrong kind", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "drift-reset")
		writeAdaptiveResetDelegation(t, path, privateKey, authority, ResetKindAdaptive, 0, strings.Repeat("2", 32))
		if got := consumeToolDriftResetFile(path, authority, newResetAtomicEpoch(resetAuthorityEpoch(0)), nil).Result; got != ResetAuthorityWrongKind {
			t.Fatalf("wrong kind result = %q, want wrong_kind", got)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires privileges on Windows")
		}
		dir := t.TempDir()
		target := filepath.Join(dir, "delegation")
		writeAdaptiveResetDelegation(t, target, privateKey, authority, ResetKindDrift, 0, strings.Repeat("3", 32))
		path := filepath.Join(dir, "drift-reset")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if got := consumeToolDriftResetFile(path, authority, newResetAtomicEpoch(resetAuthorityEpoch(0)), nil).Result; got != ResetAuthorityUnreadable {
			t.Fatalf("symlink result = %q, want unreadable", got)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("unreadable path must stay in place: %v", err)
		}
	})
}
