// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLateGroupCloseRejectsUnavailableAndUnboundDirectory(t *testing.T) {
	t.Run("intact signed close", func(t *testing.T) {
		set := closeTestGroup(t, 0)
		if err := set.recorder.Close(); err != nil {
			t.Fatal(err)
		}
		if hash, err := PublishLateReceiptGroupClose(set.recorder.Dir(), set.open.GroupID, set.signer); hash == "" || err != nil {
			t.Fatalf("intact closed group hash=%q err=%v", hash, err)
		}
	})
	key := testGroupKey(t)
	id := strings.Repeat("a", 32)
	missing := filepath.Join(t.TempDir(), "missing")
	t.Run("missing evidence directory", func(t *testing.T) {
		hash, err := PublishLateReceiptGroupClose(missing, id, key)
		var pathErr *os.PathError
		if hash != "" || !errors.Is(err, os.ErrNotExist) || !errors.As(err, &pathErr) || pathErr.Path != missing || !strings.HasPrefix(err.Error(), "opening evidence directory for receipt ceremony lock: ") {
			t.Fatalf("missing evidence directory hash=%q err=%v, want missing lock directory", hash, err)
		}
	})
	dir := t.TempDir()
	t.Run("invalid group ID", func(t *testing.T) {
		if hash, err := PublishLateReceiptGroupClose(dir, "invalid", key); hash != "" || err == nil || err.Error() != "invalid receipt group ID" {
			t.Fatalf("invalid group ID hash=%q err=%v, want invalid receipt group ID", hash, err)
		}
	})
	t.Run("missing AEL directory", func(t *testing.T) {
		hash, err := PublishLateReceiptGroupClose(dir, id, key)
		var pathErr *os.PathError
		if hash != "" || !errors.Is(err, os.ErrNotExist) || !errors.As(err, &pathErr) || pathErr.Path != filepath.Join(dir, "ael") || !strings.HasPrefix(err.Error(), "receipt group AEL path is not a real directory: ") {
			t.Fatalf("missing AEL directory hash=%q err=%v, want missing AEL path", hash, err)
		}
	})
	closeName, err := ReceiptGroupFileName(id, "close")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, closeName)); !os.IsNotExist(err) {
		t.Fatalf("refused close left artifact: %v", err)
	}
}

func TestLateGroupCloseTransitionInventoryRejectsMalformedArtifact(t *testing.T) {
	dir := t.TempDir()
	name, err := ReceiptGroupFileName(strings.Repeat("b", 32), "transition")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("malformed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := refuseSuccessorTransition(dir, strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "invalid receipt group transition inventory") {
		t.Fatalf("malformed transition accepted: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := refuseSuccessorTransition(dir, strings.Repeat("a", 64)); err != nil {
		t.Fatalf("empty transition inventory rejected: %v", err)
	}
}
