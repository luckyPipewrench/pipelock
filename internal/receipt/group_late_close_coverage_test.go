// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLateGroupCloseRejectsUnavailableAndUnboundDirectory(t *testing.T) {
	key := testGroupKey(t)
	id := strings.Repeat("a", 32)
	missing := filepath.Join(t.TempDir(), "missing")
	if hash, err := PublishLateReceiptGroupClose(missing, id, key); hash != "" || err == nil {
		t.Fatalf("missing evidence directory published close=%q err=%v", hash, err)
	}
	dir := t.TempDir()
	if hash, err := PublishLateReceiptGroupClose(dir, "invalid", key); hash != "" || err == nil {
		t.Fatalf("invalid group ID published close=%q err=%v", hash, err)
	}
	if hash, err := PublishLateReceiptGroupClose(dir, id, key); hash != "" || err == nil || !strings.Contains(err.Error(), "AEL path") {
		t.Fatalf("missing AEL directory published close=%q err=%v", hash, err)
	}
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
