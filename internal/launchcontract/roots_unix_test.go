// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package launchcontract

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemRootFileFallback(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bad, good, missing := filepath.Join(dir, "bad.pem"), filepath.Join(dir, "good.pem"), filepath.Join(dir, "missing.pem")
	data := certificate(t, nil)
	if err := os.WriteFile(bad, []byte("bad PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := systemRootsFromFiles([]string{missing, bad, good})
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("roots=%q err=%v", got, err)
	}
	if _, err := systemRootsFromFiles([]string{missing, bad}); err == nil {
		t.Fatal("absence of usable system roots accepted")
	}
}
