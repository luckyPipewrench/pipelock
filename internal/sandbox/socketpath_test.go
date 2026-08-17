// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckSocketPathLength_AcceptsAPathTheKernelCanBind(t *testing.T) {
	if err := checkSocketPathLength("/tmp/pipelock-sandbox-123456789/proxy.sock"); err != nil {
		t.Fatalf("ordinary path rejected: %v", err)
	}
}

func TestCheckSocketPathLength_AcceptsExactlyTheLimit(t *testing.T) {
	path := "/" + strings.Repeat("a", maxUnixSocketPath-1)
	if len(path) != maxUnixSocketPath {
		t.Fatalf("fixture is %d bytes, want %d", len(path), maxUnixSocketPath)
	}
	if err := checkSocketPathLength(path); err != nil {
		t.Fatalf("path at exactly the limit rejected: %v", err)
	}
}

// The failure this guard exists for. Without it bind returns EINVAL, which
// reaches the operator as "invalid argument" and names neither the length nor
// TMPDIR.
func TestCheckSocketPathLength_RefusesOverLongPathAndSaysWhy(t *testing.T) {
	path := "/" + strings.Repeat("a", maxUnixSocketPath)
	err := checkSocketPathLength(path)
	if err == nil {
		t.Fatal("a path one byte over the limit was accepted")
	}
	for _, want := range []string{"TMPDIR", "kernel limit"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q, so it is not actionable: %v", want, err)
		}
	}
}

// The real production shape: a long TMPDIR is what makes the derived path
// exceed the limit, and it is the only input an operator controls.
func TestNewStandaloneControlDir_RefusesALongTMPDIR(t *testing.T) {
	base := t.TempDir()
	deep := filepath.Join(base, strings.Repeat("d", 90))
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Skipf("cannot build a long temp path here: %v", err)
	}
	t.Setenv("TMPDIR", deep)

	dir, err := newStandaloneControlDir()
	if err == nil {
		_ = os.Remove(dir)
		t.Fatalf("control dir accepted under a TMPDIR that cannot hold a bindable socket: %s", dir)
	}
	if !strings.Contains(err.Error(), "TMPDIR") {
		t.Errorf("refusal does not name TMPDIR, so an operator cannot act on it: %v", err)
	}
	// A rejected directory must not be left behind.
	if dir != "" {
		if _, statErr := os.Stat(dir); statErr == nil {
			t.Errorf("rejected control dir %s was left on disk", dir)
		}
	}
}

func TestNewStandaloneControlDir_AcceptsAShortTMPDIR(t *testing.T) {
	// Deliberately not t.TempDir(). It embeds the test name, and this test's
	// name alone pushes the derived socket path to 130 bytes -- the guard above
	// refuses it, correctly. Any test that needs a bindable unix socket has to
	// build a short directory rather than take the framework's.
	short, err := os.MkdirTemp("/tmp", "plk")
	if err != nil {
		t.Skipf("cannot create a short temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(short) }()
	t.Setenv("TMPDIR", short)

	dir, err := newStandaloneControlDir()
	if err != nil {
		t.Fatalf("short TMPDIR rejected: %v", err)
	}
	defer func() { _ = os.Remove(dir) }()
	if got := len(ProxySocketPath(dir)); got > maxUnixSocketPath {
		t.Fatalf("accepted a control dir whose socket path is %d bytes", got)
	}
}
