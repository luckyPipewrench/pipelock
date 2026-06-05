// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateCommand(t *testing.T) {
	t.Parallel()

	out := t.TempDir()
	cmd := newRootCmd()
	cmd.SetArgs([]string{"generate", "--out", out, "--version", "v2.7.0-test"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("generate command: %v\n%s", err, buf.String())
	}

	// Gallery index and signer key were written.
	for _, name := range []string{"gallery.json", "signing-key.pub"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
	if !strings.Contains(buf.String(), "Lab signer public key:") {
		t.Errorf("expected key line in output, got:\n%s", buf.String())
	}
}

func TestGenerateCommand_RequiresOut(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{"generate"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	if err := cmd.Execute(); err == nil {
		t.Errorf("expected error when --out is missing")
	}
}
