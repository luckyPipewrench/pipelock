// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareInspectOutputBindsParentDirectory(t *testing.T) {
	root := t.TempDir()
	evidence := filepath.Join(root, "evidence")
	parent := filepath.Join(root, "output")
	if err := os.Mkdir(evidence, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	output, err := prepareInspectOutput(parent, "pin.json", evidence)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = output.close() }()
	moved := filepath.Join(root, "moved-output")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := output.file.Write([]byte("bound\n")); err != nil {
		t.Fatal(err)
	}
	if matches, err := output.parentMatches(parent); err != nil || matches {
		t.Fatalf("replacement parent match = %t, %v", matches, err)
	}
	if _, err := os.Stat(filepath.Join(parent, "pin.json")); !os.IsNotExist(err) {
		t.Fatalf("replacement parent received output: %v", err)
	}
	// #nosec G304 -- moved is the test's own temporary directory.
	if raw, err := os.ReadFile(filepath.Join(moved, "pin.json")); err != nil || string(raw) != "bound\n" {
		t.Fatalf("bound output = %q, %v", raw, err)
	}
}

func TestPrepareInspectOutputRejectsEvidenceDescendant(t *testing.T) {
	evidence := t.TempDir()
	parent := filepath.Join(evidence, "nested")
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareInspectOutput(parent, "pin.json", evidence); err == nil {
		t.Fatal("prepareInspectOutput accepted evidence descendant")
	}
}

func TestPrepareInspectOutputRejectsInvalidPathsAndExistingFile(t *testing.T) {
	root := t.TempDir()
	evidence := filepath.Join(root, "evidence")
	parent := filepath.Join(root, "output")
	if err := os.Mkdir(evidence, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareInspectOutput(filepath.Join(root, "missing"), "pin.json", evidence); err == nil {
		t.Fatal("prepareInspectOutput accepted missing parent")
	}
	if _, err := prepareInspectOutput(parent, "pin.json", filepath.Join(root, "missing-evidence")); err == nil {
		t.Fatal("prepareInspectOutput accepted missing evidence root")
	}
	if err := os.WriteFile(filepath.Join(parent, "pin.json"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareInspectOutput(parent, "pin.json", evidence); err == nil {
		t.Fatal("prepareInspectOutput replaced existing output")
	}
}
