// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcpwrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStringArgs(t *testing.T) {
	t.Parallel()

	if got, err := stringArgs(nil); err != nil || got != nil {
		t.Errorf("nil: got %v err %v", got, err)
	}
	if got, err := stringArgs([]string{"a", "b"}); err != nil || strings.Join(got, " ") != "a b" {
		t.Errorf("[]string: got %v err %v", got, err)
	}
	if got, err := stringArgs([]interface{}{"a", "b"}); err != nil || strings.Join(got, " ") != "a b" {
		t.Errorf("[]interface{}: got %v err %v", got, err)
	}
	if _, err := stringArgs([]interface{}{"a", 1}); err == nil || !strings.Contains(err.Error(), "want string") {
		t.Errorf("non-string element should error, got %v", err)
	}
	if _, err := stringArgs("notalist"); err == nil || !strings.Contains(err.Error(), "must be a list") {
		t.Errorf("non-list should error, got %v", err)
	}
}

// TestWrapServer_RejectsNonStringArgs confirms wrap fails loudly rather than
// silently dropping a non-string arg (which would change the wrapped command).
func TestWrapServer_RejectsNonStringArgs(t *testing.T) {
	t.Parallel()

	_, _, _, err := WrapServer(map[string]interface{}{
		FieldCommand: "tool",
		FieldArgs:    []interface{}{"--port", 8080},
	}, fakeExe, "", "/c.yaml", "s")
	if err == nil || !strings.Contains(err.Error(), "want string") {
		t.Fatalf("err = %v, want non-string args rejection", err)
	}
}

// TestApplySidecarOps_SurfacesDeleteFailure confirms a delete that fails (here,
// a non-empty directory at the sidecar path) is returned rather than swallowed,
// so a credential file that could not be removed is surfaced.
func TestApplySidecarOps_SurfacesDeleteFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stuck := filepath.Join(dir, "stuck.headers")
	if err := os.Mkdir(stuck, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stuck, "child"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed child: %v", err)
	}
	if err := ApplySidecarOps([]SidecarOp{SidecarDelete(stuck)}); err == nil {
		t.Fatal("expected delete of a non-empty directory to surface an error")
	}
}
