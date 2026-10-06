// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package exec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestExecFormatFailure(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "invalid-executable")
	if err := os.WriteFile(path, []byte("invalid executable format"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := launch(&cobra.Command{}, []string{path}, os.Environ()); err == nil || !strings.Contains(err.Error(), "exec command") {
		t.Fatalf("err=%v", err)
	}
}
