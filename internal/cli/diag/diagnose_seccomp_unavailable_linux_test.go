// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !amd64

package diag

import (
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestDiagnoseReportsSeccompUnavailableWithoutFilter(t *testing.T) {
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)

	err := runDiagnoseSandbox(cmd, false, false)
	if err == nil {
		t.Fatal("diagnose succeeded despite unavailable seccomp")
	}
	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 1 {
		t.Fatalf("diagnose error = %v, want exit code 1", err)
	}

	const want = "sandbox_seccomp      FAIL  unavailable"
	if got := output.String(); !bytes.Contains([]byte(got), []byte(want)) {
		t.Fatalf("diagnose output missing %q:\n%s", want, got)
	}
}
