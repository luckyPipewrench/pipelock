// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"strings"
	"testing"
)

func TestCaptureCmd_RequiresOutput(t *testing.T) {
	cmd := captureCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --output is not provided")
	}
	if !strings.Contains(err.Error(), "--output") {
		t.Errorf("expected error to mention --output, got: %v", err)
	}
}

func TestCaptureCmd_Help(t *testing.T) {
	cmd := captureCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	// Request help output.
	cmd.SetArgs([]string{"--help"})
	// Execute returns an error for --help (pflag ErrHelp); ignore it.
	_ = cmd.Execute()
	help := buf.String()
	if !strings.Contains(help, "--output") {
		t.Errorf("expected --output flag in help output, got:\n%s", help)
	}
	if !strings.Contains(help, "--duration") {
		t.Errorf("expected --duration flag in help output, got:\n%s", help)
	}
}
