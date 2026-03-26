// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestVersionCmd(t *testing.T) {
	cmd := versionCmd()

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.Run(cmd, nil)

	output := buf.String()
	if !strings.Contains(output, "pipelock version") {
		t.Errorf("expected 'pipelock version' in output, got: %s", output)
	}
	if !strings.Contains(output, "build date:") {
		t.Errorf("expected 'build date:' in output, got: %s", output)
	}
	if !strings.Contains(output, "git commit:") {
		t.Errorf("expected 'git commit:' in output, got: %s", output)
	}
	if !strings.Contains(output, "go version:") {
		t.Errorf("expected 'go version:' in output, got: %s", output)
	}
}

func TestVersionCmd_ContainsVersion(t *testing.T) {
	cmd := versionCmd()

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.Run(cmd, nil)

	output := buf.String()
	if !strings.Contains(output, cliutil.Version) {
		t.Errorf("expected output to contain version %q, got: %s", cliutil.Version, output)
	}
}
