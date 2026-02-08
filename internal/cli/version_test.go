package cli

import (
	"strings"
	"testing"
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
	if !strings.Contains(output, Version) {
		t.Errorf("expected output to contain version %q, got: %s", Version, output)
	}
}
