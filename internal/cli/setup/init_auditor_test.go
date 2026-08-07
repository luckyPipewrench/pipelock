// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// init must not report success when the auditor it just promised to install did
// not install. A silent partial install is how an operator ends up believing
// the corpus is watched when nothing is watching it, which is the whole reason
// the auditor exists.
func TestInitCmdFailsWhenAuditorInstallFails(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the auditor is installed only on linux")
	}

	stub(t, &evidenceAuditorUserConfigDir, func() (string, error) {
		return "", errors.New("no user config directory")
	})

	home := t.TempDir()
	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", filepath.Join(home, "cfg", "pipelock.yaml"),
		"--skip-canary",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("init reported success despite a failed auditor install\noutput:\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "installing evidence corpus auditor") {
		t.Fatalf("error = %v, want it to name the auditor install step", err)
	}
}
