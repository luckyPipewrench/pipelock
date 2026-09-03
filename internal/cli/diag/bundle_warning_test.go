// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const unverifiableBundleWarning = "loaded although min_pipelock"

// writeUnversionedBundleConfig installs the unsigned test bundle under a
// temporary rules directory and returns a config file that points at it. The
// bundle declares min_pipelock and a test binary carries no release stamp, so
// merging it produces the unprovable-version warning every command must print.
func writeUnversionedBundleConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	setupUnsignedBundle(t, rulesDir, testBundleName, []byte(validBundleYAML))
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	cfgYAML := fmt.Sprintf("mode: audit\ninternal: []\nrules:\n  rules_dir: %s\n", rulesDir)
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestDiagCommands_PrintUnverifiableBundleVersionWarning(t *testing.T) {
	tests := []struct {
		name string
		cmd  func() *cobra.Command
		args []string
	}{
		{name: "diagnose", cmd: DiagnoseCmd, args: []string{"--json", "--config"}},
		{name: "test", cmd: TestCmd, args: []string{"--json", "--config"}},
		{name: "verify-install", cmd: VerifyInstallCmd, args: []string{"--json", "--no-color", "--config"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgPath := writeUnversionedBundleConfig(t)
			cmd := tt.cmd()
			var out, errOut bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			cmd.SetArgs(append(tt.args, cfgPath))
			// verify-install may fail its own posture checks under the audit
			// config; the warning must reach stderr regardless of the verdict.
			_ = cmd.Execute()
			if !strings.Contains(errOut.String(), unverifiableBundleWarning) {
				t.Fatalf("%s did not print the unprovable-version warning to stderr\nstderr:\n%s\nstdout:\n%s", tt.name, errOut.String(), out.String())
			}
			if strings.Contains(out.String(), unverifiableBundleWarning) {
				t.Fatalf("%s wrote the warning to stdout, which corrupts --json output:\n%s", tt.name, out.String())
			}
		})
	}
}

func TestDemoCmd_PrintsUnverifiableBundleVersionWarning(t *testing.T) {
	// demo takes no --config flag, so the bundle is installed where
	// rules.ResolveRulesDir looks: $XDG_DATA_HOME/pipelock/rules.
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	setupUnsignedBundle(t, filepath.Join(dataHome, "pipelock", "rules"), testBundleName, []byte(validBundleYAML))

	cmd := demoRoot()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"demo"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("demo: %v\nstderr:\n%s", err, errOut.String())
	}
	if !strings.Contains(errOut.String(), unverifiableBundleWarning) {
		t.Fatalf("demo did not print the unprovable-version warning to stderr\nstderr:\n%s", errOut.String())
	}
}
