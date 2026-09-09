// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `pipelock check` is the command an operator runs to find out whether a config
// is sound, and it was reporting OK on a config that startup and reload both
// warn about, because Load() surfaces only the hard error and the advisory
// warnings were never rendered.
//
// The exit code deliberately stays zero. This command is usable in CI and the
// existing advisories fire on legitimate configurations, so failing on one
// would get the command removed from the pipeline, which is the availability
// failure direction rather than a win.
func TestCheckRendersValidationWarnings(t *testing.T) {
	t.Parallel()

	// An api_allowlist naming a messaging domain is the pre-existing advisory
	// that was invisible here; the trusted_domains entry is the one added
	// alongside this change. Both must appear.
	const cfgYAML = `mode: strict
api_allowlist:
  - "api.telegram.org"
trusted_domains:
  - "*.duckdns.org"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(path, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cmd := CheckCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--config", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("a config with advisories must still exit zero, or this command stops being usable in CI: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Config validation: OK") {
		t.Fatalf("expected the config to validate; the advisories are not errors:\n%s", out)
	}
	for _, want := range []string{"[WARNING] api_allowlist", "[WARNING] trusted_domains"} {
		if !strings.Contains(out, want) {
			t.Errorf("check output does not contain %q, so an operator running the config checker sees a clean result on a config that startup warns about:\n%s", want, out)
		}
	}
}

// The control for the test above: a clean config must not grow phantom
// warnings, or the assertion there would pass on an implementation that printed
// a warning header unconditionally.
func TestCheckPrintsNoWarningsForACleanConfig(t *testing.T) {
	t.Parallel()

	const cfgYAML = `mode: balanced
trusted_domains:
  - "internal-svc"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(path, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cmd := CheckCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--config", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out := buf.String(); strings.Contains(out, "[WARNING]") {
		t.Errorf("a clean config produced a warning, so the warning path fires unconditionally:\n%s", out)
	}
}
