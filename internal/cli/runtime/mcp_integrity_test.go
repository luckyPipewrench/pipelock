// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	mcpintegrity "github.com/luckyPipewrench/pipelock/internal/mcp/integrity"
)

const osWindows = "windows"

func testMCPRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "pipelock",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(McpCmd())
	return cmd
}

func TestMCPIntegrityManifestGenerateAndVerifyScript(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("test uses POSIX shebang script")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "server.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho mcp\n"), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")

	cmd := testMCPRoot()
	var genOut bytes.Buffer
	cmd.SetOut(&genOut)
	cmd.SetArgs([]string{"mcp", "integrity", "manifest", "generate", "--output", manifestPath, "--", script})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.Contains(genOut.String(), "Manifest written") {
		t.Fatalf("generate output = %q", genOut.String())
	}

	manifest, err := mcpintegrity.LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	resolvedScript, err := filepath.EvalSymlinks(script)
	if err != nil {
		t.Fatalf("resolve script: %v", err)
	}
	if _, ok := manifest.Entries[resolvedScript]; !ok {
		t.Fatalf("manifest missing script entry %q: %+v", resolvedScript, manifest.Entries)
	}
	if len(manifest.Entries) != 2 {
		t.Fatalf("manifest entries = %d, want interpreter + script: %+v", len(manifest.Entries), manifest.Entries)
	}

	verifyCmd := testMCPRoot()
	var verifyOut bytes.Buffer
	verifyCmd.SetOut(&verifyOut)
	verifyCmd.SetArgs([]string{"mcp", "integrity", "manifest", "verify", "--manifest", manifestPath, "--", script})
	if err := verifyCmd.Execute(); err != nil {
		t.Fatalf("verify: %v\noutput: %s", err, verifyOut.String())
	}
	if !strings.Contains(verifyOut.String(), "verified") {
		t.Fatalf("verify output = %q", verifyOut.String())
	}
}

func TestMCPIntegrityManifestGenerateRefusesOverwriteUnlessMerge(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("test uses POSIX shell command")
	}
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")

	cmd := testMCPRoot()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"mcp", "integrity", "manifest", "generate", "--output", manifestPath, "--", "sh"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("initial generate: %v", err)
	}

	overwriteCmd := testMCPRoot()
	overwriteCmd.SetOut(&bytes.Buffer{})
	overwriteCmd.SetArgs([]string{"mcp", "integrity", "manifest", "generate", "--output", manifestPath, "--", "sh"})
	if err := overwriteCmd.Execute(); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite err = %v, want already exists", err)
	}

	mergeCmd := testMCPRoot()
	mergeCmd.SetOut(&bytes.Buffer{})
	mergeCmd.SetArgs([]string{"mcp", "integrity", "manifest", "generate", "--output", manifestPath, "--merge", "--", "sh"})
	if err := mergeCmd.Execute(); err != nil {
		t.Fatalf("merge generate: %v", err)
	}
}

func TestMCPIntegrityManifestUsesWorkdirForRelativeScript(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("test uses POSIX shell command")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "server.sh")
	if err := os.WriteFile(script, []byte("echo mcp\n"), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")

	cmd := testMCPRoot()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"mcp", "integrity", "manifest", "generate",
		"--output", manifestPath,
		"--workdir", dir,
		"--", "sh", "server.sh",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("generate with workdir: %v", err)
	}

	manifest, err := mcpintegrity.LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	resolvedScript, err := filepath.EvalSymlinks(script)
	if err != nil {
		t.Fatalf("resolve script: %v", err)
	}
	if _, ok := manifest.Entries[resolvedScript]; !ok {
		t.Fatalf("manifest missing workdir-resolved script %q: %+v", resolvedScript, manifest.Entries)
	}
}

func TestMCPIntegrityManifestVerifyReportsMismatch(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("test uses POSIX shell command")
	}
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	resolvedShell, _, err := mcpintegrity.ResolveAndHash("sh")
	if err != nil {
		t.Fatalf("resolve sh: %v", err)
	}
	manifest := &mcpintegrity.Manifest{
		Version: mcpintegrity.ManifestVersion,
		Entries: map[string]string{
			resolvedShell: strings.Repeat("0", 64),
		},
	}
	if err := mcpintegrity.SaveManifest(manifestPath, manifest); err != nil {
		t.Fatalf("save manifest: %v", err)
	}

	cmd := testMCPRoot()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"mcp", "integrity", "manifest", "verify", "--manifest", manifestPath, "--json", "--", "sh"})
	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected verify failure")
	}

	var report mcpIntegrityReport
	if jsonErr := json.Unmarshal(out.Bytes(), &report); jsonErr != nil {
		t.Fatalf("unmarshal report: %v\n%s", jsonErr, out.String())
	}
	if report.OK {
		t.Fatalf("report OK = true, want false: %+v", report)
	}
	if len(report.Reasons) == 0 || !strings.Contains(report.Reasons[0], "hash mismatch") {
		t.Fatalf("reasons = %+v, want hash mismatch", report.Reasons)
	}
}

func TestMCPIntegrityManifestRequiresPaths(t *testing.T) {
	genCmd := testMCPRoot()
	genCmd.SetOut(&bytes.Buffer{})
	genCmd.SetArgs([]string{"mcp", "integrity", "manifest", "generate", "--", "sh"})
	if err := genCmd.Execute(); err == nil || !strings.Contains(err.Error(), "--output is required") {
		t.Fatalf("generate err = %v, want output required", err)
	}

	verifyCmd := testMCPRoot()
	verifyCmd.SetOut(&bytes.Buffer{})
	verifyCmd.SetArgs([]string{"mcp", "integrity", "manifest", "verify", "--", "sh"})
	if err := verifyCmd.Execute(); err == nil || !strings.Contains(err.Error(), "--manifest is required") {
		t.Fatalf("verify err = %v, want manifest required", err)
	}
}

func TestMCPIntegrityManifestGenerateSuppressesSuspiciousFlag(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("test uses POSIX shebang script")
	}
	// When the operator points generate at a script that lives inside the
	// --workdir they passed (the expected case for relative resolution),
	// the underlying VerifyResult.Suspicious flag goes true. That flag
	// is meaningful at runtime, not at generate time; surfacing it would
	// train operators to ignore it. Confirm the report omits it.
	dir := t.TempDir()
	script := filepath.Join(dir, "server.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho mcp\n"), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")

	cmd := testMCPRoot()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		"mcp", "integrity", "manifest", "generate",
		"--output", manifestPath,
		"--workdir", dir,
		"--json",
		"--", script,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if strings.Contains(out.String(), "suspicious") {
		t.Fatalf("generate JSON should omit suspicious, got:\n%s", out.String())
	}
	var report mcpIntegrityReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out.String())
	}
	if report.Suspicious {
		t.Fatalf("generate report should suppress Suspicious flag, got %+v", report)
	}
	if !report.OK {
		t.Fatalf("expected OK=true on successful generate, got %+v", report)
	}
}

func TestMCPIntegrityManifestMergePreservesExistingEntries(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("test uses POSIX shell command")
	}
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")

	// First generate pins one command.
	first := testMCPRoot()
	first.SetOut(&bytes.Buffer{})
	first.SetArgs([]string{"mcp", "integrity", "manifest", "generate", "--output", manifestPath, "--", "sh"})
	if err := first.Execute(); err != nil {
		t.Fatalf("first generate: %v", err)
	}
	before, err := mcpintegrity.LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("load before merge: %v", err)
	}
	if len(before.Entries) == 0 {
		t.Fatalf("first generate produced empty manifest")
	}

	// Second generate adds another command via --merge.
	second := testMCPRoot()
	second.SetOut(&bytes.Buffer{})
	second.SetArgs([]string{"mcp", "integrity", "manifest", "generate", "--output", manifestPath, "--merge", "--", "/bin/true"})
	if err := second.Execute(); err != nil {
		t.Fatalf("merge generate: %v", err)
	}

	after, err := mcpintegrity.LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("load after merge: %v", err)
	}
	for path, hash := range before.Entries {
		got, ok := after.Entries[path]
		if !ok {
			t.Errorf("merge dropped pre-existing entry %s", path)
			continue
		}
		if got != hash {
			t.Errorf("merge mutated pre-existing entry %s: before=%s after=%s", path, hash, got)
		}
	}
	if len(after.Entries) <= len(before.Entries) {
		t.Errorf("merge should add at least one new entry: before=%d after=%d", len(before.Entries), len(after.Entries))
	}
}

func TestMCPIntegrityManifestEnvShebangIsPinned(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("test uses POSIX shebang script")
	}
	// Validates the /usr/bin/env shebang path through the CLI surface.
	// A shebang script that uses `#!/usr/bin/env sh` must result in BOTH
	// the resolved interpreter and the resolved script being pinned, so a
	// swap of either component is detected at verify time.
	dir := t.TempDir()
	script := filepath.Join(dir, "envscript.sh")
	if err := os.WriteFile(script, []byte("#!/usr/bin/env sh\necho hello\n"), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")

	cmd := testMCPRoot()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"mcp", "integrity", "manifest", "generate", "--output", manifestPath, "--", script})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("generate: %v", err)
	}

	manifest, err := mcpintegrity.LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	resolvedScript, err := filepath.EvalSymlinks(script)
	if err != nil {
		t.Fatalf("resolve script: %v", err)
	}
	if _, ok := manifest.Entries[resolvedScript]; !ok {
		t.Fatalf("manifest missing script entry %q: %+v", resolvedScript, manifest.Entries)
	}
	// At least 2 entries: the resolved shebang interpreter + the script.
	if len(manifest.Entries) < 2 {
		t.Fatalf("expected interpreter + script pinned, got %d entries: %+v", len(manifest.Entries), manifest.Entries)
	}

	verifyCmd := testMCPRoot()
	verifyCmd.SetOut(&bytes.Buffer{})
	verifyCmd.SetArgs([]string{"mcp", "integrity", "manifest", "verify", "--manifest", manifestPath, "--", script})
	if err := verifyCmd.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
