// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSidecar_DryRun(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--dry-run",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Verify all 7 phase markers appear.
	for i := 1; i <= 7; i++ {
		marker := "[" + itoa(i) + "/7]"
		if !strings.Contains(output, marker) {
			t.Errorf("output should contain phase marker %s", marker)
		}
	}

	// Verify dry-run message.
	if !strings.Contains(output, "Dry run") {
		t.Errorf("output should contain 'Dry run', got:\n%s", output)
	}

	// Verify diff preview section is present.
	if !strings.Contains(output, "Diff preview") {
		t.Errorf("output should contain 'Diff preview', got:\n%s", output)
	}
}

func TestRunSidecar_JSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--dry-run",
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result sidecarResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}

	if result.Detect == nil {
		t.Fatal("detect field should not be nil")
	}
	if result.Detect.Kind != kindDeployment {
		t.Errorf("detect.kind = %q, want %q", result.Detect.Kind, kindDeployment)
	}
	if result.Detect.Name != "my-agent" {
		t.Errorf("detect.name = %q, want %q", result.Detect.Name, "my-agent")
	}

	if result.Patch == nil {
		t.Fatal("patch field should not be nil")
	}
	if !result.Patch.DryRun {
		t.Error("patch.dry_run should be true")
	}
	if result.Patch.EmitFormat != emitPatch {
		t.Errorf("patch.emit_format = %q, want %q", result.Patch.EmitFormat, emitPatch)
	}
}

func TestRunSidecar_AllKinds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		file     string
		wantKind string
		wantName string
	}{
		{
			name:     "deployment",
			file:     "deployment.yaml",
			wantKind: kindDeployment,
			wantName: "my-agent",
		},
		{
			name:     "statefulset",
			file:     "statefulset.yaml",
			wantKind: kindStatefulSet,
			wantName: "my-db-agent",
		},
		{
			name:     "job",
			file:     "job.yaml",
			wantKind: kindJob,
			wantName: "batch-runner",
		},
		{
			name:     "cronjob",
			file:     "cronjob.yaml",
			wantKind: kindCronJob,
			wantName: "scheduled-scan",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			cmd := SidecarCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{
				"--inject-spec", testdataPath(t, tc.file),
				"--dry-run",
				"--json",
			})

			if err := cmd.Execute(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var result sidecarResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
			}

			if result.Detect.Kind != tc.wantKind {
				t.Errorf("detect.kind = %q, want %q", result.Detect.Kind, tc.wantKind)
			}
			if result.Detect.Name != tc.wantName {
				t.Errorf("detect.name = %q, want %q", result.Detect.Name, tc.wantName)
			}
		})
	}
}

func TestRunSidecar_EmitPatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "patched.yaml")

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--output", outPath,
		"--skip-canary",
		"--skip-verify",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify file was written.
	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if len(data) == 0 {
		t.Error("output file is empty")
	}

	// Verify it contains multi-document YAML.
	if !strings.Contains(string(data), "---") {
		t.Error("output should contain YAML document separator")
	}
}

func TestRunSidecar_Idempotent(t *testing.T) {
	t.Parallel()

	// First pass: generate a patched manifest.
	dir := t.TempDir()
	patchedPath := filepath.Join(dir, "patched.yaml")

	var buf1 bytes.Buffer
	cmd1 := SidecarCmd()
	cmd1.SetOut(&buf1)
	cmd1.SetErr(&buf1)
	cmd1.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--output", patchedPath,
		"--skip-canary",
		"--skip-verify",
	})

	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first run: %v", err)
	}

	// Second pass: run against the already-patched manifest with JSON output.
	var buf2 bytes.Buffer
	cmd2 := SidecarCmd()
	cmd2.SetOut(&buf2)
	cmd2.SetErr(&buf2)
	cmd2.SetArgs([]string{
		"--inject-spec", patchedPath,
		"--dry-run",
		"--json",
	})

	if err := cmd2.Execute(); err != nil {
		t.Fatalf("second run: %v", err)
	}

	var result sidecarResult
	if err := json.Unmarshal(buf2.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf2.String())
	}

	if !result.Detect.AlreadyPatched {
		t.Error("second run should detect already_patched=true")
	}
}

func TestRunSidecar_CanaryDetection(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--output", filepath.Join(t.TempDir(), "out.yaml"),
		"--skip-verify",
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result sidecarResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	if result.Canary == nil {
		t.Fatal("canary field should not be nil")
	}
	if !result.Canary.Detected {
		t.Error("canary.detected should be true (DLP should catch the synthetic secret)")
	}
}

func TestRunSidecar_InvalidPreset(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--preset", "bogus",
		"--dry-run",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid preset")
	}
}

func TestRunSidecar_InvalidEmitFormat(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--emit", "bad-format",
		"--dry-run",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid emit format")
	}
}

func TestRunSidecar_MissingInjectSpec(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--dry-run"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing --inject-spec")
	}
}

func TestRunSidecar_EmitKustomize(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outDir := filepath.Join(dir, "kustomize-out")

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--emit", "kustomize",
		"--output", outDir,
		"--skip-canary",
		"--skip-verify",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify kustomize files exist.
	for _, name := range []string{
		"kustomization.yaml",
		"workload.yaml",
		"pipelock-sidecar-patch.yaml",
		"pipelock-configmap.yaml",
		"pipelock-networkpolicy.yaml",
	} {
		path := filepath.Join(outDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file %s not created", name)
		}
	}
}

func TestRunSidecar_JSONRequiresOutputWhenEmitting(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--json",
		"--skip-canary",
		"--skip-verify",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --json emits to stdout without --output")
	}
	if !strings.Contains(err.Error(), "--json requires --output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunSidecar_EmitHelmValues(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "values.yaml")

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--emit", "helm-values",
		"--output", outPath,
		"--skip-canary",
		"--skip-verify",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	if !strings.Contains(string(data), "Helm chart values") {
		t.Error("output should contain Helm header comment")
	}
}

func TestRunSidecar_SkipCanary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--dry-run",
		"--skip-canary",
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result sidecarResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	if result.Canary == nil {
		t.Fatal("canary field should not be nil")
	}
	if !result.Canary.Skipped {
		t.Error("canary.skipped should be true with --skip-canary")
	}
}

func TestRunSidecar_CustomAgentIdentity(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--dry-run",
		"--json",
		"--agent-identity", "team/custom-bot",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result sidecarResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	if result.Patch.AgentIdentity != "team/custom-bot" {
		t.Errorf("agent_identity = %q, want %q", result.Patch.AgentIdentity, "team/custom-bot")
	}
}

// itoa is a minimal int-to-string without importing strconv (keeps imports lean).
func itoa(n int) string {
	if n < 0 {
		return "-" + itoa(-n)
	}
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}
