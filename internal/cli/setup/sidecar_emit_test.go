// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func mustPatchResult(t *testing.T, opts sidecarOptions) *sidecarPatchResult {
	t.Helper()

	manifest, err := detectWorkload(testdataPath(t, "deployment.yaml"))
	if err != nil {
		t.Fatalf("detectWorkload: %v", err)
	}
	result, err := generateSidecarPatch(manifest, opts)
	if err != nil {
		t.Fatalf("generateSidecarPatch: %v", err)
	}
	return result
}

func TestParseImageRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ref     string
		wantRep string
		wantTag string
		wantDig string
	}{
		{name: "ghcr with version tag", ref: "ghcr.io/luckypipewrench/pipelock:v2.1.2", wantRep: "ghcr.io/luckypipewrench/pipelock", wantTag: "v2.1.2"},
		{name: "custom registry with latest", ref: "myregistry.com/pipelock:latest", wantRep: "myregistry.com/pipelock", wantTag: "latest"},
		{name: "bare image no tag", ref: "pipelock", wantRep: "pipelock", wantTag: "latest"},
		{name: "custom registry with sha256 tag", ref: "myregistry.com/pipelock:sha256-abc", wantRep: "myregistry.com/pipelock", wantTag: "sha256-abc"},
		{name: "nested path with tag", ref: "registry.example.com/org/sub/pipelock:v1.0.0", wantRep: "registry.example.com/org/sub/pipelock", wantTag: "v1.0.0"},
		{name: "port in registry with tag", ref: "localhost:5000/pipelock:dev", wantRep: "localhost:5000/pipelock", wantTag: "dev"},
		{name: "image with only registry no tag", ref: "myregistry.com/pipelock", wantRep: "myregistry.com/pipelock", wantTag: "latest"},
		{name: "digest reference", ref: "ghcr.io/luckypipewrench/pipelock@sha256:deadbeef", wantRep: "ghcr.io/luckypipewrench/pipelock", wantDig: "sha256:deadbeef"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseImageRef(tc.ref)
			if got.Repository != tc.wantRep {
				t.Fatalf("parseImageRef(%q) repo = %q, want %q", tc.ref, got.Repository, tc.wantRep)
			}
			if got.Tag != tc.wantTag {
				t.Fatalf("parseImageRef(%q) tag = %q, want %q", tc.ref, got.Tag, tc.wantTag)
			}
			if got.Digest != tc.wantDig {
				t.Fatalf("parseImageRef(%q) digest = %q, want %q", tc.ref, got.Digest, tc.wantDig)
			}
		})
	}
}

func TestWriteOutput_File(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "output.yaml")
	content := []byte("test-content\n")

	if err := writeOutput(nil, content, outPath, false); err != nil {
		t.Fatalf("writeOutput: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if string(data) != string(content) {
		t.Fatalf("file content = %q, want %q", string(data), string(content))
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file permission = %o, want 600", perm)
	}
}

func TestWriteOutput_Stdout(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	content := []byte("stdout-content\n")
	if err := writeOutput(&buf, content, "", false); err != nil {
		t.Fatalf("writeOutput to stdout: %v", err)
	}
	if buf.String() != string(content) {
		t.Fatalf("stdout content = %q, want %q", buf.String(), string(content))
	}
}

func TestWriteOutput_NoOverwrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "existing.yaml")
	if err := os.WriteFile(outPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("writing seed file: %v", err)
	}

	err := writeOutput(nil, []byte("new-content"), outPath, false)
	if err == nil {
		t.Fatal("expected error when file exists and force=false")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error should contain 'already exists', got: %s", err.Error())
	}
}

func TestWriteOutput_ForceOverwrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "existing.yaml")
	if err := os.WriteFile(outPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("writing seed file: %v", err)
	}

	if err := writeOutput(nil, []byte("overwritten-content"), outPath, true); err != nil {
		t.Fatalf("writeOutput with force: %v", err)
	}
	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	if string(data) != "overwritten-content" {
		t.Fatalf("file content = %q, want overwritten-content", string(data))
	}
}

func TestWriteOutput_CreatesParentDirs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "nested", "deep", "output.yaml")
	if err := writeOutput(nil, []byte("nested"), outPath, false); err != nil {
		t.Fatalf("writeOutput: %v", err)
	}
	if _, err := os.Stat(outPath); os.IsNotExist(err) {
		t.Fatal("output file was not created")
	}
}

func TestEmitPatchFormat(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "patch-output.yaml")
	result := mustPatchResult(t, sidecarOptions{preset: config.ModeBalanced})

	if err := emitPatchFormat(nil, result, sidecarOptions{output: outPath, emit: emitPatch}); err != nil {
		t.Fatalf("emitPatchFormat: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	content := string(data)

	if docSeparatorCount := strings.Count(content, "---"); docSeparatorCount < 6 {
		t.Fatalf("expected at least 6 document separators, got %d", docSeparatorCount)
	}
	for _, needle := range []string{"kind: Deployment", "kind: ConfigMap", "kind: Service", "kind: NetworkPolicy", "kind: PodDisruptionBudget"} {
		if !strings.Contains(content, needle) {
			t.Fatalf("output should contain %q", needle)
		}
	}
}

func TestEmitKustomizeFormat(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outDir := filepath.Join(dir, "kustomize-output")
	result := mustPatchResult(t, sidecarOptions{preset: config.ModeBalanced})

	if err := emitKustomizeFormat(result, sidecarOptions{output: outDir, emit: emitKustomize}); err != nil {
		t.Fatalf("emitKustomizeFormat: %v", err)
	}

	expectedFiles := []string{
		"kustomization.yaml",
		"agent-workload.yaml",
		"pipelock-configmap.yaml",
		"pipelock-deployment.yaml",
		"pipelock-service.yaml",
		"agent-networkpolicy.yaml",
		"pipelock-networkpolicy.yaml",
		"pipelock-pdb.yaml",
	}
	for _, name := range expectedFiles {
		path := filepath.Join(outDir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if info.Size() == 0 {
			t.Fatalf("file %s is empty", name)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("file %s permission = %o, want 600", name, perm)
		}
	}

	kustomData, err := os.ReadFile(filepath.Clean(filepath.Join(outDir, "kustomization.yaml")))
	if err != nil {
		t.Fatalf("reading kustomization.yaml: %v", err)
	}
	var kustomization map[string]interface{}
	if err := yaml.Unmarshal(kustomData, &kustomization); err != nil {
		t.Fatalf("parsing kustomization.yaml: %v", err)
	}
	resources, ok := kustomization["resources"].([]interface{})
	if !ok {
		t.Fatal("kustomization resources should be a list")
	}
	wantResources := map[string]bool{
		"agent-workload.yaml":         false,
		"pipelock-configmap.yaml":     false,
		"pipelock-deployment.yaml":    false,
		"pipelock-service.yaml":       false,
		"agent-networkpolicy.yaml":    false,
		"pipelock-networkpolicy.yaml": false,
		"pipelock-pdb.yaml":           false,
	}
	for _, resource := range resources {
		name, _ := resource.(string)
		if _, ok := wantResources[name]; ok {
			wantResources[name] = true
		}
	}
	for name, found := range wantResources {
		if !found {
			t.Fatalf("kustomization resources missing %s", name)
		}
	}
}

func TestEmitKustomizeFormat_EmptyOutputDir(t *testing.T) {
	t.Parallel()

	result := mustPatchResult(t, sidecarOptions{preset: config.ModeBalanced})
	err := emitKustomizeFormat(result, sidecarOptions{output: "", emit: emitKustomize})
	if err == nil {
		t.Fatal("expected error for empty output directory")
	}
	if !strings.Contains(err.Error(), "--output directory required") {
		t.Fatalf("error should mention required output, got: %s", err.Error())
	}
}

func TestEmitKustomizeFormat_NoOverwriteWithoutForce(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outDir := filepath.Join(dir, "kustomize-output")
	result := mustPatchResult(t, sidecarOptions{preset: config.ModeBalanced})

	if err := emitKustomizeFormat(result, sidecarOptions{output: outDir, emit: emitKustomize}); err != nil {
		t.Fatalf("first emitKustomizeFormat: %v", err)
	}
	err := emitKustomizeFormat(result, sidecarOptions{output: outDir, emit: emitKustomize})
	if err == nil {
		t.Fatal("expected overwrite error on second emit without --force")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected already exists error, got: %v", err)
	}
}

func TestEmitHelmValuesFormat(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outDir := filepath.Join(dir, "helm-bundle")
	result := mustPatchResult(t, sidecarOptions{preset: config.ModeBalanced})

	if err := emitHelmValuesFormat(nil, result, sidecarOptions{output: outDir, emit: emitHelmValues, preset: config.ModeBalanced}); err != nil {
		t.Fatalf("emitHelmValuesFormat: %v", err)
	}

	for _, name := range []string{"values.yaml", "agent-workload.yaml", "agent-networkpolicy.yaml", "pipelock-networkpolicy.yaml", "pipelock-pdb.yaml", "README.txt"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("expected file %s: %v", name, err)
		}
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(outDir, "values.yaml")))
	if err != nil {
		t.Fatalf("reading values.yaml: %v", err)
	}
	if !strings.Contains(string(data), "Pipelock Helm bundle values") {
		t.Fatal("values.yaml should contain the bundle header comment")
	}

	var values map[string]interface{}
	if err := yaml.Unmarshal(data, &values); err != nil {
		t.Fatalf("parsing helm values: %v", err)
	}
	if values["fullnameOverride"] != result.ProxyName {
		t.Fatalf("fullnameOverride = %v, want %q", values["fullnameOverride"], result.ProxyName)
	}
	if values["replicaCount"] != proxyReplicaCount {
		t.Fatalf("replicaCount = %v, want %d", values["replicaCount"], proxyReplicaCount)
	}

	imgMap := values["image"].(map[string]interface{})
	if imgMap["repository"] != defaultImageRepo {
		t.Fatalf("image.repository = %v, want %s", imgMap["repository"], defaultImageRepo)
	}
	if imgMap["tag"] != cliutil.Version {
		t.Fatalf("image.tag = %v, want %s", imgMap["tag"], cliutil.Version)
	}
	if imgMap["digest"] != "" {
		t.Fatalf("image.digest = %v, want empty string", imgMap["digest"])
	}
	if imgMap["pullPolicy"] != "IfNotPresent" {
		t.Fatalf("image.pullPolicy = %v, want IfNotPresent", imgMap["pullPolicy"])
	}

	resources := values["resources"].(map[string]interface{})
	requests := resources["requests"].(map[string]interface{})
	limits := resources["limits"].(map[string]interface{})
	if requests["cpu"] != proxyCPURequest || requests["memory"] != proxyMemoryRequest {
		t.Fatalf("requests = %v, want cpu=%s memory=%s", requests, proxyCPURequest, proxyMemoryRequest)
	}
	if limits["cpu"] != proxyCPULimit || limits["memory"] != proxyMemoryLimit {
		t.Fatalf("limits = %v, want cpu=%s memory=%s", limits, proxyCPULimit, proxyMemoryLimit)
	}
	if _, ok := values["affinity"].(map[string]interface{}); !ok {
		t.Fatal("values.yaml should include affinity")
	}
	podLabels := values["podLabels"].(map[string]interface{})
	if podLabels["app.kubernetes.io/component"] != "proxy" {
		t.Fatalf("podLabels.component = %v, want proxy", podLabels["app.kubernetes.io/component"])
	}

	plMap := values["pipelock"].(map[string]interface{})
	if plMap["mode"] != config.ModeBalanced {
		t.Fatalf("pipelock.mode = %v, want %s", plMap["mode"], config.ModeBalanced)
	}
	if plMap["default_agent_identity"] != result.AgentIdentity {
		t.Fatalf("pipelock.default_agent_identity = %v, want %q", plMap["default_agent_identity"], result.AgentIdentity)
	}
	if bind, _ := plMap["bind_default_agent_identity"].(bool); !bind {
		t.Fatalf("pipelock.bind_default_agent_identity = %v, want true", plMap["bind_default_agent_identity"])
	}
	forwardProxy := plMap["forward_proxy"].(map[string]interface{})
	if enabled, _ := forwardProxy["enabled"].(bool); !enabled {
		t.Fatal("pipelock.forward_proxy.enabled should be true")
	}

	readme, err := os.ReadFile(filepath.Clean(filepath.Join(outDir, "README.txt")))
	if err != nil {
		t.Fatalf("reading README.txt: %v", err)
	}
	if !strings.Contains(string(readme), "helm upgrade --install") {
		t.Fatal("README.txt should contain install instructions")
	}
	if !strings.Contains(string(readme), "kubectl rollout status deployment/") {
		t.Fatal("README.txt should include rollout status guidance")
	}
	if !strings.Contains(string(readme), "pipelock-pdb.yaml") {
		t.Fatal("README.txt should include the PDB apply command")
	}
}

func TestEmitHelmValuesFormat_CustomImage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outDir := filepath.Join(dir, "helm-custom")
	result := mustPatchResult(t, sidecarOptions{
		preset: config.ModeStrict,
		image:  "registry.example.com/pipelock:v1.2.3",
	})

	if err := emitHelmValuesFormat(nil, result, sidecarOptions{
		output: outDir,
		emit:   emitHelmValues,
		preset: config.ModeStrict,
		image:  "registry.example.com/pipelock:v1.2.3",
	}); err != nil {
		t.Fatalf("emitHelmValuesFormat: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(outDir, "values.yaml")))
	if err != nil {
		t.Fatalf("reading values.yaml: %v", err)
	}
	var values map[string]interface{}
	if err := yaml.Unmarshal(data, &values); err != nil {
		t.Fatalf("parsing helm values: %v", err)
	}
	imgMap := values["image"].(map[string]interface{})
	if imgMap["repository"] != "registry.example.com/pipelock" {
		t.Fatalf("image.repository = %v, want registry.example.com/pipelock", imgMap["repository"])
	}
	if imgMap["tag"] != "v1.2.3" {
		t.Fatalf("image.tag = %v, want v1.2.3", imgMap["tag"])
	}
	if imgMap["digest"] != "" {
		t.Fatalf("image.digest = %v, want empty string", imgMap["digest"])
	}
}

func TestEmitHelmValuesFormat_DigestImage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outDir := filepath.Join(dir, "helm-digest")
	result := mustPatchResult(t, sidecarOptions{
		preset: config.ModeStrict,
		image:  "ghcr.io/luckypipewrench/pipelock@sha256:deadbeef",
	})

	if err := emitHelmValuesFormat(nil, result, sidecarOptions{
		output: outDir,
		emit:   emitHelmValues,
		preset: config.ModeStrict,
		image:  "ghcr.io/luckypipewrench/pipelock@sha256:deadbeef",
	}); err != nil {
		t.Fatalf("emitHelmValuesFormat: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(outDir, "values.yaml")))
	if err != nil {
		t.Fatalf("reading values.yaml: %v", err)
	}
	var values map[string]interface{}
	if err := yaml.Unmarshal(data, &values); err != nil {
		t.Fatalf("parsing helm values: %v", err)
	}
	imgMap := values["image"].(map[string]interface{})
	if imgMap["repository"] != "ghcr.io/luckypipewrench/pipelock" {
		t.Fatalf("image.repository = %v, want ghcr.io/luckypipewrench/pipelock", imgMap["repository"])
	}
	if imgMap["digest"] != "sha256:deadbeef" {
		t.Fatalf("image.digest = %v, want sha256:deadbeef", imgMap["digest"])
	}
	if imgMap["tag"] != "" {
		t.Fatalf("image.tag = %v, want empty string", imgMap["tag"])
	}
}

func TestEmitPatched_UnknownFormat(t *testing.T) {
	t.Parallel()

	err := emitPatched(nil, mustPatchResult(t, sidecarOptions{preset: config.ModeBalanced}), sidecarOptions{emit: "unknown-format"})
	if err == nil {
		t.Fatal("expected error for unknown emit format")
	}
	if !strings.Contains(err.Error(), "unknown emit format") {
		t.Fatalf("error should mention unknown format, got: %s", err.Error())
	}
}
