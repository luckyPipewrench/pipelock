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

func TestParseImageRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ref     string
		wantRep string
		wantTag string
		wantDig string
	}{
		{
			name:    "ghcr with version tag",
			ref:     "ghcr.io/luckypipewrench/pipelock:v2.1.2",
			wantRep: "ghcr.io/luckypipewrench/pipelock",
			wantTag: "v2.1.2",
		},
		{
			name:    "custom registry with latest",
			ref:     "myregistry.com/pipelock:latest",
			wantRep: "myregistry.com/pipelock",
			wantTag: "latest",
		},
		{
			name:    "bare image no tag",
			ref:     "pipelock",
			wantRep: "pipelock",
			wantTag: "latest",
		},
		{
			name:    "custom registry with sha256 tag",
			ref:     "myregistry.com/pipelock:sha256-abc",
			wantRep: "myregistry.com/pipelock",
			wantTag: "sha256-abc",
		},
		{
			name:    "nested path with tag",
			ref:     "registry.example.com/org/sub/pipelock:v1.0.0",
			wantRep: "registry.example.com/org/sub/pipelock",
			wantTag: "v1.0.0",
		},
		{
			name:    "port in registry with tag",
			ref:     "localhost:5000/pipelock:dev",
			wantRep: "localhost:5000/pipelock",
			wantTag: "dev",
		},
		{
			name:    "image with only registry no tag",
			ref:     "myregistry.com/pipelock",
			wantRep: "myregistry.com/pipelock",
			wantTag: "latest",
		},
		{
			name:    "digest reference",
			ref:     "ghcr.io/luckypipewrench/pipelock@sha256:deadbeef",
			wantRep: "ghcr.io/luckypipewrench/pipelock",
			wantDig: "sha256:deadbeef",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseImageRef(tc.ref)
			if got.Repository != tc.wantRep {
				t.Errorf("parseImageRef(%q) repo = %q, want %q", tc.ref, got.Repository, tc.wantRep)
			}
			if got.Tag != tc.wantTag {
				t.Errorf("parseImageRef(%q) tag = %q, want %q", tc.ref, got.Tag, tc.wantTag)
			}
			if got.Digest != tc.wantDig {
				t.Errorf("parseImageRef(%q) digest = %q, want %q", tc.ref, got.Digest, tc.wantDig)
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
		t.Errorf("file content = %q, want %q", string(data), string(content))
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file permission = %o, want 600", perm)
	}
}

func TestWriteOutput_Stdout(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	content := []byte("stdout-content\n")
	err := writeOutput(&buf, content, "", false)
	if err != nil {
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

	// Create an existing file.
	if err := os.WriteFile(outPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("writing seed file: %v", err)
	}

	err := writeOutput(nil, []byte("new-content"), outPath, false)
	if err == nil {
		t.Fatal("expected error when file exists and force=false")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should contain 'already exists', got: %s", err.Error())
	}

	// Verify original content is preserved.
	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	if string(data) != "original" {
		t.Errorf("original file was modified: got %q", string(data))
	}
}

func TestWriteOutput_ForceOverwrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "existing.yaml")

	// Create an existing file.
	if err := os.WriteFile(outPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("writing seed file: %v", err)
	}

	newContent := []byte("overwritten-content")
	if err := writeOutput(nil, newContent, outPath, true); err != nil {
		t.Fatalf("writeOutput with force: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	if string(data) != string(newContent) {
		t.Errorf("file content = %q, want %q", string(data), string(newContent))
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
		t.Error("output file was not created")
	}
}

func TestEmitPatchFormat(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "patch-output.yaml")

	result := &sidecarPatchResult{
		PatchedManifest: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "test-agent",
			},
			"spec": map[string]interface{}{
				"replicas": 1,
			},
		},
		ConfigMapYAML:     "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: pipelock-config\n",
		NetworkPolicyYAML: "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: test-np\n",
		AgentIdentity:     "deployment/test-agent",
	}

	opts := sidecarOptions{
		output: outPath,
		emit:   emitPatch,
	}

	if err := emitPatchFormat(nil, result, opts); err != nil {
		t.Fatalf("emitPatchFormat: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	content := string(data)

	// Verify the output contains the three YAML documents separated by "---".
	docSeparatorCount := strings.Count(content, "---")
	if docSeparatorCount < 2 {
		t.Errorf("expected at least 2 document separators, got %d", docSeparatorCount)
	}

	// Verify the patched manifest is present.
	if !strings.Contains(content, "Deployment") {
		t.Error("output should contain the Deployment kind")
	}

	// Verify ConfigMap YAML is present.
	if !strings.Contains(content, "ConfigMap") {
		t.Error("output should contain the ConfigMap")
	}

	// Verify NetworkPolicy YAML is present.
	if !strings.Contains(content, "NetworkPolicy") {
		t.Error("output should contain the NetworkPolicy")
	}
}

func TestEmitKustomizeFormat(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outDir := filepath.Join(dir, "kustomize-output")

	result := &sidecarPatchResult{
		OriginalManifestYAML: "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: test-agent\n",
		PatchedManifest: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "test-agent",
			},
		},
		ConfigMapYAML:     "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: pipelock-config\n",
		NetworkPolicyYAML: "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: test-np\n",
		AgentIdentity:     "deployment/test-agent",
	}

	opts := sidecarOptions{
		output: outDir,
		emit:   emitKustomize,
	}

	if err := emitKustomizeFormat(result, opts); err != nil {
		t.Fatalf("emitKustomizeFormat: %v", err)
	}

	// Verify all 5 expected files were created.
	expectedFiles := []string{
		"kustomization.yaml",
		"workload.yaml",
		"pipelock-sidecar-patch.yaml",
		"pipelock-configmap.yaml",
		"pipelock-networkpolicy.yaml",
	}

	for _, name := range expectedFiles {
		path := filepath.Join(outDir, name)
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			t.Errorf("expected file %s not created", name)
			continue
		}
		if err != nil {
			t.Errorf("stat %s: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", name)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("file %s permission = %o, want 600", name, perm)
		}
	}

	// Verify kustomization.yaml has expected structure.
	kustomData, err := os.ReadFile(filepath.Clean(filepath.Join(outDir, "kustomization.yaml")))
	if err != nil {
		t.Fatalf("reading kustomization.yaml: %v", err)
	}

	var kustomization map[string]interface{}
	if err := yaml.Unmarshal(kustomData, &kustomization); err != nil {
		t.Fatalf("parsing kustomization.yaml: %v", err)
	}

	if kustomization["apiVersion"] != "kustomize.config.k8s.io/v1beta1" {
		t.Errorf("kustomization apiVersion = %v, want kustomize.config.k8s.io/v1beta1",
			kustomization["apiVersion"])
	}
	if kustomization["kind"] != "Kustomization" {
		t.Errorf("kustomization kind = %v, want Kustomization", kustomization["kind"])
	}

	resources, ok := kustomization["resources"].([]interface{})
	if !ok {
		t.Fatal("kustomization resources should be a list")
	}
	foundWorkload := false
	for _, resource := range resources {
		if resource == "workload.yaml" {
			foundWorkload = true
			break
		}
	}
	if !foundWorkload {
		t.Fatal("kustomization resources should include workload.yaml")
	}
}

func TestEmitKustomizeFormat_EmptyOutputDir(t *testing.T) {
	t.Parallel()

	result := &sidecarPatchResult{
		OriginalManifestYAML: "kind: Deployment\n",
		PatchedManifest:      map[string]interface{}{"kind": "Deployment"},
	}

	opts := sidecarOptions{
		output: "",
		emit:   emitKustomize,
	}

	err := emitKustomizeFormat(result, opts)
	if err == nil {
		t.Fatal("expected error for empty output directory")
	}
	if !strings.Contains(err.Error(), "--output directory required") {
		t.Errorf("error should mention required output, got: %s", err.Error())
	}
}

func TestEmitKustomizeFormat_NoOverwriteWithoutForce(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outDir := filepath.Join(dir, "kustomize-output")
	result := &sidecarPatchResult{
		OriginalManifestYAML: "kind: Deployment\n",
		PatchedManifest:      map[string]interface{}{"kind": "Deployment"},
		ConfigMapYAML:        "kind: ConfigMap\n",
		NetworkPolicyYAML:    "kind: NetworkPolicy\n",
	}
	opts := sidecarOptions{
		output: outDir,
		emit:   emitKustomize,
	}

	if err := emitKustomizeFormat(result, opts); err != nil {
		t.Fatalf("first emitKustomizeFormat: %v", err)
	}

	err := emitKustomizeFormat(result, opts)
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
	outPath := filepath.Join(dir, "values.yaml")

	result := &sidecarPatchResult{
		PatchedManifest: map[string]interface{}{
			"kind": "Deployment",
		},
		AgentIdentity: "deployment/test-agent",
	}

	opts := sidecarOptions{
		output: outPath,
		emit:   emitHelmValues,
		preset: config.ModeBalanced,
	}

	if err := emitHelmValuesFormat(nil, result, opts); err != nil {
		t.Fatalf("emitHelmValuesFormat: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	content := string(data)

	// Verify the header comment is present.
	if !strings.Contains(content, "Pipelock Helm chart values") {
		t.Error("output should contain the Helm header comment")
	}

	// Parse the YAML (skip comment header lines).
	var values map[string]interface{}
	if err := yaml.Unmarshal(data, &values); err != nil {
		t.Fatalf("parsing helm values: %v", err)
	}

	// Verify expected top-level keys.
	if _, ok := values["image"]; !ok {
		t.Error("helm values should contain 'image' key")
	}
	if _, ok := values["pipelock"]; !ok {
		t.Error("helm values should contain 'pipelock' key")
	}
	if _, ok := values["networkPolicy"]; !ok {
		t.Error("helm values should contain 'networkPolicy' key")
	}

	// Verify image defaults.
	imgMap, ok := values["image"].(map[string]interface{})
	if !ok {
		t.Fatal("image value should be a map")
	}
	if imgMap["repository"] != defaultImageRepo {
		t.Errorf("image.repository = %v, want %s", imgMap["repository"], defaultImageRepo)
	}
	if imgMap["tag"] != cliutil.Version {
		t.Errorf("image.tag = %v, want %s", imgMap["tag"], cliutil.Version)
	}
	if imgMap["digest"] != "" {
		t.Errorf("image.digest = %v, want empty string", imgMap["digest"])
	}

	// Verify pipelock section.
	plMap, ok := values["pipelock"].(map[string]interface{})
	if !ok {
		t.Fatal("pipelock value should be a map")
	}
	if plMap["mode"] != config.ModeBalanced {
		t.Errorf("pipelock.mode = %v, want %s", plMap["mode"], config.ModeBalanced)
	}
	if plMap["default_agent_identity"] != "deployment/test-agent" {
		t.Errorf("pipelock.default_agent_identity = %v, want deployment/test-agent",
			plMap["default_agent_identity"])
	}
}

func TestEmitHelmValuesFormat_CustomImage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "values-custom.yaml")

	result := &sidecarPatchResult{
		PatchedManifest: map[string]interface{}{
			"kind": "Deployment",
		},
		AgentIdentity: "deployment/agent",
	}

	opts := sidecarOptions{
		output: outPath,
		emit:   emitHelmValues,
		preset: config.ModeStrict,
		image:  "registry.example.com/pipelock:v1.2.3",
	}

	if err := emitHelmValuesFormat(nil, result, opts); err != nil {
		t.Fatalf("emitHelmValuesFormat: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	var values map[string]interface{}
	if err := yaml.Unmarshal(data, &values); err != nil {
		t.Fatalf("parsing helm values: %v", err)
	}

	imgMap, ok := values["image"].(map[string]interface{})
	if !ok {
		t.Fatal("image value should be a map")
	}
	if imgMap["repository"] != "registry.example.com/pipelock" {
		t.Errorf("image.repository = %v, want registry.example.com/pipelock",
			imgMap["repository"])
	}
	if imgMap["tag"] != "v1.2.3" {
		t.Errorf("image.tag = %v, want v1.2.3", imgMap["tag"])
	}
	if imgMap["digest"] != "" {
		t.Errorf("image.digest = %v, want empty string", imgMap["digest"])
	}
}

func TestEmitHelmValuesFormat_DigestImage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "values-digest.yaml")

	result := &sidecarPatchResult{
		PatchedManifest: map[string]interface{}{"kind": "Deployment"},
		AgentIdentity:   "deployment/agent",
	}

	opts := sidecarOptions{
		output: outPath,
		emit:   emitHelmValues,
		preset: config.ModeStrict,
		image:  "ghcr.io/luckypipewrench/pipelock@sha256:deadbeef",
	}

	if err := emitHelmValuesFormat(nil, result, opts); err != nil {
		t.Fatalf("emitHelmValuesFormat: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	var values map[string]interface{}
	if err := yaml.Unmarshal(data, &values); err != nil {
		t.Fatalf("parsing helm values: %v", err)
	}

	imgMap, ok := values["image"].(map[string]interface{})
	if !ok {
		t.Fatal("image value should be a map")
	}
	if imgMap["repository"] != "ghcr.io/luckypipewrench/pipelock" {
		t.Errorf("image.repository = %v, want ghcr.io/luckypipewrench/pipelock", imgMap["repository"])
	}
	if imgMap["digest"] != "sha256:deadbeef" {
		t.Errorf("image.digest = %v, want sha256:deadbeef", imgMap["digest"])
	}
	if imgMap["tag"] != "" {
		t.Errorf("image.tag = %v, want empty string", imgMap["tag"])
	}
}

func TestEmitPatched_UnknownFormat(t *testing.T) {
	t.Parallel()

	result := &sidecarPatchResult{
		PatchedManifest: map[string]interface{}{"kind": "Deployment"},
	}

	opts := sidecarOptions{
		emit: "unknown-format",
	}

	err := emitPatched(nil, result, opts)
	if err == nil {
		t.Fatal("expected error for unknown emit format")
	}
	if !strings.Contains(err.Error(), "unknown emit format") {
		t.Errorf("error should mention unknown format, got: %s", err.Error())
	}
}
