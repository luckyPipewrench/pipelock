// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestGenerateSidecarPatch_Deployment(t *testing.T) {
	manifest, err := detectWorkload(testdataPath(t, "deployment.yaml"))
	if err != nil {
		t.Fatalf("detectWorkload: %v", err)
	}

	opts := sidecarOptions{
		preset: config.ModeBalanced,
	}

	result, err := generateSidecarPatch(manifest, opts)
	if err != nil {
		t.Fatalf("generateSidecarPatch: %v", err)
	}

	// Verify 2 containers in patched manifest.
	podSpec, err := getPodSpec(result.PatchedManifest, kindDeployment)
	if err != nil {
		t.Fatalf("getPodSpec on patched: %v", err)
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		t.Fatal("containers not found in patched pod spec")
	}
	if len(containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(containers))
	}

	// Second container should be named "pipelock".
	second, ok := containers[1].(map[string]interface{})
	if !ok {
		t.Fatal("second container is not a map")
	}
	if name, _ := second["name"].(string); name != sidecarContainerName {
		t.Errorf("second container name = %q, want %q", name, sidecarContainerName)
	}

	// First container should have proxy env vars.
	first, ok := containers[0].(map[string]interface{})
	if !ok {
		t.Fatal("first container is not a map")
	}
	envList, ok := first["env"].([]interface{})
	if !ok {
		t.Fatal("first container has no env list")
	}

	wantEnvNames := []string{envHTTPSProxy, envHTTPProxy, envNoProxy}
	for _, wantName := range wantEnvNames {
		if !hasEnvVar(envList, wantName) {
			t.Errorf("first container missing env var %s", wantName)
		}
	}

	// Volumes should include pipelock-config.
	volumes, ok := podSpec["volumes"].([]interface{})
	if !ok {
		t.Fatal("volumes not found in patched pod spec")
	}
	foundVol := false
	for _, v := range volumes {
		vMap, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		if n, _ := vMap["name"].(string); n == sidecarConfigVolume {
			foundVol = true
			break
		}
	}
	if !foundVol {
		t.Errorf("expected volume %q in patched manifest", sidecarConfigVolume)
	}

	// ConfigMapYAML should be non-empty.
	if result.ConfigMapYAML == "" {
		t.Error("ConfigMapYAML should not be empty")
	}

	// NetworkPolicyYAML should be non-empty.
	if result.NetworkPolicyYAML == "" {
		t.Error("NetworkPolicyYAML should not be empty")
	}
	var networkPolicy map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.NetworkPolicyYAML), &networkPolicy); err != nil {
		t.Fatalf("parsing NetworkPolicyYAML: %v", err)
	}
	spec, ok := networkPolicy["spec"].(map[string]interface{})
	if !ok {
		t.Fatal("network policy spec should be a map")
	}
	podSelector, ok := spec["podSelector"].(map[string]interface{})
	if !ok {
		t.Fatal("network policy podSelector should be a map")
	}
	matchLabels, ok := podSelector["matchLabels"].(map[string]interface{})
	if !ok {
		t.Fatal("network policy matchLabels should be a map")
	}
	if matchLabels["app"] != "my-agent" {
		t.Fatalf("network policy selector = %v, want app=my-agent", matchLabels)
	}
	egress, ok := spec["egress"].([]interface{})
	if !ok || len(egress) != 2 {
		t.Fatalf("network policy egress = %v, want 2 rules", spec["egress"])
	}

	// AgentIdentity should be "deployment/my-agent".
	wantIdentity := "deployment/my-agent"
	if result.AgentIdentity != wantIdentity {
		t.Errorf("AgentIdentity = %q, want %q", result.AgentIdentity, wantIdentity)
	}
}

func TestGenerateSidecarPatch_Idempotent(t *testing.T) {
	manifest, err := detectWorkload(testdataPath(t, "deployment.yaml"))
	if err != nil {
		t.Fatalf("detectWorkload: %v", err)
	}

	opts := sidecarOptions{
		preset: config.ModeBalanced,
	}

	// First patch.
	first, err := generateSidecarPatch(manifest, opts)
	if err != nil {
		t.Fatalf("first generateSidecarPatch: %v", err)
	}

	// Build a new workloadManifest from the patched result.
	patchedManifest := &workloadManifest{
		Kind: manifest.Kind,
		Name: manifest.Name,
		Raw:  first.PatchedManifest,
	}

	// Second patch on already-patched manifest.
	second, err := generateSidecarPatch(patchedManifest, opts)
	if err != nil {
		t.Fatalf("second generateSidecarPatch: %v", err)
	}

	// Second run should not add duplicate containers.
	podSpec, err := getPodSpec(second.PatchedManifest, kindDeployment)
	if err != nil {
		t.Fatalf("getPodSpec on second patch: %v", err)
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		t.Fatal("containers not found")
	}

	// Should still be 2 containers, not 3.
	if len(containers) != 2 {
		t.Errorf("expected 2 containers after second patch, got %d", len(containers))
	}

	// ConfigMapYAML should be empty on idempotent run (no new artifacts).
	if second.ConfigMapYAML != "" {
		t.Error("expected empty ConfigMapYAML on idempotent patch")
	}
}

func TestGenerateSidecarPatch_AllKinds(t *testing.T) {
	tests := []struct {
		name         string
		file         string
		kind         string
		wantIdentity string
	}{
		{
			name:         "deployment",
			file:         "deployment.yaml",
			kind:         kindDeployment,
			wantIdentity: "deployment/my-agent",
		},
		{
			name:         "statefulset",
			file:         "statefulset.yaml",
			kind:         kindStatefulSet,
			wantIdentity: "statefulset/my-db-agent",
		},
		{
			name:         "job",
			file:         "job.yaml",
			kind:         kindJob,
			wantIdentity: "job/batch-runner",
		},
		{
			name:         "cronjob",
			file:         "cronjob.yaml",
			kind:         kindCronJob,
			wantIdentity: "cronjob/scheduled-scan",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest, err := detectWorkload(testdataPath(t, tc.file))
			if err != nil {
				t.Fatalf("detectWorkload: %v", err)
			}

			opts := sidecarOptions{
				preset: config.ModeBalanced,
			}

			result, err := generateSidecarPatch(manifest, opts)
			if err != nil {
				t.Fatalf("generateSidecarPatch: %v", err)
			}

			// Verify sidecar container was added.
			podSpec, err := getPodSpec(result.PatchedManifest, tc.kind)
			if err != nil {
				t.Fatalf("getPodSpec: %v", err)
			}
			if !hasPipelockContainer(podSpec) {
				t.Error("patched manifest should have pipelock container")
			}

			// Verify identity derivation.
			if result.AgentIdentity != tc.wantIdentity {
				t.Errorf("AgentIdentity = %q, want %q", result.AgentIdentity, tc.wantIdentity)
			}

			// Verify artifacts were generated.
			if result.ConfigMapYAML == "" {
				t.Error("ConfigMapYAML should not be empty")
			}
			if result.NetworkPolicyYAML == "" {
				t.Error("NetworkPolicyYAML should not be empty")
			}
		})
	}
}

func TestGenerateSidecarPatch_CustomImage(t *testing.T) {
	manifest, err := detectWorkload(testdataPath(t, "deployment.yaml"))
	if err != nil {
		t.Fatalf("detectWorkload: %v", err)
	}

	const customImage = "registry.example.com/pipelock:v1.2.3"
	opts := sidecarOptions{
		preset: config.ModeBalanced,
		image:  customImage,
	}

	result, err := generateSidecarPatch(manifest, opts)
	if err != nil {
		t.Fatalf("generateSidecarPatch: %v", err)
	}

	podSpec, err := getPodSpec(result.PatchedManifest, kindDeployment)
	if err != nil {
		t.Fatalf("getPodSpec: %v", err)
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		t.Fatal("containers not found")
	}

	// Find the pipelock container and check its image.
	for _, c := range containers {
		cMap, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := cMap["name"].(string)
		if name == sidecarContainerName {
			img, _ := cMap["image"].(string)
			if img != customImage {
				t.Errorf("sidecar image = %q, want %q", img, customImage)
			}
			return
		}
	}
	t.Fatal("pipelock sidecar container not found in patched manifest")
}

func TestGenerateSidecarPatch_CustomIdentity(t *testing.T) {
	manifest, err := detectWorkload(testdataPath(t, "deployment.yaml"))
	if err != nil {
		t.Fatalf("detectWorkload: %v", err)
	}

	const customIdentity = "team-alpha/my-custom-agent"
	opts := sidecarOptions{
		preset:        config.ModeBalanced,
		agentIdentity: customIdentity,
	}

	result, err := generateSidecarPatch(manifest, opts)
	if err != nil {
		t.Fatalf("generateSidecarPatch: %v", err)
	}

	if result.AgentIdentity != customIdentity {
		t.Errorf("AgentIdentity = %q, want %q", result.AgentIdentity, customIdentity)
	}
}

func TestResolveImage(t *testing.T) {
	tests := []struct {
		name      string
		image     string
		wantImage string
	}{
		{
			name:      "default image uses version",
			image:     "",
			wantImage: fmt.Sprintf("%s:%s", defaultImageRepo, cliutil.Version),
		},
		{
			name:      "custom image override",
			image:     "my-registry.io/pipelock:custom",
			wantImage: "my-registry.io/pipelock:custom",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := sidecarOptions{image: tc.image}
			got := resolveImage(opts)
			if got != tc.wantImage {
				t.Errorf("resolveImage() = %q, want %q", got, tc.wantImage)
			}
		})
	}
}

func TestResolveAgentIdentity_Sidecar(t *testing.T) {
	tests := []struct {
		name          string
		kind          string
		workloadName  string
		agentIdentity string
		want          string
	}{
		{
			name:         "derived from deployment",
			kind:         kindDeployment,
			workloadName: "my-agent",
			want:         "deployment/my-agent",
		},
		{
			name:         "derived from statefulset",
			kind:         kindStatefulSet,
			workloadName: "my-db",
			want:         "statefulset/my-db",
		},
		{
			name:         "derived from job",
			kind:         kindJob,
			workloadName: "runner",
			want:         "job/runner",
		},
		{
			name:         "derived from cronjob",
			kind:         kindCronJob,
			workloadName: "scanner",
			want:         "cronjob/scanner",
		},
		{
			name:          "custom identity overrides derivation",
			kind:          kindDeployment,
			workloadName:  "my-agent",
			agentIdentity: "custom/override",
			want:          "custom/override",
		},
		{
			name:         "empty workload name",
			kind:         kindDeployment,
			workloadName: "",
			want:         "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := &workloadManifest{
				Kind: tc.kind,
				Name: tc.workloadName,
			}
			opts := sidecarOptions{
				agentIdentity: tc.agentIdentity,
			}
			got := resolveAgentIdentity(manifest, opts)
			if got != tc.want {
				t.Errorf("resolveAgentIdentity() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNetworkPolicySelectorLabels_UsesSelectorMatchLabels(t *testing.T) {
	raw := map[string]interface{}{
		"spec": map[string]interface{}{
			"selector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app.kubernetes.io/name": "agent",
					"tier":                   "prod",
				},
			},
			"template": map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": map[string]interface{}{
						"ignored": "value",
					},
				},
			},
		},
	}

	got, err := networkPolicySelectorLabels(raw, kindDeployment)
	if err != nil {
		t.Fatalf("networkPolicySelectorLabels: %v", err)
	}
	if got["app.kubernetes.io/name"] != "agent" || got["tier"] != "prod" {
		t.Fatalf("selector labels = %v, want selector.matchLabels", got)
	}
}

func TestNetworkPolicySelectorLabels_FallsBackToTemplateLabels(t *testing.T) {
	raw := map[string]interface{}{
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": map[string]interface{}{
						"job-name": "nightly",
					},
				},
			},
		},
	}

	got, err := networkPolicySelectorLabels(raw, kindJob)
	if err != nil {
		t.Fatalf("networkPolicySelectorLabels: %v", err)
	}
	if got["job-name"] != "nightly" {
		t.Fatalf("selector labels = %v, want template labels", got)
	}
}

func TestRenderNetworkPolicy_EmptySelectorError(t *testing.T) {
	if _, err := renderNetworkPolicy("default", "agent", nil); err == nil {
		t.Fatal("expected error for empty selector labels")
	}
}
