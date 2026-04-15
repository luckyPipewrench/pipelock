// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func envValue(t *testing.T, envList []interface{}, name string) string {
	t.Helper()

	for _, entry := range envList {
		envMap, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		if envName, _ := envMap["name"].(string); envName == name {
			value, _ := envMap["value"].(string)
			return value
		}
	}

	t.Fatalf("env var %q not found", name)
	return ""
}

func envCount(envList []interface{}, name string) int {
	count := 0
	for _, entry := range envList {
		envMap, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		if envName, _ := envMap["name"].(string); envName == name {
			count++
		}
	}
	return count
}

func TestGenerateSidecarPatch_Deployment(t *testing.T) {
	manifest, err := detectWorkload(testdataPath(t, "deployment.yaml"))
	if err != nil {
		t.Fatalf("detectWorkload: %v", err)
	}

	opts := sidecarOptions{preset: config.ModeBalanced}
	result, err := generateSidecarPatch(manifest, opts)
	if err != nil {
		t.Fatalf("generateSidecarPatch: %v", err)
	}

	if result.ProxyName != "my-agent-pipelock" {
		t.Fatalf("ProxyName = %q, want %q", result.ProxyName, "my-agent-pipelock")
	}
	if result.ProxyURL != "http://my-agent-pipelock:8888" {
		t.Fatalf("ProxyURL = %q, want %q", result.ProxyURL, "http://my-agent-pipelock:8888")
	}

	podSpec, err := getPodSpec(result.PatchedManifest, kindDeployment)
	if err != nil {
		t.Fatalf("getPodSpec on patched: %v", err)
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		t.Fatal("containers not found in patched pod spec")
	}
	if len(containers) != 1 {
		t.Fatalf("expected 1 agent container, got %d", len(containers))
	}
	if hasPipelockContainer(podSpec) {
		t.Fatal("patched workload should not inject a same-pod pipelock container")
	}

	first, ok := containers[0].(map[string]interface{})
	if !ok {
		t.Fatal("agent container is not a map")
	}
	envList, ok := first["env"].([]interface{})
	if !ok {
		t.Fatal("agent container has no env list")
	}
	if got := envValue(t, envList, envHTTPSProxy); got != result.ProxyURL {
		t.Fatalf("%s = %q, want %q", envHTTPSProxy, got, result.ProxyURL)
	}
	if got := envValue(t, envList, envHTTPProxy); got != result.ProxyURL {
		t.Fatalf("%s = %q, want %q", envHTTPProxy, got, result.ProxyURL)
	}
	if got := envValue(t, envList, envNoProxy); got != noProxyValue {
		t.Fatalf("%s = %q, want %q", envNoProxy, got, noProxyValue)
	}

	metadata, ok := result.PatchedManifest["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata missing from patched manifest")
	}
	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata.annotations missing from patched manifest")
	}
	if annotations[managedTopologyAnnotation] != managedTopologyCompanion {
		t.Fatalf("metadata.annotations[%q] = %v, want %q", managedTopologyAnnotation, annotations[managedTopologyAnnotation], managedTopologyCompanion)
	}
	if annotations[managedProxyNameAnnotation] != result.ProxyName {
		t.Fatalf("metadata.annotations[%q] = %v, want %q", managedProxyNameAnnotation, annotations[managedProxyNameAnnotation], result.ProxyName)
	}
	if annotations[managedProxyServiceAnnotation] != result.ProxyURL {
		t.Fatalf("metadata.annotations[%q] = %v, want %q", managedProxyServiceAnnotation, annotations[managedProxyServiceAnnotation], result.ProxyURL)
	}

	for _, artifact := range []string{
		result.ConfigMapYAML,
		result.DeploymentYAML,
		result.ServiceYAML,
		result.AgentNetworkPolicyYAML,
		result.ProxyNetworkPolicyYAML,
		result.PodDisruptionBudgetYAML,
	} {
		if artifact == "" {
			t.Fatal("expected all companion artifacts to be non-empty")
		}
	}

	var deployment map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.DeploymentYAML), &deployment); err != nil {
		t.Fatalf("parsing DeploymentYAML: %v", err)
	}
	if deployment["kind"] != kindDeployment {
		t.Fatalf("deployment kind = %v, want %s", deployment["kind"], kindDeployment)
	}
	deployMeta := deployment["metadata"].(map[string]interface{})
	if deployMeta["name"] != result.ProxyName {
		t.Fatalf("deployment metadata.name = %v, want %q", deployMeta["name"], result.ProxyName)
	}
	deploySpec := deployment["spec"].(map[string]interface{})
	if deploySpec["replicas"] != proxyReplicaCount {
		t.Fatalf("deployment replicas = %v, want %d", deploySpec["replicas"], proxyReplicaCount)
	}
	template := deploySpec["template"].(map[string]interface{})
	templateSpec := template["spec"].(map[string]interface{})
	if _, ok := templateSpec["affinity"].(map[string]interface{}); !ok {
		t.Fatal("proxy deployment should define affinity")
	}
	proxyContainers := templateSpec["containers"].([]interface{})
	if len(proxyContainers) != 1 {
		t.Fatalf("proxy deployment should have 1 container, got %d", len(proxyContainers))
	}
	proxyContainer := proxyContainers[0].(map[string]interface{})
	if proxyContainer["name"] != proxyContainerName {
		t.Fatalf("proxy container name = %v, want %q", proxyContainer["name"], proxyContainerName)
	}
	if proxyContainer["image"] != fmt.Sprintf("%s:%s", defaultImageRepo, cliutil.Version) {
		t.Fatalf("proxy image = %v", proxyContainer["image"])
	}
	if proxyContainer["imagePullPolicy"] != "IfNotPresent" {
		t.Fatalf("proxy imagePullPolicy = %v, want IfNotPresent", proxyContainer["imagePullPolicy"])
	}
	volumeMounts := proxyContainer["volumeMounts"].([]interface{})
	volumeMount := volumeMounts[0].(map[string]interface{})
	if volumeMount["mountPath"] != sidecarConfigMount {
		t.Fatalf("config mountPath = %v, want %q", volumeMount["mountPath"], sidecarConfigMount)
	}
	if _, ok := volumeMount["subPath"]; ok {
		t.Fatal("config mount should not use subPath")
	}
	resources := proxyContainer["resources"].(map[string]interface{})
	requests := resources["requests"].(map[string]interface{})
	limits := resources["limits"].(map[string]interface{})
	if requests["cpu"] != proxyCPURequest || requests["memory"] != proxyMemoryRequest {
		t.Fatalf("requests = %v, want cpu=%s memory=%s", requests, proxyCPURequest, proxyMemoryRequest)
	}
	if limits["cpu"] != proxyCPULimit || limits["memory"] != proxyMemoryLimit {
		t.Fatalf("limits = %v, want cpu=%s memory=%s", limits, proxyCPULimit, proxyMemoryLimit)
	}

	var agentPolicy map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.AgentNetworkPolicyYAML), &agentPolicy); err != nil {
		t.Fatalf("parsing AgentNetworkPolicyYAML: %v", err)
	}
	agentSpec := agentPolicy["spec"].(map[string]interface{})
	podSelector := agentSpec["podSelector"].(map[string]interface{})
	matchLabels := podSelector["matchLabels"].(map[string]interface{})
	if matchLabels["app"] != "my-agent" {
		t.Fatalf("agent policy selector = %v, want app=my-agent", matchLabels)
	}
	if strings.Contains(result.AgentNetworkPolicyYAML, "port: 80") || strings.Contains(result.AgentNetworkPolicyYAML, "port: 443") {
		t.Fatal("agent NetworkPolicy should not allow direct web egress")
	}

	var proxyPolicy map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.ProxyNetworkPolicyYAML), &proxyPolicy); err != nil {
		t.Fatalf("parsing ProxyNetworkPolicyYAML: %v", err)
	}
	proxySpec := proxyPolicy["spec"].(map[string]interface{})
	if _, ok := proxySpec["ingress"].([]interface{}); !ok {
		t.Fatal("proxy NetworkPolicy should define ingress rules")
	}
	if _, ok := proxySpec["egress"].([]interface{}); !ok {
		t.Fatal("proxy NetworkPolicy should define egress rules")
	}

	var pdb map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.PodDisruptionBudgetYAML), &pdb); err != nil {
		t.Fatalf("parsing PodDisruptionBudgetYAML: %v", err)
	}
	if pdb["kind"] != "PodDisruptionBudget" {
		t.Fatalf("pdb kind = %v, want PodDisruptionBudget", pdb["kind"])
	}
	pdbSpec := pdb["spec"].(map[string]interface{})
	if pdbSpec["minAvailable"] != 1 {
		t.Fatalf("pdb minAvailable = %v, want 1", pdbSpec["minAvailable"])
	}

	wantIdentity := "deployment/my-agent"
	if result.AgentIdentity != wantIdentity {
		t.Fatalf("AgentIdentity = %q, want %q", result.AgentIdentity, wantIdentity)
	}
}

func TestGenerateSidecarPatch_Idempotent(t *testing.T) {
	manifest, err := detectWorkload(testdataPath(t, "deployment.yaml"))
	if err != nil {
		t.Fatalf("detectWorkload: %v", err)
	}

	opts := sidecarOptions{preset: config.ModeBalanced}
	first, err := generateSidecarPatch(manifest, opts)
	if err != nil {
		t.Fatalf("first generateSidecarPatch: %v", err)
	}

	patchedBytes, err := yaml.Marshal(first.PatchedManifest)
	if err != nil {
		t.Fatalf("marshal patched manifest: %v", err)
	}
	patchedManifest := &workloadManifest{
		Kind:     manifest.Kind,
		Name:     manifest.Name,
		Raw:      first.PatchedManifest,
		RawBytes: patchedBytes,
	}

	second, err := generateSidecarPatch(patchedManifest, opts)
	if err != nil {
		t.Fatalf("second generateSidecarPatch: %v", err)
	}

	podSpec, err := getPodSpec(second.PatchedManifest, kindDeployment)
	if err != nil {
		t.Fatalf("getPodSpec on second patch: %v", err)
	}
	containers := podSpec["containers"].([]interface{})
	firstContainer := containers[0].(map[string]interface{})
	envList := firstContainer["env"].([]interface{})
	if envCount(envList, envHTTPSProxy) != 1 || envCount(envList, envHTTPProxy) != 1 || envCount(envList, envNoProxy) != 1 {
		t.Fatalf("expected proxy env vars to remain singletons, got env=%v", envList)
	}

	if second.ProxyName != first.ProxyName {
		t.Fatalf("ProxyName changed across idempotent run: %q vs %q", second.ProxyName, first.ProxyName)
	}
	if second.ProxyURL != first.ProxyURL {
		t.Fatalf("ProxyURL changed across idempotent run: %q vs %q", second.ProxyURL, first.ProxyURL)
	}
	if second.Config == nil || second.DeploymentYAML == "" || second.ServiceYAML == "" || second.PodDisruptionBudgetYAML == "" {
		t.Fatal("idempotent generation should still render companion artifacts for verification")
	}
}

func TestGenerateSidecarPatch_AllKinds(t *testing.T) {
	tests := []struct {
		name         string
		file         string
		kind         string
		wantIdentity string
	}{
		{name: "deployment", file: "deployment.yaml", kind: kindDeployment, wantIdentity: "deployment/my-agent"},
		{name: "statefulset", file: "statefulset.yaml", kind: kindStatefulSet, wantIdentity: "statefulset/my-db-agent"},
		{name: "job", file: "job.yaml", kind: kindJob, wantIdentity: "job/batch-runner"},
		{name: "cronjob", file: "cronjob.yaml", kind: kindCronJob, wantIdentity: "cronjob/scheduled-scan"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest, err := detectWorkload(testdataPath(t, tc.file))
			if err != nil {
				t.Fatalf("detectWorkload: %v", err)
			}

			result, err := generateSidecarPatch(manifest, sidecarOptions{preset: config.ModeBalanced})
			if err != nil {
				t.Fatalf("generateSidecarPatch: %v", err)
			}

			podSpec, err := getPodSpec(result.PatchedManifest, tc.kind)
			if err != nil {
				t.Fatalf("getPodSpec: %v", err)
			}
			if hasPipelockContainer(podSpec) {
				t.Fatal("patched manifest should not have a same-pod pipelock container")
			}

			containers := podSpec["containers"].([]interface{})
			agentContainer := containers[0].(map[string]interface{})
			envList := agentContainer["env"].([]interface{})
			if envValue(t, envList, envHTTPSProxy) != result.ProxyURL {
				t.Fatalf("%s should point to proxy URL", envHTTPSProxy)
			}
			if result.AgentIdentity != tc.wantIdentity {
				t.Fatalf("AgentIdentity = %q, want %q", result.AgentIdentity, tc.wantIdentity)
			}
			if result.ConfigMapYAML == "" || result.DeploymentYAML == "" || result.ServiceYAML == "" || result.PodDisruptionBudgetYAML == "" {
				t.Fatal("expected companion resources for every workload kind")
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
	result, err := generateSidecarPatch(manifest, sidecarOptions{
		preset: config.ModeBalanced,
		image:  customImage,
	})
	if err != nil {
		t.Fatalf("generateSidecarPatch: %v", err)
	}

	var deployment map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.DeploymentYAML), &deployment); err != nil {
		t.Fatalf("parsing DeploymentYAML: %v", err)
	}
	spec := deployment["spec"].(map[string]interface{})
	template := spec["template"].(map[string]interface{})
	templateSpec := template["spec"].(map[string]interface{})
	containers := templateSpec["containers"].([]interface{})
	proxyContainer := containers[0].(map[string]interface{})
	if proxyContainer["image"] != customImage {
		t.Fatalf("proxy image = %v, want %q", proxyContainer["image"], customImage)
	}
}

func TestGenerateSidecarPatch_CustomIdentity(t *testing.T) {
	manifest, err := detectWorkload(testdataPath(t, "deployment.yaml"))
	if err != nil {
		t.Fatalf("detectWorkload: %v", err)
	}

	const customIdentity = "team-alpha/my-custom-agent"
	result, err := generateSidecarPatch(manifest, sidecarOptions{
		preset:        config.ModeBalanced,
		agentIdentity: customIdentity,
	})
	if err != nil {
		t.Fatalf("generateSidecarPatch: %v", err)
	}

	if result.AgentIdentity != customIdentity {
		t.Fatalf("AgentIdentity = %q, want %q", result.AgentIdentity, customIdentity)
	}
}

func TestInjectProxyEnvs_RejectsConflictingProxy(t *testing.T) {
	podSpec := map[string]interface{}{
		"containers": []interface{}{
			map[string]interface{}{
				"name": "agent",
				"env": []interface{}{
					map[string]interface{}{"name": envHTTPSProxy, "value": "http://wrong-proxy:8888"},
				},
			},
		},
	}

	err := injectProxyEnvs(podSpec, "http://expected-proxy:8888")
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if !strings.Contains(err.Error(), envHTTPSProxy) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveImage(t *testing.T) {
	tests := []struct {
		name      string
		image     string
		wantImage string
	}{
		{name: "default image uses version", image: "", wantImage: fmt.Sprintf("%s:%s", defaultImageRepo, cliutil.Version)},
		{name: "custom image override", image: "my-registry.io/pipelock:custom", wantImage: "my-registry.io/pipelock:custom"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveImage(sidecarOptions{image: tc.image})
			if got != tc.wantImage {
				t.Fatalf("resolveImage() = %q, want %q", got, tc.wantImage)
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
		{name: "derived from deployment", kind: kindDeployment, workloadName: "my-agent", want: "deployment/my-agent"},
		{name: "derived from statefulset", kind: kindStatefulSet, workloadName: "my-db", want: "statefulset/my-db"},
		{name: "derived from job", kind: kindJob, workloadName: "runner", want: "job/runner"},
		{name: "derived from cronjob", kind: kindCronJob, workloadName: "scanner", want: "cronjob/scanner"},
		{name: "custom identity overrides derivation", kind: kindDeployment, workloadName: "my-agent", agentIdentity: "custom/override", want: "custom/override"},
		{name: "empty workload name", kind: kindDeployment, workloadName: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := &workloadManifest{Kind: tc.kind, Name: tc.workloadName}
			got := resolveAgentIdentity(manifest, sidecarOptions{agentIdentity: tc.agentIdentity})
			if got != tc.want {
				t.Fatalf("resolveAgentIdentity() = %q, want %q", got, tc.want)
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

func TestRenderAgentNetworkPolicy_EmptySelectorError(t *testing.T) {
	if _, err := renderAgentNetworkPolicy("default", "agent", nil, map[string]string{"app": "proxy"}); err == nil {
		t.Fatal("expected error for empty agent selector labels")
	}
}

func TestRenderProxyNetworkPolicy_EmptySelectorError(t *testing.T) {
	if _, err := renderProxyNetworkPolicy("default", "proxy", map[string]string{"app": "proxy"}, nil); err == nil {
		t.Fatal("expected error for empty agent selector labels")
	}
}
