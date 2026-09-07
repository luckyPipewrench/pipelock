// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"gopkg.in/yaml.v3"
)

func TestNetworkPolicyHasPortExact(t *testing.T) {
	t.Parallel()

	policy := `
spec:
  egress:
    - ports:
        - protocol: TCP
          port: 8080
        - protocol: TCP
          port: 4430
        - protocol: TCP
          port: 88890
        - protocol: TCP
          port: 30000
        - protocol: TCP
          port: 8889 # mcp
`

	for _, port := range []int{80, 443, 8888, 3000} {
		if networkPolicyHasPort(policy, port) {
			t.Fatalf("networkPolicyHasPort matched substring port %d", port)
		}
	}
	if !networkPolicyHasPort(policy, 8889) {
		t.Fatal("networkPolicyHasPort should match exact port line")
	}
}

func TestRunSidecarVerify_MCPLauncherContract(t *testing.T) {
	t.Parallel()

	result := mustPatchResult(t, sidecarOptions{
		preset:      config.ModeBalanced,
		mcpUpstream: "http://openclaw:3000/mcp",
	})

	var buf bytes.Buffer
	verify := runSidecarVerify(&buf, result, sidecarOptions{}, false)
	if !verify.Healthy || !verify.Reachable {
		t.Fatalf("verify = %+v, output:\n%s", verify, buf.String())
	}
	if !strings.Contains(buf.String(), "Static topology checks passed") {
		t.Fatalf("verify output missing success message:\n%s", buf.String())
	}
}

func TestRunSidecarVerifyRejectsStaticTopologyDrift(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*testing.T, *sidecarPatchResult)
		wantError string
	}{
		{
			name: "wrong replica count",
			mutate: func(_ *testing.T, result *sidecarPatchResult) {
				result.DeploymentYAML = strings.Replace(
					result.DeploymentYAML,
					fmt.Sprintf("replicas: %d", proxyReplicaCount),
					fmt.Sprintf("replicas: %d", proxyReplicaCount-1),
					1,
				)
			},
			wantError: fmt.Sprintf("proxy Deployment does not set replicas=%d", proxyReplicaCount),
		},
		{
			name: "subpath config mount",
			mutate: func(t *testing.T, result *sidecarPatchResult) {
				result.DeploymentYAML = addConfigMountSubPath(t, result.DeploymentYAML)
			},
			wantError: "proxy Deployment still uses subPath ConfigMap mount",
		},
		{
			name: "missing config directory mount",
			mutate: func(_ *testing.T, result *sidecarPatchResult) {
				result.DeploymentYAML = strings.Replace(result.DeploymentYAML, "mountPath: /etc/pipelock", "mountPath: /etc/not-pipelock", 1)
			},
			wantError: "proxy Deployment does not mount the config directory",
		},
		{
			name: "wrong image pull policy",
			mutate: func(_ *testing.T, result *sidecarPatchResult) {
				result.DeploymentYAML = strings.Replace(result.DeploymentYAML, "imagePullPolicy: IfNotPresent", "imagePullPolicy: Always", 1)
			},
			wantError: "proxy Deployment does not set imagePullPolicy=IfNotPresent",
		},
		{
			name: "forward proxy disabled",
			mutate: func(_ *testing.T, result *sidecarPatchResult) {
				result.Config.ForwardProxy.Enabled = false
			},
			wantError: "forward_proxy.enabled is false",
		},
		{
			name: "wrong proxy listener",
			mutate: func(_ *testing.T, result *sidecarPatchResult) {
				result.Config.FetchProxy.Listen = "127.0.0.1:8080"
			},
			wantError: "fetch_proxy.listen = \"127.0.0.1:8080\"",
		},
		{
			name: "agent direct web egress",
			mutate: func(t *testing.T, result *sidecarPatchResult) {
				result.AgentNetworkPolicyYAML = addAgentDirectWebEgress(t, result.AgentNetworkPolicyYAML)
			},
			wantError: "agent NetworkPolicy still allows direct web egress",
		},
		{
			name: "agent missing proxy port",
			mutate: func(_ *testing.T, result *sidecarPatchResult) {
				result.AgentNetworkPolicyYAML = strings.Replace(
					result.AgentNetworkPolicyYAML,
					fmt.Sprintf("port: %d", sidecarHealthPort),
					"port: 9999",
					1,
				)
			},
			wantError: "agent NetworkPolicy does not allow proxy port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mustPatchResult(t, sidecarOptions{preset: config.ModeBalanced})
			tt.mutate(t, result)

			var buf bytes.Buffer
			verify := runSidecarVerify(&buf, result, sidecarOptions{}, false)
			if verify.Healthy || verify.Reachable {
				t.Fatalf("verify = %+v, want unhealthy and unreachable; output:\n%s", verify, buf.String())
			}
			wantDetail := "static topology verification failed: " + tt.wantError
			if verify.Detail != wantDetail {
				t.Fatalf("verify detail = %q, want exactly %q", verify.Detail, wantDetail)
			}
			if !strings.Contains(buf.String(), "Static topology verification failed") {
				t.Fatalf("verify output missing failure message:\n%s", buf.String())
			}
			if strings.Contains(buf.String(), "Static topology checks passed") {
				t.Fatalf("unhealthy verification claimed success:\n%s", buf.String())
			}
		})
	}

	healthy := mustPatchResult(t, sidecarOptions{preset: config.ModeBalanced})
	var buf bytes.Buffer
	verify := runSidecarVerify(&buf, healthy, sidecarOptions{}, false)
	if !verify.Healthy || !verify.Reachable || !strings.Contains(buf.String(), "Static topology checks passed") {
		t.Fatalf("fresh healthy topology verify = %+v, output:\n%s", verify, buf.String())
	}
}

func addConfigMountSubPath(t *testing.T, deploymentYAML string) string {
	t.Helper()

	deployment := decodeSidecarVerifyYAML(t, deploymentYAML)
	podSpec, err := getPodSpec(deployment, kindDeployment)
	if err != nil {
		t.Fatalf("getPodSpec: %v", err)
	}
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		t.Fatal("Deployment containers are unavailable")
	}
	for _, rawContainer := range containers {
		container, ok := rawContainer.(map[string]interface{})
		if !ok || container["name"] != proxyContainerName {
			continue
		}
		mounts, ok := container["volumeMounts"].([]interface{})
		if !ok {
			t.Fatal("proxy container volumeMounts are unavailable")
		}
		for _, rawMount := range mounts {
			mount, ok := rawMount.(map[string]interface{})
			if !ok || mount["mountPath"] != sidecarConfigMount {
				continue
			}
			mount["subPath"] = sidecarConfigFile
			return encodeSidecarVerifyYAML(t, deployment)
		}
	}
	t.Fatal("proxy config volumeMount is unavailable")
	return ""
}

func addAgentDirectWebEgress(t *testing.T, policyYAML string) string {
	t.Helper()

	policy := decodeSidecarVerifyYAML(t, policyYAML)
	spec, ok := policy["spec"].(map[string]interface{})
	if !ok {
		t.Fatal("NetworkPolicy spec is unavailable")
	}
	egress, ok := spec["egress"].([]interface{})
	if !ok {
		t.Fatal("NetworkPolicy egress rules are unavailable")
	}
	// A separate rule without a destination selector allows TCP/80 beyond the proxy.
	spec["egress"] = append(egress, map[string]interface{}{
		"ports": []interface{}{map[string]interface{}{"port": 80, "protocol": "TCP"}},
	})
	return encodeSidecarVerifyYAML(t, policy)
}

func decodeSidecarVerifyYAML(t *testing.T, input string) map[string]interface{} {
	t.Helper()

	var document map[string]interface{}
	if err := yaml.Unmarshal([]byte(input), &document); err != nil {
		t.Fatalf("unmarshal YAML: %v", err)
	}
	return document
}

func encodeSidecarVerifyYAML(t *testing.T, document map[string]interface{}) string {
	t.Helper()

	encoded, err := yaml.Marshal(document)
	if err != nil {
		t.Fatalf("marshal YAML: %v", err)
	}
	// Parse the generated fixture again so a later verifier failure represents topology drift,
	// rather than malformed YAML.
	_ = decodeSidecarVerifyYAML(t, string(encoded))
	return string(encoded)
}

func TestVerifyMCPLauncherContractFailures(t *testing.T) {
	t.Parallel()

	t.Run("missing generated fields", func(t *testing.T) {
		result := mustPatchResult(t, sidecarOptions{
			preset:      config.ModeBalanced,
			mcpUpstream: "http://openclaw:3000/mcp",
		})
		result.MCPProxyURL = ""
		result.MCPConfigPath = "/wrong/path.json"
		result.MCPServerName = ""
		result.MCPConfigMapYAML = ""

		var failed []string
		verifyMCPLauncherContract(result, &failed)
		for _, want := range []string{
			"MCP proxy URL is empty",
			"MCP config path =",
			"MCP server name is empty",
			"MCP client ConfigMap YAML is empty",
			"agent workload does not set " + envMCPProxy,
			"agent workload does not set " + envMCPConfig,
		} {
			if !containsFailure(failed, want) {
				t.Fatalf("failures missing %q: %+v", want, failed)
			}
		}
	})

	t.Run("config map does not point at proxy", func(t *testing.T) {
		result := mustPatchResult(t, sidecarOptions{
			preset:      config.ModeBalanced,
			mcpUpstream: "http://openclaw:3000/mcp",
		})
		result.MCPConfigMapYAML = "kind: ConfigMap\ndata: {}\n"

		var failed []string
		verifyMCPLauncherContract(result, &failed)
		if !containsFailure(failed, "MCP client ConfigMap does not point at the MCP proxy URL") {
			t.Fatalf("failures missing ConfigMap proxy URL check: %+v", failed)
		}
	})

	t.Run("missing pod spec", func(t *testing.T) {
		result := mustPatchResult(t, sidecarOptions{
			preset:      config.ModeBalanced,
			mcpUpstream: "http://openclaw:3000/mcp",
		})
		result.PatchedManifest = map[string]interface{}{"kind": "Deployment"}

		var failed []string
		verifyMCPLauncherContract(result, &failed)
		if !containsFailure(failed, "patched workload pod spec is unavailable") {
			t.Fatalf("failures missing pod spec check: %+v", failed)
		}
	})

	t.Run("missing volume wiring", func(t *testing.T) {
		result := mustPatchResult(t, sidecarOptions{
			preset:      config.ModeBalanced,
			mcpUpstream: "http://openclaw:3000/mcp",
		})
		podSpec, err := getPodSpec(result.PatchedManifest, kindDeployment)
		if err != nil {
			t.Fatalf("getPodSpec: %v", err)
		}
		delete(podSpec, "volumes")
		containers := podSpec["containers"].([]interface{})
		delete(containers[0].(map[string]interface{}), "volumeMounts")

		var failed []string
		verifyMCPLauncherContract(result, &failed)
		if !containsFailure(failed, "agent workload does not mount the MCP client ConfigMap volume") {
			t.Fatalf("failures missing volume check: %+v", failed)
		}
		if !containsFailure(failed, "agent container does not mount the MCP client config directory") {
			t.Fatalf("failures missing volumeMount check: %+v", failed)
		}
	})
}

func TestPodSpecHasEnvSkipsMalformedAndProxyContainer(t *testing.T) {
	t.Parallel()

	podSpec := map[string]interface{}{
		"containers": []interface{}{
			"bad container",
			map[string]interface{}{
				"name": proxyContainerName,
				"env": []interface{}{
					map[string]interface{}{"name": envMCPProxy, "value": "http://proxy:8889"},
				},
			},
			map[string]interface{}{
				"name": "agent",
				"env": []interface{}{
					"bad env",
					map[string]interface{}{"name": envMCPProxy, "value": "http://proxy:8889"},
				},
			},
		},
	}

	if !podSpecHasEnv(podSpec, envMCPProxy, "http://proxy:8889") {
		t.Fatal("expected agent env to be found")
	}
	if podSpecHasEnv(podSpec, envMCPProxy, "http://wrong:8889") {
		t.Fatal("unexpected env match for wrong value")
	}
	if podSpecHasEnv(map[string]interface{}{}, envMCPProxy, "http://proxy:8889") {
		t.Fatal("unexpected env match without containers")
	}
}

func containsFailure(failed []string, want string) bool {
	for _, item := range failed {
		if strings.Contains(item, want) {
			return true
		}
	}
	return false
}
