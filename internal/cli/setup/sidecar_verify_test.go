// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
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
