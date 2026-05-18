// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"io"
	"regexp"
	"strings"
)

// sidecarVerifyResult holds the outcome of the sidecar verify phase.
type sidecarVerifyResult struct {
	Reachable bool   `json:"reachable"`
	Healthy   bool   `json:"healthy"`
	Skipped   bool   `json:"skipped"`
	Detail    string `json:"detail,omitempty"`
}

// runSidecarVerify performs static verification of the generated enforced topology.
func runSidecarVerify(w io.Writer, result *sidecarPatchResult, opts sidecarOptions, jsonOutput bool) *sidecarVerifyResult {
	if opts.skipVerify {
		return &sidecarVerifyResult{Skipped: true, Detail: "skipped (--skip-verify)"}
	}

	if result == nil || result.Config == nil {
		return &sidecarVerifyResult{Healthy: false, Detail: "generated topology is missing proxy config"}
	}

	var failed []string
	if result.ProxyName == "" || result.ProxyURL == "" {
		failed = append(failed, "proxy identity metadata is incomplete")
	}
	if result.DeploymentYAML == "" {
		failed = append(failed, "proxy Deployment YAML is empty")
	}
	if result.ServiceYAML == "" {
		failed = append(failed, "proxy Service YAML is empty")
	}
	if result.PodDisruptionBudgetYAML == "" {
		failed = append(failed, "proxy PodDisruptionBudget YAML is empty")
	}
	if !strings.Contains(result.DeploymentYAML, fmt.Sprintf("replicas: %d", proxyReplicaCount)) {
		failed = append(failed, fmt.Sprintf("proxy Deployment does not set replicas=%d", proxyReplicaCount))
	}
	if strings.Contains(result.DeploymentYAML, "subPath:") {
		failed = append(failed, "proxy Deployment still uses subPath ConfigMap mount")
	}
	if !strings.Contains(result.DeploymentYAML, "mountPath: /etc/pipelock") {
		failed = append(failed, "proxy Deployment does not mount the config directory")
	}
	if !strings.Contains(result.DeploymentYAML, "imagePullPolicy: IfNotPresent") {
		failed = append(failed, "proxy Deployment does not set imagePullPolicy=IfNotPresent")
	}
	if !result.Config.ForwardProxy.Enabled {
		failed = append(failed, "forward_proxy.enabled is false")
	}
	if got := result.Config.FetchProxy.Listen; got != fmt.Sprintf("0.0.0.0:%d", sidecarHealthPort) {
		failed = append(failed, fmt.Sprintf("fetch_proxy.listen = %q", got))
	}
	if got := result.Config.MetricsListen; got != fmt.Sprintf("0.0.0.0:%d", sidecarMetricsPort) {
		failed = append(failed, fmt.Sprintf("metrics_listen = %q", got))
	}
	if !strings.Contains(result.AgentNetworkPolicyYAML, "matchLabels") || !strings.Contains(result.AgentNetworkPolicyYAML, "podSelector") {
		failed = append(failed, "agent NetworkPolicy missing selectors")
	}
	if networkPolicyHasPort(result.AgentNetworkPolicyYAML, 80) || networkPolicyHasPort(result.AgentNetworkPolicyYAML, 443) {
		failed = append(failed, "agent NetworkPolicy still allows direct web egress")
	}
	if !networkPolicyHasPort(result.AgentNetworkPolicyYAML, sidecarHealthPort) {
		failed = append(failed, "agent NetworkPolicy does not allow proxy port")
	}
	if result.MCPUpstream != "" && !networkPolicyHasPort(result.AgentNetworkPolicyYAML, sidecarMCPPort) {
		failed = append(failed, "agent NetworkPolicy does not allow MCP proxy port")
	}
	if result.MCPUpstream != "" {
		verifyMCPLauncherContract(result, &failed)
	}
	if !networkPolicyHasPort(result.ProxyNetworkPolicyYAML, sidecarHealthPort) {
		failed = append(failed, "proxy NetworkPolicy does not allow agent ingress on proxy port")
	}
	if result.MCPUpstream != "" {
		if !networkPolicyHasPort(result.ProxyNetworkPolicyYAML, sidecarMCPPort) {
			failed = append(failed, "proxy NetworkPolicy does not allow agent ingress on MCP proxy port")
		}
		if upstreamPort := mcpUpstreamPolicyPort(result.MCPUpstream); upstreamPort != 0 &&
			!networkPolicyHasPort(result.ProxyNetworkPolicyYAML, upstreamPort) {
			failed = append(failed, fmt.Sprintf("proxy NetworkPolicy does not allow MCP upstream port %d", upstreamPort))
		}
	}
	if !networkPolicyHasPort(result.ProxyNetworkPolicyYAML, 80) || !networkPolicyHasPort(result.ProxyNetworkPolicyYAML, 443) {
		failed = append(failed, "proxy NetworkPolicy does not allow web egress")
	}

	if len(failed) == 0 {
		if !jsonOutput {
			_, _ = fmt.Fprintln(w, "  Static topology checks passed.")
			_, _ = fmt.Fprintf(w, "  Agent egress is limited to DNS + %s.\n", result.ProxyName)
			_, _ = fmt.Fprintln(w, "  Proxy config is cluster-reachable with forward proxy enabled.")
		}
		return &sidecarVerifyResult{
			Reachable: true,
			Healthy:   true,
			Detail:    "static topology verification passed",
		}
	}

	detail := "static topology verification failed: " + strings.Join(failed, "; ")
	if !jsonOutput {
		_, _ = fmt.Fprintln(w, "  Static topology verification failed.")
		_, _ = fmt.Fprintf(w, "  %s\n", detail)
	}
	return &sidecarVerifyResult{
		Healthy: false,
		Detail:  detail,
	}
}

func networkPolicyHasPort(policyYAML string, port int) bool {
	pattern := fmt.Sprintf(`(?m)^\s*-?\s*port:\s*%d\s*(?:#.*)?$`, port)
	return regexp.MustCompile(pattern).MatchString(policyYAML)
}

func verifyMCPLauncherContract(result *sidecarPatchResult, failed *[]string) {
	if result.MCPProxyURL == "" {
		*failed = append(*failed, "MCP proxy URL is empty")
	}
	if result.MCPConfigPath != sidecarMCPConfigPath() {
		*failed = append(*failed, fmt.Sprintf("MCP config path = %q", result.MCPConfigPath))
	}
	if result.MCPServerName == "" {
		*failed = append(*failed, "MCP server name is empty")
	}
	if result.MCPConfigMapYAML == "" {
		*failed = append(*failed, "MCP client ConfigMap YAML is empty")
	} else if !strings.Contains(result.MCPConfigMapYAML, result.MCPProxyURL) {
		*failed = append(*failed, "MCP client ConfigMap does not point at the MCP proxy URL")
	}

	kind, _ := result.PatchedManifest["kind"].(string)
	podSpec, err := getPodSpec(result.PatchedManifest, kind)
	if err != nil {
		*failed = append(*failed, "patched workload pod spec is unavailable")
		return
	}
	if !podSpecHasEnv(podSpec, envMCPProxy, result.MCPProxyURL) {
		*failed = append(*failed, fmt.Sprintf("agent workload does not set %s", envMCPProxy))
	}
	if !podSpecHasEnv(podSpec, envMCPConfig, result.MCPConfigPath) {
		*failed = append(*failed, fmt.Sprintf("agent workload does not set %s", envMCPConfig))
	}
	if !podSpecHasConfigMapVolume(podSpec, mcpClientConfigMapName(result.ProxyName)) {
		*failed = append(*failed, "agent workload does not mount the MCP client ConfigMap volume")
	}
	if !podSpecHasVolumeMount(podSpec) {
		*failed = append(*failed, "agent container does not mount the MCP client config directory")
	}
}

func podSpecHasEnv(podSpec map[string]interface{}, name, value string) bool {
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return false
	}
	for _, item := range containers {
		container, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if containerName, _ := container["name"].(string); containerName == proxyContainerName {
			continue
		}
		envList, _ := container["env"].([]interface{})
		for _, envItem := range envList {
			envMap, ok := envItem.(map[string]interface{})
			if !ok {
				continue
			}
			if envName, _ := envMap["name"].(string); envName != name {
				continue
			}
			envValue, _ := envMap["value"].(string)
			if envValue == value {
				return true
			}
		}
	}
	return false
}

func podSpecHasConfigMapVolume(podSpec map[string]interface{}, configMapName string) bool {
	volumes, ok := podSpec["volumes"].([]interface{})
	if !ok {
		return false
	}
	for _, item := range volumes {
		volume, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if name, _ := volume["name"].(string); name != sidecarMCPConfigVolume {
			continue
		}
		configMap, _ := volume["configMap"].(map[string]interface{})
		gotName, _ := configMap["name"].(string)
		return gotName == configMapName
	}
	return false
}

func podSpecHasVolumeMount(podSpec map[string]interface{}) bool {
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return false
	}
	for _, item := range containers {
		container, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if containerName, _ := container["name"].(string); containerName == proxyContainerName {
			continue
		}
		mounts, _ := container["volumeMounts"].([]interface{})
		for _, mountItem := range mounts {
			mount, ok := mountItem.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := mount["name"].(string)
			path, _ := mount["mountPath"].(string)
			if name == sidecarMCPConfigVolume && path == sidecarMCPConfigMount {
				return true
			}
		}
	}
	return false
}
