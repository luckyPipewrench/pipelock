// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"io"
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
	if strings.Contains(result.AgentNetworkPolicyYAML, "port: 80") || strings.Contains(result.AgentNetworkPolicyYAML, "port: 443") {
		failed = append(failed, "agent NetworkPolicy still allows direct web egress")
	}
	if !strings.Contains(result.AgentNetworkPolicyYAML, fmt.Sprintf("port: %d", sidecarHealthPort)) {
		failed = append(failed, "agent NetworkPolicy does not allow proxy port")
	}
	if !strings.Contains(result.ProxyNetworkPolicyYAML, fmt.Sprintf("port: %d", sidecarHealthPort)) {
		failed = append(failed, "proxy NetworkPolicy does not allow agent ingress on proxy port")
	}
	if !strings.Contains(result.ProxyNetworkPolicyYAML, "port: 80") || !strings.Contains(result.ProxyNetworkPolicyYAML, "port: 443") {
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
