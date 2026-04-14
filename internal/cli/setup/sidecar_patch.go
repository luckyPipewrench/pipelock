// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package setup implements init flows. This file generates a strategic-merge
// patch that injects a pipelock sidecar into Kubernetes workload manifests.
// Strategic merge is used for container-level mutations (container additions,
// env additions) because kubectl apply handles list-merge on container name.
package setup

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Fixed names and values for the sidecar injection.
const (
	sidecarContainerName = "pipelock"
	sidecarConfigVolume  = "pipelock-config"
	sidecarConfigMount   = "/etc/pipelock"
	sidecarConfigFile    = "pipelock.yaml"
	sidecarHealthPath    = "/health"
	sidecarHealthPort    = 8888

	// defaultImage is the GHCR image with the current version tag.
	// Overridden by --image flag.
	defaultImageRepo = "ghcr.io/luckypipewrench/pipelock"

	// Proxy env vars injected into the primary container.
	envHTTPSProxy = "HTTPS_PROXY"
	envHTTPProxy  = "HTTP_PROXY"
	envNoProxy    = "NO_PROXY"
	noProxyValue  = "localhost,127.0.0.1,.svc,.cluster.local"
)

// sidecarPatchResult holds the generated patch and related artifacts.
type sidecarPatchResult struct {
	// OriginalManifestYAML is the source workload manifest used for kustomize output.
	OriginalManifestYAML string
	// PatchedManifest is the full manifest with the sidecar injected.
	PatchedManifest map[string]interface{}
	// ConfigMapYAML is the standalone ConfigMap for the pipelock config.
	ConfigMapYAML string
	// NetworkPolicyYAML is a deny-all NetworkPolicy with explicit egress to the sidecar.
	NetworkPolicyYAML string
	// AgentIdentity is the derived default_agent_identity value.
	AgentIdentity string
}

// generateSidecarPatch creates the patched manifest with the pipelock sidecar injected.
// The patch is idempotent: if a pipelock container already exists, no changes are made.
func generateSidecarPatch(manifest *workloadManifest, opts sidecarOptions) (*sidecarPatchResult, error) {
	// Deep copy the raw manifest to avoid mutating the original.
	patched, err := deepCopyMap(manifest.Raw)
	if err != nil {
		return nil, fmt.Errorf("deep copy manifest: %w", err)
	}

	podSpec, err := getPodSpec(patched, manifest.Kind)
	if err != nil {
		return nil, fmt.Errorf("locating pod spec: %w", err)
	}

	// Idempotency: if pipelock container already exists, return as-is.
	if hasPipelockContainer(podSpec) {
		return &sidecarPatchResult{
			OriginalManifestYAML: string(manifest.RawBytes),
			PatchedManifest:      patched,
			AgentIdentity:        resolveAgentIdentity(manifest, opts),
		}, nil
	}

	image := resolveImage(opts)
	agentIdentity := resolveAgentIdentity(manifest, opts)

	// Build the sidecar container spec.
	sidecar := buildSidecarContainer(image, opts.preset)

	// Add the sidecar container.
	containers, _ := podSpec["containers"].([]interface{})
	podSpec["containers"] = append(containers, sidecar)

	// Add the config volume.
	volumes, _ := podSpec["volumes"].([]interface{})
	podSpec["volumes"] = append(volumes, map[string]interface{}{
		"name": sidecarConfigVolume,
		"configMap": map[string]interface{}{
			"name": sidecarConfigVolume,
		},
	})

	// Inject proxy env vars into existing primary container(s).
	injectProxyEnvs(podSpec)

	// Build the ConfigMap YAML.
	pipelockCfg := buildConfig(opts.preset, nil)
	pipelockCfg.DefaultAgentIdentity = agentIdentity
	configMapYAML, err := renderConfigMap(pipelockCfg, opts.preset)
	if err != nil {
		return nil, fmt.Errorf("rendering ConfigMap: %w", err)
	}

	// Build the NetworkPolicy YAML.
	namespace := extractNamespace(manifest.Raw)
	selectorLabels, err := networkPolicySelectorLabels(manifest.Raw, manifest.Kind)
	if err != nil {
		return nil, fmt.Errorf("building NetworkPolicy selector: %w", err)
	}
	networkPolicyYAML, err := renderNetworkPolicy(namespace, manifest.Name, selectorLabels)
	if err != nil {
		return nil, fmt.Errorf("rendering NetworkPolicy: %w", err)
	}

	return &sidecarPatchResult{
		OriginalManifestYAML: string(manifest.RawBytes),
		PatchedManifest:      patched,
		ConfigMapYAML:        configMapYAML,
		NetworkPolicyYAML:    networkPolicyYAML,
		AgentIdentity:        agentIdentity,
	}, nil
}

// buildSidecarContainer creates the pipelock sidecar container spec.
func buildSidecarContainer(image, preset string) map[string]interface{} {
	return map[string]interface{}{
		"name":  sidecarContainerName,
		"image": image,
		"args":  []interface{}{"run", "--config", sidecarConfigMount + "/" + sidecarConfigFile},
		"ports": []interface{}{
			map[string]interface{}{
				"name":          "proxy",
				"containerPort": sidecarHealthPort,
				"protocol":      "TCP",
			},
		},
		"env": []interface{}{
			map[string]interface{}{"name": "PIPELOCK_MODE", "value": preset},
			map[string]interface{}{"name": "PIPELOCK_CONFIG_PATH", "value": sidecarConfigMount + "/" + sidecarConfigFile},
		},
		"volumeMounts": []interface{}{
			map[string]interface{}{
				"name":      sidecarConfigVolume,
				"mountPath": sidecarConfigMount,
				"readOnly":  true,
			},
		},
		"resources": map[string]interface{}{
			"requests": map[string]interface{}{
				"cpu":    "25m",
				"memory": "32Mi",
			},
			"limits": map[string]interface{}{
				"cpu":    "200m",
				"memory": "128Mi",
			},
		},
		"readinessProbe": map[string]interface{}{
			"httpGet": map[string]interface{}{
				"path": sidecarHealthPath,
				"port": sidecarHealthPort,
			},
			"initialDelaySeconds": 2,
			"periodSeconds":       10,
		},
		"livenessProbe": map[string]interface{}{
			"httpGet": map[string]interface{}{
				"path": sidecarHealthPath,
				"port": sidecarHealthPort,
			},
			"initialDelaySeconds": 5,
			"periodSeconds":       30,
		},
		"securityContext": map[string]interface{}{
			"readOnlyRootFilesystem":   true,
			"allowPrivilegeEscalation": false,
			"runAsNonRoot":             true,
			"runAsUser":                65534,
			"capabilities": map[string]interface{}{
				"drop": []interface{}{"ALL"},
			},
		},
	}
}

// injectProxyEnvs adds HTTPS_PROXY, HTTP_PROXY, NO_PROXY to existing non-pipelock containers.
func injectProxyEnvs(podSpec map[string]interface{}) {
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return
	}
	proxyURL := fmt.Sprintf("http://localhost:%d", sidecarHealthPort)
	proxyEnvs := []interface{}{
		map[string]interface{}{"name": envHTTPSProxy, "value": proxyURL},
		map[string]interface{}{"name": envHTTPProxy, "value": proxyURL},
		map[string]interface{}{"name": envNoProxy, "value": noProxyValue},
	}

	for _, c := range containers {
		cMap, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := cMap["name"].(string)
		if name == sidecarContainerName {
			continue
		}
		existing, _ := cMap["env"].([]interface{})
		// Skip if proxy env already set (idempotency).
		if hasEnvVar(existing, envHTTPSProxy) {
			continue
		}
		cMap["env"] = append(existing, proxyEnvs...)
	}
}

// hasEnvVar checks if a named env var exists in the list.
func hasEnvVar(envList []interface{}, name string) bool {
	for _, e := range envList {
		eMap, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		if n, _ := eMap["name"].(string); n == name {
			return true
		}
	}
	return false
}

// resolveImage determines the sidecar container image.
func resolveImage(opts sidecarOptions) string {
	if opts.image != "" {
		return opts.image
	}
	version := cliutil.Version
	return fmt.Sprintf("%s:%s", defaultImageRepo, version)
}

// resolveAgentIdentity determines the default agent identity for the sidecar config.
// Uses --agent-identity flag if set, otherwise derives from workload kind/name.
func resolveAgentIdentity(manifest *workloadManifest, opts sidecarOptions) string {
	if opts.agentIdentity != "" {
		return opts.agentIdentity
	}
	if manifest.Name != "" {
		return strings.ToLower(manifest.Kind) + "/" + manifest.Name
	}
	return ""
}

// renderConfigMap builds a Kubernetes ConfigMap YAML string for the pipelock config.
func renderConfigMap(cfg *config.Config, preset string) (string, error) {
	configData, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshaling config: %w", err)
	}

	header := fmt.Sprintf("# Pipelock sidecar config (%s preset)\n# Generated by: pipelock init sidecar\n\n", preset)

	cmName := sidecarConfigVolume
	cm := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]interface{}{
			"name": cmName,
			"labels": map[string]interface{}{
				"app.kubernetes.io/managed-by": "pipelock",
				"app.kubernetes.io/component":  "sidecar-config",
			},
		},
		"data": map[string]interface{}{
			sidecarConfigFile: header + string(configData),
		},
	}

	out, err := yaml.Marshal(cm)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// renderNetworkPolicy builds a pod-scoped egress policy for sidecar mode.
//
// Kubernetes NetworkPolicy is pod-scoped, not container-scoped: it cannot force
// app->sidecar routing inside a multi-container pod. The generated policy keeps
// the injected sidecar functional by allowing DNS plus standard web egress while
// still constraining the selected workload pods to that pod boundary.
func renderNetworkPolicy(namespace, workloadName string, selectorLabels map[string]string) (string, error) {
	if len(selectorLabels) == 0 {
		return "", fmt.Errorf("selector labels must not be empty")
	}

	matchLabels := make(map[string]interface{}, len(selectorLabels))
	for key, value := range selectorLabels {
		matchLabels[key] = value
	}

	np := map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]interface{}{
			"name":      workloadName + "-pipelock-egress",
			"namespace": namespace,
			"labels": map[string]interface{}{
				"app.kubernetes.io/managed-by": "pipelock",
			},
		},
		"spec": map[string]interface{}{
			"podSelector": map[string]interface{}{
				"matchLabels": matchLabels,
			},
			"policyTypes": []interface{}{"Egress"},
			"egress": []interface{}{
				// Allow DNS.
				map[string]interface{}{
					"ports": []interface{}{
						map[string]interface{}{
							"port":     53,
							"protocol": "UDP",
						},
						map[string]interface{}{
							"port":     53,
							"protocol": "TCP",
						},
					},
				},
				// Allow standard web egress so the sidecar can reach upstream HTTP(S)/WS APIs.
				map[string]interface{}{
					"ports": []interface{}{
						map[string]interface{}{
							"port":     80,
							"protocol": "TCP",
						},
						map[string]interface{}{
							"port":     443,
							"protocol": "TCP",
						},
					},
				},
			},
		},
	}

	out, err := yaml.Marshal(np)
	if err != nil {
		return "", fmt.Errorf("marshaling NetworkPolicy: %w", err)
	}
	return string(out), nil
}

// extractNamespace gets the namespace from metadata, defaulting to "default".
func extractNamespace(raw map[string]interface{}) string {
	meta, ok := raw["metadata"].(map[string]interface{})
	if !ok {
		return "default"
	}
	ns, _ := meta["namespace"].(string)
	if ns == "" {
		return "default"
	}
	return ns
}

func networkPolicySelectorLabels(raw map[string]interface{}, kind string) (map[string]string, error) {
	selectorPath := []string{"spec", "selector", "matchLabels"}
	if kind == kindCronJob {
		selectorPath = []string{"spec", "jobTemplate", "spec", "selector", "matchLabels"}
	}
	labels, err := extractStringMapAtPath(raw, selectorPath)
	if err != nil {
		return nil, fmt.Errorf("selector.matchLabels: %w", err)
	}
	if len(labels) > 0 {
		return labels, nil
	}

	templatePath := []string{"spec", "template", "metadata", "labels"}
	if kind == kindCronJob {
		templatePath = []string{"spec", "jobTemplate", "spec", "template", "metadata", "labels"}
	}
	labels, err = extractStringMapAtPath(raw, templatePath)
	if err != nil {
		return nil, fmt.Errorf("pod template labels: %w", err)
	}
	if len(labels) > 0 {
		return labels, nil
	}

	return nil, fmt.Errorf("no selector.matchLabels or pod template labels found")
}

func extractStringMapAtPath(raw map[string]interface{}, path []string) (map[string]string, error) {
	current := raw
	for i, key := range path {
		next, ok := current[key]
		if !ok {
			return nil, nil
		}
		if i == len(path)-1 {
			nextMap, ok := next.(map[string]interface{})
			if !ok {
				return nil, nil
			}
			out := make(map[string]string, len(nextMap))
			for labelKey, labelValue := range nextMap {
				value, ok := labelValue.(string)
				if !ok {
					return nil, fmt.Errorf("label %q has non-string value %T", labelKey, labelValue)
				}
				if value == "" {
					continue
				}
				out[labelKey] = value
			}
			return out, nil
		}
		nextMap, ok := next.(map[string]interface{})
		if !ok {
			return nil, nil
		}
		current = nextMap
	}
	return nil, nil
}

// deepCopyMap performs a deep copy via YAML marshal/unmarshal.
func deepCopyMap(src map[string]interface{}) (map[string]interface{}, error) {
	data, err := yaml.Marshal(src)
	if err != nil {
		return nil, err
	}
	var dst map[string]interface{}
	if err := yaml.Unmarshal(data, &dst); err != nil {
		return nil, err
	}
	return dst, nil
}
