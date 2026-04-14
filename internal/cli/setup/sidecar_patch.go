// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package setup implements init flows. This file generates an enforced
// companion-proxy topology for Kubernetes workloads: the agent workload is
// patched to talk to a separate pipelock proxy Service, and matching
// NetworkPolicies keep direct agent egress off the wire.
package setup

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Fixed names and values for companion-proxy generation.
const (
	proxyContainerName   = "pipelock"
	sidecarContainerName = proxyContainerName // legacy alias for pre-companion tests/helpers
	sidecarConfigVolume  = "pipelock-config"
	sidecarConfigMount   = "/etc/pipelock"
	sidecarConfigFile    = "pipelock.yaml"
	sidecarHealthPath    = "/health"
	sidecarHealthPort    = 8888
	sidecarMetricsPort   = 9091

	// defaultImage is the GHCR image with the current version tag.
	// Overridden by --image flag.
	defaultImageRepo = "ghcr.io/luckypipewrench/pipelock"

	// Proxy env vars injected into the primary container.
	envHTTPSProxy = "HTTPS_PROXY"
	envHTTPProxy  = "HTTP_PROXY"
	envNoProxy    = "NO_PROXY"
	noProxyValue  = "localhost,127.0.0.1,.svc,.cluster.local"

	proxyReplicaCount = 2

	proxyCPURequest    = "100m"
	proxyMemoryRequest = "128Mi"
	proxyCPULimit      = "500m"
	proxyMemoryLimit   = "512Mi"

	managedTopologyAnnotation     = "pipelock.dev/topology"
	managedProxyNameAnnotation    = "pipelock.dev/proxy-name"
	managedProxyServiceAnnotation = "pipelock.dev/proxy-service"
	managedTopologyCompanion      = "companion-proxy"
	managedByLabelValue           = "pipelock-init-sidecar"
)

// sidecarPatchResult holds the generated patch and related artifacts.
type sidecarPatchResult struct {
	// OriginalManifestYAML is the source workload manifest used for kustomize output.
	OriginalManifestYAML string
	// PatchedManifest is the full agent workload manifest with proxy env routing.
	PatchedManifest map[string]interface{}
	// Config is the rendered proxy config used for canary and topology verification.
	Config *config.Config
	// ConfigMapYAML is the standalone ConfigMap for the companion proxy.
	ConfigMapYAML string
	// DeploymentYAML is the companion proxy Deployment.
	DeploymentYAML string
	// ServiceYAML is the companion proxy Service.
	ServiceYAML string
	// AgentNetworkPolicyYAML constrains the agent pods to DNS + pipelock proxy.
	AgentNetworkPolicyYAML string
	// ProxyNetworkPolicyYAML constrains the proxy pods to trusted ingress + web egress.
	ProxyNetworkPolicyYAML string
	// PodDisruptionBudgetYAML protects the proxy deployment during voluntary disruptions.
	PodDisruptionBudgetYAML string
	// AgentIdentity is the derived default_agent_identity value.
	AgentIdentity string
	// ProxyName is the generated name of the companion proxy resources.
	ProxyName string
	// ProxyURL is the Service URL injected into the agent workload.
	ProxyURL string
	// AgentSelectorLabels identify the protected agent pods.
	AgentSelectorLabels map[string]string
	// ProxySelectorLabels identify the companion proxy pods.
	ProxySelectorLabels map[string]string
}

// generateSidecarPatch creates an enforced companion-proxy topology for the workload.
// The patched manifest is the agent workload only; the companion proxy resources are
// emitted separately.
func generateSidecarPatch(manifest *workloadManifest, opts sidecarOptions) (*sidecarPatchResult, error) {
	patched, err := deepCopyMap(manifest.Raw)
	if err != nil {
		return nil, fmt.Errorf("deep copy manifest: %w", err)
	}
	podSpec, err := getPodSpec(patched, manifest.Kind)
	if err != nil {
		return nil, fmt.Errorf("locating pod spec: %w", err)
	}
	agentIdentity := resolveAgentIdentity(manifest, opts)
	namespace := extractNamespace(manifest.Raw)
	selectorLabels, err := networkPolicySelectorLabels(manifest.Raw, manifest.Kind)
	if err != nil {
		return nil, fmt.Errorf("building NetworkPolicy selector: %w", err)
	}

	proxyName := resolveProxyName(manifest.Raw, manifest.Name)
	proxyURL := proxyServiceURL(proxyName)
	proxyLabels := proxySelectorLabels(proxyName)

	if err := annotateManagedWorkload(patched, manifest.Kind, proxyName); err != nil {
		return nil, fmt.Errorf("annotating workload: %w", err)
	}
	if err := injectProxyEnvs(podSpec, proxyURL); err != nil {
		return nil, fmt.Errorf("injecting proxy env: %w", err)
	}

	proxyCfg := buildProxyConfig(opts.preset, agentIdentity)
	configMapYAML, err := renderConfigMap(proxyCfg, opts.preset, namespace, proxyName, proxyLabels)
	if err != nil {
		return nil, fmt.Errorf("rendering ConfigMap: %w", err)
	}
	deploymentYAML, err := renderProxyDeployment(namespace, proxyName, resolveImage(opts), proxyLabels)
	if err != nil {
		return nil, fmt.Errorf("rendering Deployment: %w", err)
	}
	serviceYAML, err := renderProxyService(namespace, proxyName, proxyLabels)
	if err != nil {
		return nil, fmt.Errorf("rendering Service: %w", err)
	}
	agentNetworkPolicyYAML, err := renderAgentNetworkPolicy(namespace, manifest.Name, selectorLabels, proxyLabels)
	if err != nil {
		return nil, fmt.Errorf("rendering agent NetworkPolicy: %w", err)
	}
	proxyNetworkPolicyYAML, err := renderProxyNetworkPolicy(namespace, proxyName, proxyLabels, selectorLabels)
	if err != nil {
		return nil, fmt.Errorf("rendering proxy NetworkPolicy: %w", err)
	}
	pdbYAML, err := renderProxyPodDisruptionBudget(namespace, proxyName, proxyLabels)
	if err != nil {
		return nil, fmt.Errorf("rendering PodDisruptionBudget: %w", err)
	}

	return &sidecarPatchResult{
		OriginalManifestYAML:    string(manifest.RawBytes),
		PatchedManifest:         patched,
		Config:                  proxyCfg,
		ConfigMapYAML:           configMapYAML,
		DeploymentYAML:          deploymentYAML,
		ServiceYAML:             serviceYAML,
		AgentNetworkPolicyYAML:  agentNetworkPolicyYAML,
		ProxyNetworkPolicyYAML:  proxyNetworkPolicyYAML,
		PodDisruptionBudgetYAML: pdbYAML,
		AgentIdentity:           agentIdentity,
		ProxyName:               proxyName,
		ProxyURL:                proxyURL,
		AgentSelectorLabels:     selectorLabels,
		ProxySelectorLabels:     proxyLabels,
	}, nil
}

func buildProxyConfig(preset, agentIdentity string) *config.Config {
	cfg := buildConfig(preset, nil)
	cfg.DefaultAgentIdentity = agentIdentity
	cfg.BindDefaultAgentIdentity = true
	cfg.FetchProxy.Listen = fmt.Sprintf("0.0.0.0:%d", sidecarHealthPort)
	cfg.MetricsListen = fmt.Sprintf("0.0.0.0:%d", sidecarMetricsPort)
	cfg.ForwardProxy.Enabled = true
	return cfg
}

// injectProxyEnvs adds HTTPS_PROXY, HTTP_PROXY, NO_PROXY to agent containers.
// Existing conflicting proxy env vars are rejected instead of silently preserved.
func injectProxyEnvs(podSpec map[string]interface{}, proxyURL string) error {
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return nil
	}
	for _, c := range containers {
		cMap, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		containerName, _ := cMap["name"].(string)
		if containerName == proxyContainerName {
			continue
		}
		existing, _ := cMap["env"].([]interface{})
		existing, err := upsertProxyEnv(existing, envHTTPSProxy, proxyURL)
		if err != nil {
			return fmt.Errorf("container %q: %w", containerName, err)
		}
		existing, err = upsertProxyEnv(existing, envHTTPProxy, proxyURL)
		if err != nil {
			return fmt.Errorf("container %q: %w", containerName, err)
		}
		existing, err = upsertProxyEnv(existing, envNoProxy, noProxyValue)
		if err != nil {
			return fmt.Errorf("container %q: %w", containerName, err)
		}
		cMap["env"] = existing
	}
	return nil
}

func upsertProxyEnv(envList []interface{}, name, value string) ([]interface{}, error) {
	for i, e := range envList {
		eMap, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		if n, _ := eMap["name"].(string); n != name {
			continue
		}
		existingValue, ok := eMap["value"].(string)
		if !ok {
			return nil, fmt.Errorf("%s already defined via valueFrom; patch it manually", name)
		}
		if existingValue != value {
			return nil, fmt.Errorf("%s already defined as %q, want %q", name, existingValue, value)
		}
		envList[i] = eMap
		return envList, nil
	}
	return append(envList, map[string]interface{}{"name": name, "value": value}), nil
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

// renderConfigMap builds the ConfigMap consumed by the companion proxy Deployment.
func renderConfigMap(cfg *config.Config, preset, namespace, proxyName string, proxyLabels map[string]string) (string, error) {
	configData, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshaling config: %w", err)
	}

	header := fmt.Sprintf("# Pipelock companion proxy config (%s preset)\n# Generated by: pipelock init sidecar\n\n", preset)
	labels := managedProxyResourceLabels(proxyLabels, "config")

	cm := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]interface{}{
			"name":      proxyName,
			"namespace": namespace,
			"labels":    labelsToInterfaceMap(labels),
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

func renderProxyDeployment(namespace, proxyName, image string, proxyLabels map[string]string) (string, error) {
	deploy := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      proxyName,
			"namespace": namespace,
			"labels":    labelsToInterfaceMap(managedProxyResourceLabels(proxyLabels, "proxy")),
		},
		"spec": map[string]interface{}{
			"replicas": proxyReplicaCount,
			"selector": map[string]interface{}{
				"matchLabels": labelsToInterfaceMap(proxyLabels),
			},
			"template": map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": labelsToInterfaceMap(managedProxyResourceLabels(proxyLabels, "proxy")),
				},
				"spec": map[string]interface{}{
					"automountServiceAccountToken": false,
					"securityContext": map[string]interface{}{
						"seccompProfile": map[string]interface{}{
							"type": "RuntimeDefault",
						},
					},
					"affinity": map[string]interface{}{
						"podAntiAffinity": map[string]interface{}{
							"preferredDuringSchedulingIgnoredDuringExecution": []interface{}{
								map[string]interface{}{
									"weight": 100,
									"podAffinityTerm": map[string]interface{}{
										"labelSelector": map[string]interface{}{
											"matchLabels": labelsToInterfaceMap(proxyLabels),
										},
										"topologyKey": "kubernetes.io/hostname",
									},
								},
							},
						},
					},
					"containers": []interface{}{
						map[string]interface{}{
							"name":            proxyContainerName,
							"image":           image,
							"args":            []interface{}{"run", "--config", sidecarConfigMount + "/" + sidecarConfigFile},
							"imagePullPolicy": "IfNotPresent",
							"ports": []interface{}{
								map[string]interface{}{"name": "http", "containerPort": sidecarHealthPort, "protocol": "TCP"},
								map[string]interface{}{"name": "metrics", "containerPort": sidecarMetricsPort, "protocol": "TCP"},
							},
							"volumeMounts": []interface{}{
								map[string]interface{}{
									"name":      sidecarConfigVolume,
									"mountPath": sidecarConfigMount,
									"readOnly":  true,
								},
							},
							"resources": map[string]interface{}{
								"requests": map[string]interface{}{"cpu": proxyCPURequest, "memory": proxyMemoryRequest},
								"limits":   map[string]interface{}{"cpu": proxyCPULimit, "memory": proxyMemoryLimit},
							},
							"readinessProbe": map[string]interface{}{
								"httpGet":             map[string]interface{}{"path": sidecarHealthPath, "port": "http"},
								"initialDelaySeconds": 2,
								"periodSeconds":       10,
							},
							"livenessProbe": map[string]interface{}{
								"httpGet":             map[string]interface{}{"path": sidecarHealthPath, "port": "http"},
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
						},
					},
					"volumes": []interface{}{
						map[string]interface{}{
							"name": sidecarConfigVolume,
							"configMap": map[string]interface{}{
								"name": proxyName,
							},
						},
					},
				},
			},
		},
	}
	out, err := yaml.Marshal(deploy)
	if err != nil {
		return "", fmt.Errorf("marshaling Deployment: %w", err)
	}
	return string(out), nil
}

func renderProxyService(namespace, proxyName string, proxyLabels map[string]string) (string, error) {
	svc := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name":      proxyName,
			"namespace": namespace,
			"labels":    labelsToInterfaceMap(managedProxyResourceLabels(proxyLabels, "proxy")),
		},
		"spec": map[string]interface{}{
			"type":     "ClusterIP",
			"selector": labelsToInterfaceMap(proxyLabels),
			"ports": []interface{}{
				map[string]interface{}{"name": "http", "port": sidecarHealthPort, "targetPort": "http", "protocol": "TCP"},
				map[string]interface{}{"name": "metrics", "port": sidecarMetricsPort, "targetPort": "metrics", "protocol": "TCP"},
			},
		},
	}
	out, err := yaml.Marshal(svc)
	if err != nil {
		return "", fmt.Errorf("marshaling Service: %w", err)
	}
	return string(out), nil
}

func renderAgentNetworkPolicy(namespace, workloadName string, agentLabels, proxyLabels map[string]string) (string, error) {
	if len(agentLabels) == 0 || len(proxyLabels) == 0 {
		return "", fmt.Errorf("agent and proxy selector labels must not be empty")
	}
	np := map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]interface{}{
			"name":      kubeResourceName(workloadName, "pipelock-egress"),
			"namespace": namespace,
			"labels":    labelsToInterfaceMap(managedComponentLabels("agent-network-policy")),
		},
		"spec": map[string]interface{}{
			"podSelector": map[string]interface{}{
				"matchLabels": labelsToInterfaceMap(agentLabels),
			},
			"policyTypes": []interface{}{"Egress"},
			"egress": []interface{}{
				map[string]interface{}{
					"ports": []interface{}{
						map[string]interface{}{"port": 53, "protocol": "UDP"},
						map[string]interface{}{"port": 53, "protocol": "TCP"},
					},
				},
				map[string]interface{}{
					"to": []interface{}{
						map[string]interface{}{
							"podSelector": map[string]interface{}{
								"matchLabels": labelsToInterfaceMap(proxyLabels),
							},
						},
					},
					"ports": []interface{}{
						map[string]interface{}{"port": sidecarHealthPort, "protocol": "TCP"},
					},
				},
			},
		},
	}
	out, err := yaml.Marshal(np)
	if err != nil {
		return "", fmt.Errorf("marshaling agent NetworkPolicy: %w", err)
	}
	return string(out), nil
}

func renderProxyNetworkPolicy(namespace, proxyName string, proxyLabels, agentLabels map[string]string) (string, error) {
	if len(agentLabels) == 0 || len(proxyLabels) == 0 {
		return "", fmt.Errorf("agent and proxy selector labels must not be empty")
	}
	np := map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]interface{}{
			"name":      kubeResourceName(proxyName, "policy"),
			"namespace": namespace,
			"labels":    labelsToInterfaceMap(managedProxyResourceLabels(proxyLabels, "network-policy")),
		},
		"spec": map[string]interface{}{
			"podSelector": map[string]interface{}{
				"matchLabels": labelsToInterfaceMap(proxyLabels),
			},
			"policyTypes": []interface{}{"Ingress", "Egress"},
			"ingress": []interface{}{
				map[string]interface{}{
					"from": []interface{}{
						map[string]interface{}{
							"podSelector": map[string]interface{}{
								"matchLabels": labelsToInterfaceMap(agentLabels),
							},
						},
					},
					"ports": []interface{}{
						map[string]interface{}{"port": sidecarHealthPort, "protocol": "TCP"},
					},
				},
			},
			"egress": []interface{}{
				map[string]interface{}{
					"ports": []interface{}{
						map[string]interface{}{"port": 53, "protocol": "UDP"},
						map[string]interface{}{"port": 53, "protocol": "TCP"},
					},
				},
				map[string]interface{}{
					"ports": []interface{}{
						map[string]interface{}{"port": 80, "protocol": "TCP"},
						map[string]interface{}{"port": 443, "protocol": "TCP"},
					},
				},
			},
		},
	}
	out, err := yaml.Marshal(np)
	if err != nil {
		return "", fmt.Errorf("marshaling proxy NetworkPolicy: %w", err)
	}
	return string(out), nil
}

func renderProxyPodDisruptionBudget(namespace, proxyName string, proxyLabels map[string]string) (string, error) {
	pdb := map[string]interface{}{
		"apiVersion": "policy/v1",
		"kind":       "PodDisruptionBudget",
		"metadata": map[string]interface{}{
			"name":      kubeResourceName(proxyName, "pdb"),
			"namespace": namespace,
			"labels":    labelsToInterfaceMap(managedProxyResourceLabels(proxyLabels, "pdb")),
		},
		"spec": map[string]interface{}{
			"minAvailable": 1,
			"selector": map[string]interface{}{
				"matchLabels": labelsToInterfaceMap(proxyLabels),
			},
		},
	}
	out, err := yaml.Marshal(pdb)
	if err != nil {
		return "", fmt.Errorf("marshaling PodDisruptionBudget: %w", err)
	}
	return string(out), nil
}

func hasPipelockTopology(raw map[string]interface{}) bool {
	return extractAnnotation(raw, managedTopologyAnnotation) == managedTopologyCompanion
}

func resolveProxyName(raw map[string]interface{}, workloadName string) string {
	if existing := extractAnnotation(raw, managedProxyNameAnnotation); existing != "" {
		return existing
	}
	return kubeResourceName(workloadName, "pipelock")
}

func extractAnnotation(raw map[string]interface{}, key string) string {
	meta, ok := raw["metadata"].(map[string]interface{})
	if !ok {
		return ""
	}
	annotations, ok := meta["annotations"].(map[string]interface{})
	if !ok {
		return ""
	}
	value, _ := annotations[key].(string)
	return value
}

func proxyServiceURL(proxyName string) string {
	return fmt.Sprintf("http://%s:%d", proxyName, sidecarHealthPort)
}

func proxySelectorLabels(proxyName string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "pipelock",
		"app.kubernetes.io/instance":  proxyName,
		"app.kubernetes.io/component": "proxy",
	}
}

func managedProxyResourceLabels(proxyLabels map[string]string, component string) map[string]string {
	labels := cloneStringMap(proxyLabels)
	labels["app.kubernetes.io/component"] = component
	labels["app.kubernetes.io/managed-by"] = managedByLabelValue
	labels["app.kubernetes.io/version"] = cliutil.Version
	return labels
}

func managedComponentLabels(component string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "pipelock",
		"app.kubernetes.io/component":  component,
		"app.kubernetes.io/managed-by": managedByLabelValue,
		"app.kubernetes.io/version":    cliutil.Version,
	}
}

func annotateManagedWorkload(raw map[string]interface{}, kind, proxyName string) error {
	annotations := map[string]string{
		managedTopologyAnnotation:     managedTopologyCompanion,
		managedProxyNameAnnotation:    proxyName,
		managedProxyServiceAnnotation: proxyServiceURL(proxyName),
	}
	if err := setAnnotationsAtPath(raw, []string{"metadata", "annotations"}, annotations); err != nil {
		return err
	}
	templatePath := []string{"spec", "template", "metadata", "annotations"}
	if kind == kindCronJob {
		templatePath = []string{"spec", "jobTemplate", "spec", "template", "metadata", "annotations"}
	}
	return setAnnotationsAtPath(raw, templatePath, annotations)
}

func setAnnotationsAtPath(raw map[string]interface{}, path []string, annotations map[string]string) error {
	current, err := ensureMapAtPath(raw, path)
	if err != nil {
		return err
	}
	for key, value := range annotations {
		current[key] = value
	}
	return nil
}

func ensureMapAtPath(raw map[string]interface{}, path []string) (map[string]interface{}, error) {
	current := raw
	for i, key := range path {
		if i == len(path)-1 {
			next, ok := current[key]
			if !ok {
				nextMap := map[string]interface{}{}
				current[key] = nextMap
				return nextMap, nil
			}
			nextMap, ok := next.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("%s is not a mapping in manifest", pathString(path[:i+1]))
			}
			return nextMap, nil
		}

		next, ok := current[key]
		if !ok {
			nextMap := map[string]interface{}{}
			current[key] = nextMap
			current = nextMap
			continue
		}
		nextMap, ok := next.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s is not a mapping in manifest", pathString(path[:i+1]))
		}
		current = nextMap
	}
	return current, nil
}

func labelsToInterfaceMap(labels map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(labels))
	for key, value := range labels {
		out[key] = value
	}
	return out
}

func cloneStringMap(src map[string]string) map[string]string {
	out := make(map[string]string, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func kubeResourceName(base, suffix string) string {
	base = sanitizeDNSLabel(base)
	suffix = sanitizeDNSLabel(suffix)
	switch {
	case base == "" && suffix == "":
		return "pipelock"
	case base == "":
		return suffix
	case suffix == "":
		return base
	}

	maxBaseLen := 63 - len(suffix) - 1
	if maxBaseLen > 0 && len(base) > maxBaseLen {
		base = strings.Trim(base[:maxBaseLen], "-")
	}
	name := strings.Trim(base+"-"+suffix, "-")
	if len(name) > 63 {
		name = strings.Trim(name[:63], "-")
	}
	if name == "" {
		return "pipelock"
	}
	return name
}

func sanitizeDNSLabel(input string) string {
	lower := strings.ToLower(input)
	var sb strings.Builder
	lastDash := false
	for _, r := range lower {
		isAlpha := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		if isAlpha || isDigit {
			sb.WriteRune(r)
			lastDash = false
			continue
		}
		if sb.Len() == 0 || lastDash {
			continue
		}
		sb.WriteByte('-')
		lastDash = true
	}
	return strings.Trim(sb.String(), "-")
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
