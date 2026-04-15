// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// Emit format constants.
const (
	emitPatch      = "patch"
	emitKustomize  = "kustomize"
	emitHelmValues = "helm-values"
)

type imageRef struct {
	Repository string
	Tag        string
	Digest     string
}

// emitPatched writes the patched manifest in the requested format.
func emitPatched(w io.Writer, result *sidecarPatchResult, opts sidecarOptions) error {
	switch opts.emit {
	case emitPatch:
		return emitPatchFormat(w, result, opts)
	case emitKustomize:
		return emitKustomizeFormat(result, opts)
	case emitHelmValues:
		return emitHelmValuesFormat(w, result, opts)
	default:
		return fmt.Errorf("unknown emit format %q; supported: patch, kustomize, helm-values", opts.emit)
	}
}

// emitPatchFormat writes the full enforced topology bundle as standalone YAML.
func emitPatchFormat(w io.Writer, result *sidecarPatchResult, opts sidecarOptions) error {
	data, err := yaml.Marshal(result.PatchedManifest)
	if err != nil {
		return fmt.Errorf("marshaling patched manifest: %w", err)
	}

	output := string(data) +
		"---\n" + result.ConfigMapYAML +
		"---\n" + result.DeploymentYAML +
		"---\n" + result.ServiceYAML +
		"---\n" + result.AgentNetworkPolicyYAML +
		"---\n" + result.ProxyNetworkPolicyYAML +
		"---\n" + result.PodDisruptionBudgetYAML

	return writeOutput(w, []byte(output), opts.output, opts.force)
}

// emitKustomizeFormat writes a standalone kustomize bundle directory.
func emitKustomizeFormat(result *sidecarPatchResult, opts sidecarOptions) error {
	outDir := opts.output
	if outDir == "" {
		return fmt.Errorf("--output directory required for kustomize format")
	}

	cleanDir := filepath.Clean(outDir)
	if err := os.MkdirAll(cleanDir, 0o750); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	agentData, err := yaml.Marshal(result.PatchedManifest)
	if err != nil {
		return fmt.Errorf("marshaling agent manifest: %w", err)
	}
	workloadPath := filepath.Join(cleanDir, "agent-workload.yaml")
	if err := writeOutput(nil, agentData, workloadPath, opts.force); err != nil {
		return fmt.Errorf("writing %s: %w", workloadPath, err)
	}

	// Write the ConfigMap.
	cmPath := filepath.Join(cleanDir, "pipelock-configmap.yaml")
	if err := writeOutput(nil, []byte(result.ConfigMapYAML), cmPath, opts.force); err != nil {
		return fmt.Errorf("writing %s: %w", cmPath, err)
	}

	deployPath := filepath.Join(cleanDir, "pipelock-deployment.yaml")
	if err := writeOutput(nil, []byte(result.DeploymentYAML), deployPath, opts.force); err != nil {
		return fmt.Errorf("writing %s: %w", deployPath, err)
	}

	servicePath := filepath.Join(cleanDir, "pipelock-service.yaml")
	if err := writeOutput(nil, []byte(result.ServiceYAML), servicePath, opts.force); err != nil {
		return fmt.Errorf("writing %s: %w", servicePath, err)
	}

	agentPolicyPath := filepath.Join(cleanDir, "agent-networkpolicy.yaml")
	if err := writeOutput(nil, []byte(result.AgentNetworkPolicyYAML), agentPolicyPath, opts.force); err != nil {
		return fmt.Errorf("writing %s: %w", agentPolicyPath, err)
	}

	proxyPolicyPath := filepath.Join(cleanDir, "pipelock-networkpolicy.yaml")
	if err := writeOutput(nil, []byte(result.ProxyNetworkPolicyYAML), proxyPolicyPath, opts.force); err != nil {
		return fmt.Errorf("writing %s: %w", proxyPolicyPath, err)
	}

	pdbPath := filepath.Join(cleanDir, "pipelock-pdb.yaml")
	if err := writeOutput(nil, []byte(result.PodDisruptionBudgetYAML), pdbPath, opts.force); err != nil {
		return fmt.Errorf("writing %s: %w", pdbPath, err)
	}

	kustomization := map[string]interface{}{
		"apiVersion": "kustomize.config.k8s.io/v1beta1",
		"kind":       "Kustomization",
		"resources": []interface{}{
			"agent-workload.yaml",
			"pipelock-configmap.yaml",
			"pipelock-deployment.yaml",
			"pipelock-service.yaml",
			"agent-networkpolicy.yaml",
			"pipelock-networkpolicy.yaml",
			"pipelock-pdb.yaml",
		},
	}
	kustomizationData, err := yaml.Marshal(kustomization)
	if err != nil {
		return fmt.Errorf("marshaling kustomization.yaml: %w", err)
	}
	kustomizationPath := filepath.Join(cleanDir, "kustomization.yaml")
	if err := writeOutput(nil, kustomizationData, kustomizationPath, opts.force); err != nil {
		return fmt.Errorf("writing %s: %w", kustomizationPath, err)
	}

	return nil
}

// emitHelmValuesFormat writes a Helm bundle directory: chart values plus the
// patched agent workload and the companion NetworkPolicies.
func emitHelmValuesFormat(w io.Writer, result *sidecarPatchResult, opts sidecarOptions) error {
	_ = w
	outDir := opts.output
	if outDir == "" {
		return fmt.Errorf("--output directory required for helm-values format")
	}

	values := map[string]interface{}{
		"replicaCount":     proxyReplicaCount,
		"fullnameOverride": result.ProxyName,
		"image": map[string]interface{}{
			"repository": defaultImageRepo,
			"tag":        cliutil.Version,
			"digest":     "",
			"pullPolicy": "IfNotPresent",
		},
		"resources": map[string]interface{}{
			"requests": map[string]interface{}{"cpu": proxyCPURequest, "memory": proxyMemoryRequest},
			"limits":   map[string]interface{}{"cpu": proxyCPULimit, "memory": proxyMemoryLimit},
		},
		"podLabels": map[string]interface{}{
			"app.kubernetes.io/component": "proxy",
		},
		"affinity": map[string]interface{}{
			"podAntiAffinity": map[string]interface{}{
				"preferredDuringSchedulingIgnoredDuringExecution": []interface{}{
					map[string]interface{}{
						"weight": 100,
						"podAffinityTerm": map[string]interface{}{
							"labelSelector": map[string]interface{}{
								"matchExpressions": []interface{}{
									map[string]interface{}{
										"key":      "app.kubernetes.io/instance",
										"operator": "In",
										"values":   []interface{}{result.ProxyName},
									},
								},
							},
							"topologyKey": "kubernetes.io/hostname",
						},
					},
				},
			},
		},
		"pipelock": map[string]interface{}{
			"mode": opts.preset,
			"forward_proxy": map[string]interface{}{
				"enabled": true,
			},
			"default_agent_identity":      result.AgentIdentity,
			"bind_default_agent_identity": true,
		},
		"networkPolicy": map[string]interface{}{
			"enabled": false,
		},
	}

	if opts.image != "" {
		parsed := parseImageRef(opts.image)
		img := values["image"].(map[string]interface{})
		img["repository"] = parsed.Repository
		img["tag"] = parsed.Tag
		img["digest"] = parsed.Digest
	}

	data, err := yaml.Marshal(values)
	if err != nil {
		return fmt.Errorf("marshaling helm values: %w", err)
	}

	cleanDir := filepath.Clean(outDir)
	if err := os.MkdirAll(cleanDir, 0o750); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	header := "# Pipelock Helm bundle values\n# Generated by: pipelock init sidecar --emit helm-values\n# Use release name: " + result.ProxyName + "\n\n"
	if err := writeOutput(nil, []byte(header+string(data)), filepath.Join(cleanDir, "values.yaml"), opts.force); err != nil {
		return err
	}

	agentData, err := yaml.Marshal(result.PatchedManifest)
	if err != nil {
		return fmt.Errorf("marshaling agent manifest: %w", err)
	}
	if err := writeOutput(nil, agentData, filepath.Join(cleanDir, "agent-workload.yaml"), opts.force); err != nil {
		return err
	}
	if err := writeOutput(nil, []byte(result.AgentNetworkPolicyYAML), filepath.Join(cleanDir, "agent-networkpolicy.yaml"), opts.force); err != nil {
		return err
	}
	if err := writeOutput(nil, []byte(result.ProxyNetworkPolicyYAML), filepath.Join(cleanDir, "pipelock-networkpolicy.yaml"), opts.force); err != nil {
		return err
	}
	if err := writeOutput(nil, []byte(result.PodDisruptionBudgetYAML), filepath.Join(cleanDir, "pipelock-pdb.yaml"), opts.force); err != nil {
		return err
	}

	readme := fmt.Sprintf("helm upgrade --install %s pipelock/pipelock -f %s\nkubectl rollout status deployment/%s\nkubectl apply -f %s -f %s\nkubectl apply -f %s\nkubectl apply -f %s\n",
		result.ProxyName,
		filepath.Join(cleanDir, "values.yaml"),
		result.ProxyName,
		filepath.Join(cleanDir, "pipelock-networkpolicy.yaml"),
		filepath.Join(cleanDir, "pipelock-pdb.yaml"),
		filepath.Join(cleanDir, "agent-networkpolicy.yaml"),
		filepath.Join(cleanDir, "agent-workload.yaml"),
	)
	return writeOutput(nil, []byte(readme), filepath.Join(cleanDir, "README.txt"), opts.force)
}

// writeOutput writes data to a file or stdout.
func writeOutput(w io.Writer, data []byte, outputPath string, force bool) error {
	if outputPath == "" {
		if w == nil {
			w = os.Stdout
		}
		_, err := w.Write(data)
		return err
	}

	cleanPath := filepath.Clean(outputPath)

	// Refuse to overwrite without --force.
	if _, err := os.Stat(cleanPath); err == nil && !force {
		return fmt.Errorf("output file %s already exists; use --force to overwrite", cleanPath)
	}

	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}

	if err := os.WriteFile(cleanPath, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", cleanPath, err)
	}

	return nil
}

// parseImageRef splits a container image reference into repository, tag, and digest.
func parseImageRef(ref string) imageRef {
	if repo, digest, ok := strings.Cut(ref, "@"); ok {
		return imageRef{Repository: repo, Digest: digest}
	}

	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon > lastSlash {
		return imageRef{
			Repository: ref[:lastColon],
			Tag:        ref[lastColon+1:],
		}
	}

	return imageRef{Repository: ref, Tag: "latest"}
}
