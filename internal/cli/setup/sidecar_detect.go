// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Supported workload kinds for sidecar injection.
const (
	kindDeployment  = "Deployment"
	kindStatefulSet = "StatefulSet"
	kindJob         = "Job"
	kindCronJob     = "CronJob"
)

// supportedKinds lists the 4 accepted workload types.
var supportedKinds = []string{kindDeployment, kindStatefulSet, kindJob, kindCronJob}

// workloadManifest holds the parsed workload metadata and raw YAML.
type workloadManifest struct {
	Kind     string
	Name     string
	Raw      map[string]interface{}
	RawBytes []byte
}

// detectWorkload reads a YAML file and identifies the workload kind and pod spec path.
// Returns an error for unsupported kinds with a clear message listing supported types.
func detectWorkload(path string) (*workloadManifest, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("reading manifest %s: %w", cleanPath, err)
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing manifest %s: %w", cleanPath, err)
	}

	kind, _ := raw["kind"].(string)
	if kind == "" {
		return nil, fmt.Errorf("manifest %s: missing or empty 'kind' field", cleanPath)
	}

	if !isSupportedKind(kind) {
		return nil, fmt.Errorf("unsupported workload kind %q; supported: %v", kind, supportedKinds)
	}

	// Extract the workload name from metadata.
	name := extractWorkloadName(raw)

	return &workloadManifest{
		Kind:     kind,
		Name:     name,
		Raw:      raw,
		RawBytes: data,
	}, nil
}

// podSpecPath returns the YAML path segments to the pod spec for each workload kind.
// Deployment/StatefulSet: spec.template.spec
// Job: spec.template.spec
// CronJob: spec.jobTemplate.spec.template.spec.
func podSpecPath(kind string) []string {
	switch kind {
	case kindCronJob:
		return []string{"spec", "jobTemplate", "spec", "template", "spec"}
	default:
		// Deployment, StatefulSet, Job all use spec.template.spec
		return []string{"spec", "template", "spec"}
	}
}

// getPodSpec navigates the raw YAML tree to the pod spec using the kind-specific path.
func getPodSpec(raw map[string]interface{}, kind string) (map[string]interface{}, error) {
	path := podSpecPath(kind)
	current := raw
	for i, key := range path {
		next, ok := current[key]
		if !ok {
			return nil, fmt.Errorf("missing %s in manifest (expected path: %s)", key, pathString(path[:i+1]))
		}
		nextMap, ok := next.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s is not a mapping in manifest", pathString(path[:i+1]))
		}
		current = nextMap
	}
	return current, nil
}

// hasPipelockContainer returns true if a pipelock sidecar container already exists.
func hasPipelockContainer(podSpec map[string]interface{}) bool {
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return false
	}
	for _, c := range containers {
		cMap, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := cMap["name"].(string)
		if name == sidecarContainerName {
			return true
		}
	}
	return false
}

// isSupportedKind checks if a workload kind is in the supported list.
func isSupportedKind(kind string) bool {
	for _, k := range supportedKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// extractWorkloadName gets the name from metadata.name.
func extractWorkloadName(raw map[string]interface{}) string {
	meta, ok := raw["metadata"].(map[string]interface{})
	if !ok {
		return ""
	}
	name, _ := meta["name"].(string)
	return name
}

func pathString(path []string) string {
	result := ""
	for i, p := range path {
		if i > 0 {
			result += "."
		}
		result += p
	}
	return result
}
