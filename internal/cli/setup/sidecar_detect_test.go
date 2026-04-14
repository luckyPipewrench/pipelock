// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testdataSidecarDir = "testdata/sidecar"
)

func testdataPath(t *testing.T, filename string) string {
	t.Helper()
	return filepath.Join(testdataSidecarDir, filename)
}

func TestDetectWorkload(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		wantKind string
		wantName string
	}{
		{
			name:     "deployment",
			file:     "deployment.yaml",
			wantKind: kindDeployment,
			wantName: "my-agent",
		},
		{
			name:     "statefulset",
			file:     "statefulset.yaml",
			wantKind: kindStatefulSet,
			wantName: "my-db-agent",
		},
		{
			name:     "job",
			file:     "job.yaml",
			wantKind: kindJob,
			wantName: "batch-runner",
		},
		{
			name:     "cronjob",
			file:     "cronjob.yaml",
			wantKind: kindCronJob,
			wantName: "scheduled-scan",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest, err := detectWorkload(testdataPath(t, tc.file))
			if err != nil {
				t.Fatalf("detectWorkload(%s): %v", tc.file, err)
			}
			if manifest.Kind != tc.wantKind {
				t.Errorf("Kind = %q, want %q", manifest.Kind, tc.wantKind)
			}
			if manifest.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", manifest.Name, tc.wantName)
			}
			if manifest.Raw == nil {
				t.Error("Raw should not be nil")
			}
			if len(manifest.RawBytes) == 0 {
				t.Error("RawBytes should not be empty")
			}
		})
	}
}

func TestDetectWorkload_UnsupportedKind(t *testing.T) {
	dir := t.TempDir()
	daemonsetYAML := `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: log-collector
spec:
  selector:
    matchLabels:
      app: log-collector
  template:
    spec:
      containers:
        - name: collector
          image: fluentd:latest
`
	path := filepath.Join(dir, "daemonset.yaml")
	if err := os.WriteFile(path, []byte(daemonsetYAML), 0o600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	_, err := detectWorkload(path)
	if err == nil {
		t.Fatal("expected error for unsupported kind DaemonSet")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "unsupported") {
		t.Errorf("error should contain 'unsupported', got: %s", errMsg)
	}
	// Verify the error lists supported kinds.
	for _, kind := range supportedKinds {
		if !strings.Contains(errMsg, kind) {
			t.Errorf("error should list supported kind %q, got: %s", kind, errMsg)
		}
	}
}

func TestDetectWorkload_MissingKind(t *testing.T) {
	dir := t.TempDir()
	noKindYAML := `apiVersion: v1
metadata:
  name: something
spec:
  replicas: 1
`
	path := filepath.Join(dir, "nokind.yaml")
	if err := os.WriteFile(path, []byte(noKindYAML), 0o600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	_, err := detectWorkload(path)
	if err == nil {
		t.Fatal("expected error for missing kind field")
	}
	if !strings.Contains(err.Error(), "kind") {
		t.Errorf("error should mention 'kind', got: %s", err.Error())
	}
}

func TestDetectWorkload_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("{{not: valid: yaml::: ["), 0o600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	_, err := detectWorkload(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "parsing") {
		t.Errorf("error should mention 'parsing', got: %s", err.Error())
	}
}

func TestDetectWorkload_NotFound(t *testing.T) {
	_, err := detectWorkload(filepath.Clean("/tmp/nonexistent-pipelock-test-file-404.yaml"))
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
	if !strings.Contains(err.Error(), "reading") {
		t.Errorf("error should mention 'reading', got: %s", err.Error())
	}
}

func TestPodSpecPath(t *testing.T) {
	tests := []struct {
		name     string
		kind     string
		wantPath []string
	}{
		{
			name:     "deployment",
			kind:     kindDeployment,
			wantPath: []string{"spec", "template", "spec"},
		},
		{
			name:     "statefulset",
			kind:     kindStatefulSet,
			wantPath: []string{"spec", "template", "spec"},
		},
		{
			name:     "job",
			kind:     kindJob,
			wantPath: []string{"spec", "template", "spec"},
		},
		{
			name:     "cronjob",
			kind:     kindCronJob,
			wantPath: []string{"spec", "jobTemplate", "spec", "template", "spec"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := podSpecPath(tc.kind)
			if len(got) != len(tc.wantPath) {
				t.Fatalf("podSpecPath(%s) length = %d, want %d", tc.kind, len(got), len(tc.wantPath))
			}
			for i := range got {
				if got[i] != tc.wantPath[i] {
					t.Errorf("podSpecPath(%s)[%d] = %q, want %q", tc.kind, i, got[i], tc.wantPath[i])
				}
			}
		})
	}
}

func TestGetPodSpec(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		wantKind string
	}{
		{name: "deployment", file: "deployment.yaml", wantKind: kindDeployment},
		{name: "statefulset", file: "statefulset.yaml", wantKind: kindStatefulSet},
		{name: "job", file: "job.yaml", wantKind: kindJob},
		{name: "cronjob", file: "cronjob.yaml", wantKind: kindCronJob},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest, err := detectWorkload(testdataPath(t, tc.file))
			if err != nil {
				t.Fatalf("detectWorkload: %v", err)
			}

			podSpec, err := getPodSpec(manifest.Raw, manifest.Kind)
			if err != nil {
				t.Fatalf("getPodSpec(%s): %v", tc.wantKind, err)
			}

			// Every testdata file has a containers list in the pod spec.
			containers, ok := podSpec["containers"].([]interface{})
			if !ok {
				t.Fatal("pod spec missing containers list")
			}
			if len(containers) == 0 {
				t.Fatal("containers list is empty")
			}
		})
	}
}

func TestGetPodSpec_MissingPath(t *testing.T) {
	raw := map[string]interface{}{
		"kind": kindDeployment,
		"spec": map[string]interface{}{},
	}

	_, err := getPodSpec(raw, kindDeployment)
	if err == nil {
		t.Fatal("expected error for missing pod spec path")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error should contain 'missing', got: %s", err.Error())
	}
}

func TestGetPodSpec_NotAMapping(t *testing.T) {
	raw := map[string]interface{}{
		"kind": kindDeployment,
		"spec": map[string]interface{}{
			"template": "not-a-map",
		},
	}

	_, err := getPodSpec(raw, kindDeployment)
	if err == nil {
		t.Fatal("expected error for non-mapping node")
	}
	if !strings.Contains(err.Error(), "not a mapping") {
		t.Errorf("error should contain 'not a mapping', got: %s", err.Error())
	}
}

func TestHasPipelockContainer(t *testing.T) {
	tests := []struct {
		name    string
		podSpec map[string]interface{}
		want    bool
	}{
		{
			name: "has pipelock container",
			podSpec: map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "agent"},
					map[string]interface{}{"name": sidecarContainerName},
				},
			},
			want: true,
		},
		{
			name: "no pipelock container",
			podSpec: map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "agent"},
					map[string]interface{}{"name": "other-sidecar"},
				},
			},
			want: false,
		},
		{
			name:    "no containers key",
			podSpec: map[string]interface{}{},
			want:    false,
		},
		{
			name: "empty containers list",
			podSpec: map[string]interface{}{
				"containers": []interface{}{},
			},
			want: false,
		},
		{
			name: "containers is wrong type",
			podSpec: map[string]interface{}{
				"containers": "not-a-list",
			},
			want: false,
		},
		{
			name: "container entry is wrong type",
			podSpec: map[string]interface{}{
				"containers": []interface{}{
					"not-a-map",
				},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hasPipelockContainer(tc.podSpec)
			if got != tc.want {
				t.Errorf("hasPipelockContainer() = %v, want %v", got, tc.want)
			}
		})
	}
}
