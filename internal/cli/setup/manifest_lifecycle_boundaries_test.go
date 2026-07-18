// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestProxyEnvTransaction_DoesNotPublishPartialMutation(t *testing.T) {
	originalEnv := []interface{}{
		map[string]interface{}{"name": "KEEP", "value": "yes"},
		map[string]interface{}{"name": envHTTPProxy, "value": "http://direct.example"},
	}
	podSpec := map[string]interface{}{
		"containers": []interface{}{
			"malformed",
			map[string]interface{}{"name": proxyContainerName},
			map[string]interface{}{"name": "agent", "env": originalEnv},
		},
	}
	before := cloneManifestValue(t, podSpec)

	err := injectProxyEnvs(podSpec, "http://proxy:8888", "", "")
	if err == nil || !strings.Contains(err.Error(), envHTTPProxy+" already defined") {
		t.Fatalf("error = %v, want conflicting proxy rejection", err)
	}
	if !reflect.DeepEqual(podSpec, before) {
		t.Fatalf("failed injection changed manifest:\n got: %#v\nwant: %#v", podSpec, before)
	}
}

func TestProxyEnvMutation_MalformedContainersAndValueSources(t *testing.T) {
	if err := injectProxyEnvs(map[string]interface{}{"containers": "bad"}, "http://proxy", "", ""); err != nil {
		t.Fatalf("malformed containers should be ignored without mutation: %v", err)
	}

	podSpec := map[string]interface{}{
		"containers": []interface{}{
			map[string]interface{}{
				"name": "agent",
				"env": []interface{}{
					"malformed",
					map[string]interface{}{
						"name":      envHTTPSProxy,
						"valueFrom": map[string]interface{}{"secretKeyRef": map[string]interface{}{"name": "proxy"}},
					},
				},
			},
		},
	}
	err := injectProxyEnvs(podSpec, "http://proxy", "", "")
	if err == nil || !strings.Contains(err.Error(), "defined via valueFrom") {
		t.Fatalf("error = %v, want valueFrom rejection", err)
	}
}

func TestMCPMountMutation_RejectsConflictsWithoutReplacingOperatorState(t *testing.T) {
	podSpec := map[string]interface{}{
		"volumes": []interface{}{
			"malformed",
			map[string]interface{}{"name": "operator", "emptyDir": map[string]interface{}{}},
			map[string]interface{}{
				"name":      sidecarMCPConfigVolume,
				"configMap": map[string]interface{}{"name": "operator-config"},
			},
		},
		"containers": []interface{}{
			"malformed",
			map[string]interface{}{"name": proxyContainerName},
			map[string]interface{}{
				"name": "agent",
				"volumeMounts": []interface{}{
					"malformed",
					map[string]interface{}{"name": "operator", "mountPath": sidecarMCPConfigMount},
				},
			},
		},
	}
	before := cloneManifestValue(t, podSpec)

	err := configureMCPClientConfigMount(podSpec, "wanted-config", sidecarMCPConfigPath())
	if err == nil || !strings.Contains(err.Error(), "already uses ConfigMap") {
		t.Fatalf("error = %v, want ConfigMap ownership rejection", err)
	}
	if !reflect.DeepEqual(podSpec, before) {
		t.Fatalf("ConfigMap conflict changed operator state:\n got: %#v\nwant: %#v", podSpec, before)
	}

	podSpec["volumes"].([]interface{})[2].(map[string]interface{})["configMap"] = map[string]interface{}{"name": "wanted-config"}
	err = configureMCPClientConfigMount(podSpec, "wanted-config", sidecarMCPConfigPath())
	if err == nil || !strings.Contains(err.Error(), "mountPath") {
		t.Fatalf("error = %v, want mount-path ownership rejection", err)
	}
}

func TestMCPMountLifecycle_IdempotentEnableAndTotalDisable(t *testing.T) {
	podSpec := map[string]interface{}{
		"volumes": []interface{}{
			"malformed",
			map[string]interface{}{
				"name":      sidecarMCPConfigVolume,
				"configMap": map[string]interface{}{"name": "agent-mcp"},
			},
		},
		"containers": []interface{}{
			"malformed",
			map[string]interface{}{"name": proxyContainerName},
			map[string]interface{}{
				"name": "agent",
				"volumeMounts": []interface{}{
					"malformed",
					map[string]interface{}{
						"name":      sidecarMCPConfigVolume,
						"mountPath": sidecarMCPConfigMount,
						"readOnly":  false,
					},
				},
			},
		},
	}

	if err := configureMCPClientConfigMount(podSpec, "agent-mcp", sidecarMCPConfigPath()); err != nil {
		t.Fatalf("idempotent enable failed: %v", err)
	}
	agent := podSpec["containers"].([]interface{})[2].(map[string]interface{})
	mount := agent["volumeMounts"].([]interface{})[1].(map[string]interface{})
	if mount["readOnly"] != true {
		t.Fatalf("managed mount was not tightened to read-only: %#v", mount)
	}

	if err := configureMCPClientConfigMount(podSpec, "", ""); err != nil {
		t.Fatalf("disable failed: %v", err)
	}
	volumes := podSpec["volumes"].([]interface{})
	if len(volumes) != 1 || volumes[0] != "malformed" {
		t.Fatalf("disable did not remove only the managed volume: %#v", volumes)
	}
	mounts := agent["volumeMounts"].([]interface{})
	if len(mounts) != 1 || mounts[0] != "malformed" {
		t.Fatalf("disable did not remove only the managed mount: %#v", mounts)
	}

	removePodSpecVolume(map[string]interface{}{}, sidecarMCPConfigVolume)
	removeContainerVolumeMounts(map[string]interface{}{}, sidecarMCPConfigVolume)
}

func TestManifestMapPaths_RejectScalarParentsAndCreateMissingMaps(t *testing.T) {
	raw := map[string]interface{}{"metadata": "scalar"}
	if _, err := ensureMapAtPath(raw, []string{"metadata", "annotations"}); err == nil {
		t.Fatal("scalar parent was accepted as a map")
	}

	raw = map[string]interface{}{"metadata": map[string]interface{}{"annotations": "scalar"}}
	if err := removeAnnotationsAtPath(raw, []string{"metadata", "annotations"}, []string{"old"}); err == nil {
		t.Fatal("scalar annotation map was accepted")
	}

	raw = map[string]interface{}{}
	annotations, err := ensureMapAtPath(raw, []string{"spec", "template", "metadata", "annotations"})
	if err != nil {
		t.Fatalf("creating missing path: %v", err)
	}
	annotations["managed"] = "true"
	got := raw["spec"].(map[string]interface{})["template"].(map[string]interface{})["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["managed"]
	if got != "true" {
		t.Fatalf("created map was not attached to manifest: %v", got)
	}
}

func TestSelectorResolution_RejectsMalformedAndEmptyLabels(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]interface{}
		want string
	}{
		{
			name: "non-string template label",
			raw: map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"metadata": map[string]interface{}{
							"labels": map[string]interface{}{"app": 3},
						},
					},
				},
			},
			want: "pod template labels",
		},
		{
			name: "empty label values",
			raw: map[string]interface{}{
				"spec": map[string]interface{}{
					"selector": map[string]interface{}{
						"matchLabels": map[string]interface{}{"app": ""},
					},
					"template": map[string]interface{}{
						"metadata": map[string]interface{}{
							"labels": map[string]interface{}{"app": ""},
						},
					},
				},
			},
			want: "no selector.matchLabels",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			labels, err := networkPolicySelectorLabels(tc.raw, kindDeployment)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("labels=%v error=%v, want rejection containing %q", labels, err, tc.want)
			}
			if labels != nil {
				t.Fatalf("rejected selector returned labels: %v", labels)
			}
		})
	}
}

func TestVscodeInstall_SidecarFailurePreservesConfigAndBackup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := t.TempDir()
	chdirTemp(t, project)
	vsDir := filepath.Join(project, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(vsDir, "mcp.json")
	original := []byte(`{"servers":{"remote":{"type":"http","url":"https://api.vendor.example/mcp","headers":{"X-Tenant":"north"}}}}`)
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}

	sidecarDir := filepath.Join(home, ".config", "pipelock", "wrap-headers")
	if err := os.MkdirAll(filepath.Dir(sidecarDir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecarDir, []byte("blocks directory creation"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "writing header sidecar") {
		t.Fatalf("error = %v, want sidecar failure", err)
	}
	assertFileBytes(t, target, original)
	assertFileBytes(t, target+".bak", original)
}

func TestVscodeRemove_InvalidMetadataLeavesConfigAndSidecarUntouched(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := t.TempDir()
	chdirTemp(t, project)
	vsDir := filepath.Join(project, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}

	sidecar, err := headerSidecarPath(filepath.Join(".vscode", "mcp.json"), "remote")
	if err != nil {
		t.Fatal(err)
	}
	if err := commitHeaderSidecar(sidecar, []byte("X-Tenant: north\n")); err != nil {
		t.Fatal(err)
	}
	original := []byte(`{"servers":{"remote":{"type":"stdio","command":"/usr/bin/pipelock","args":["mcp","proxy"],"_pipelock":{"original_type":"http","header_sidecar_path":"relative.headers"}}}}`)
	target := filepath.Join(vsDir, "mcp.json")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := VscodeCmd()
	var stderr strings.Builder
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"remove", "--project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !strings.Contains(stderr.String(), "header sidecar path must be absolute") {
		t.Fatalf("missing fail-closed warning: %q", stderr.String())
	}
	assertFileBytes(t, target, original)
	assertFileBytes(t, sidecar, []byte("X-Tenant: north\n"))
}

func TestVscodeRemove_BackupFailureDoesNotDeleteSidecar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := t.TempDir()
	chdirTemp(t, project)
	vsDir := filepath.Join(project, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(vsDir, "mcp.json")
	sidecar, err := headerSidecarPath(target, "remote")
	if err != nil {
		t.Fatal(err)
	}
	if err := commitHeaderSidecar(sidecar, []byte("X-Tenant: north\n")); err != nil {
		t.Fatal(err)
	}
	metaPath := strings.ReplaceAll(sidecar, `\`, `\\`)
	wrapped := []byte(`{"servers":{"remote":{"type":"stdio","command":"/usr/bin/pipelock","args":["mcp","proxy"],"_pipelock":{"original_type":"http","original_url":"https://api.vendor.example/mcp","header_sidecar_path":"` + metaPath + `"}}}}`)
	if err := os.WriteFile(target, wrapped, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target+".bak", 0o750); err != nil {
		t.Fatal(err)
	}

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"remove", "--project"})
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "creating backup") {
		t.Fatalf("error = %v, want backup failure", err)
	}
	assertFileBytes(t, target, wrapped)
	assertFileBytes(t, sidecar, []byte("X-Tenant: north\n"))
}

func TestCommitHeaderSidecar_ParentFileFailsWithoutReplacement(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(parent, []byte("operator data"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "secret.headers")
	if err := commitHeaderSidecar(target, []byte("X: value\n")); err == nil {
		t.Fatal("sidecar write unexpectedly traversed a regular file")
	}
	assertFileBytes(t, parent, []byte("operator data"))
	removeHeaderSidecar("")
}

func TestManifestNameAndEndpointBoundaries(t *testing.T) {
	if got := kubeResourceName("", ""); got != "pipelock" {
		t.Fatalf("empty resource name = %q", got)
	}
	if got := kubeResourceName("", "proxy"); got != "proxy" {
		t.Fatalf("suffix-only resource name = %q", got)
	}
	if got := kubeResourceName("agent", ""); got != "agent" {
		t.Fatalf("base-only resource name = %q", got)
	}
	if got := kubeResourceName(strings.Repeat("a", 80), strings.Repeat("b", 80)); len(got) > 63 {
		t.Fatalf("resource name exceeds Kubernetes limit: %q", got)
	}

	cases := map[string]int{
		"":                       0,
		"://malformed":           0,
		"https://host.example":   443,
		"http://host.example":    80,
		"ssh://host.example":     0,
		"https://host.example:9": 9,
	}
	for raw, want := range cases {
		if got := mcpUpstreamPolicyPort(raw); got != want {
			t.Fatalf("mcpUpstreamPolicyPort(%q) = %d, want %d", raw, got, want)
		}
	}
}

func cloneManifestValue(t *testing.T, src map[string]interface{}) map[string]interface{} {
	t.Helper()
	clone, err := deepCopyMap(src)
	if err != nil {
		t.Fatalf("copying manifest: %v", err)
	}
	return clone
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s changed:\n got: %q\nwant: %q", path, got, want)
	}
}
