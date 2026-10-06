// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestApplyFreshFilesystemDefaultRejectsUnusableInput(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if _, err := applyFreshFilesystemDefault(nil, []byte("mode: balanced\n")); err == nil || !strings.Contains(err.Error(), "stat function") {
		t.Fatalf("nil env = %v", err)
	}
	env.stat = nil
	if _, err := applyFreshFilesystemDefault(env, []byte("mode: balanced\n")); err == nil || !strings.Contains(err.Error(), "stat function") {
		t.Fatalf("nil stat = %v", err)
	}

	env.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "invalid yaml", body: "mode: [\n", want: "yaml"},
		{name: "scalar document", body: "balanced\n", want: "YAML mapping"},
		{name: "sequence document", body: "- balanced\n", want: "YAML mapping"},
		{name: "containment scalar", body: "containment: text\n", want: `containment" must be a mapping`},
		{name: "filesystem scalar", body: "containment:\n  filesystem: text\n", want: `filesystem" must be a mapping`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := applyFreshFilesystemDefault(env, []byte(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestApplyFreshFilesystemDefaultTurnsNullContainersIntoMaps(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	tests := []string{
		"containment: null\n",
		"containment: ~\n",
		"containment:\n",
		"containment:\n  filesystem: null\n",
		"containment:\n  filesystem: ~\n",
	}
	for _, body := range tests {
		t.Run(body, func(t *testing.T) {
			got, err := applyFreshFilesystemDefault(env, []byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(got), "mode: enforce") {
				t.Fatalf("config = %q", got)
			}
		})
	}

	parent := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "nope"}
	if _, err := ensureYAMLMapping(parent, "containment"); err == nil || !strings.Contains(err.Error(), "must be a mapping") {
		t.Fatalf("scalar parent = %v", err)
	}
	if _, err := ensureYAMLMapping(nil, "containment"); err == nil || !strings.Contains(err.Error(), "must be a mapping") {
		t.Fatalf("nil parent = %v", err)
	}
}
