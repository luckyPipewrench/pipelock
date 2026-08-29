// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package capabilitymanifest

import (
	"path/filepath"
	"testing"

	_ "github.com/luckyPipewrench/pipelock/enterprise/cli"

	"github.com/luckyPipewrench/pipelock/internal/cli"
)

func TestEnterpriseManifestCommandsAreRegistered(t *testing.T) {
	manifest, err := Load(filepath.Join(repositoryRoot(t), "docs/security/capability-manifest.json"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	registered := make(map[string]struct{})
	for _, path := range cli.RegisteredCommandPaths() {
		registered[path] = struct{}{}
	}
	for _, capability := range manifest.Capabilities {
		entry := capability.OperatorEntryPoint
		if entry.Kind != "command" {
			continue
		}
		if _, ok := registered[entry.Value]; !ok {
			t.Errorf("capability %q declares unreachable command %q", capability.ID, entry.Value)
		}
	}
}
