//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

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
		if entry.Kind == "command" {
			if _, ok := registered[entry.Value]; !ok {
				t.Errorf("capability %q declares unreachable command %q", capability.ID, entry.Value)
			}
		}
		// Surface coverage is where a stale or mistyped command hides: the
		// default build skips records it cannot see, because enterprise
		// commands are absent there, so the enterprise build is the only place
		// every declared command can be checked against a real path.
		for _, surface := range capability.SurfaceCoverage {
			if surface.Kind != SurfaceCommand {
				continue
			}
			if _, ok := registered[surface.Value]; !ok {
				t.Errorf("capability %q maps unreachable command %q", capability.ID, surface.Value)
			}
		}
	}
	for _, exclusion := range manifest.SurfaceExclusions {
		if exclusion.Kind != SurfaceCommand {
			continue
		}
		if _, ok := registered[exclusion.Value]; !ok {
			t.Errorf("surface exclusion names unreachable command %q; a stale exclusion silently widens the gap it documents", exclusion.Value)
		}
	}
}
