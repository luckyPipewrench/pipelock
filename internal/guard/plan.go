// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package guard

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// grant is one declared path plus the access it asks for, after the compiled
// floor has had its say.
type grant struct {
	declared string
	access   AccessKind
	// floorExempt marks a code-owned execution grant. It skips the compiled-floor
	// check against the resolved target and permits the fixed character-device
	// allowlist. Never set it for an operator-selected path.
	floorExempt bool
	// refusal is non-empty when the compiled floor rejected this declaration.
	// The grant is retained rather than dropped so the outcome list can report
	// it; a dropped declaration is indistinguishable from one that was never
	// written, which is how an operator ends up believing a path is covered.
	refusal string
}

type floorEvaluator func(string, config.GuardAccess) (config.GuardFloorDecision, error)

// planManifests flattens the manifests a profile selects into a deduplicated,
// deterministically ordered grant list, with the compiled floor applied.
//
// Deduplication is by (path, access) rather than by path alone. Two manifests
// naming the same path with different access is not a conflict to resolve
// here: the union is what the profile asked for, and the stronger grant simply
// subsumes the weaker one when the rules are built. Resolving it earlier would
// require this layer to rank access kinds, which is the sort of implicit
// precedence that later reads as a policy decision nobody made.
func planManifests(cfg *config.Config, profileName string) ([]grant, error) {
	return planManifestsWithFloor(cfg, profileName, config.ExplainGuardPathFloor)
}

func planManifestsWithFloor(cfg *config.Config, profileName string, explainFloor floorEvaluator) ([]grant, error) {
	var selected *config.GuardProfile
	for i := range cfg.Guard.Profiles {
		if cfg.Guard.Profiles[i].Name == profileName {
			selected = &cfg.Guard.Profiles[i]
			break
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("guard profile %q not found", profileName)
	}

	byName := make(map[string]config.GuardManifest, len(cfg.Guard.Manifests))
	for _, m := range cfg.Guard.Manifests {
		byName[m.Name] = m
	}

	seen := make(map[string]struct{})
	grants := make([]grant, 0, 16)
	add := func(path string, access AccessKind) error {
		clean := filepath.Clean(path)
		key := string(access) + "\x00" + clean
		if _, dup := seen[key]; dup {
			return nil
		}
		seen[key] = struct{}{}

		floorAccess := config.GuardAccessRead
		if access.IsWrite() {
			floorAccess = config.GuardAccessWrite
		}
		decision, err := explainFloor(path, floorAccess)
		if err != nil {
			return fmt.Errorf("evaluating compiled floor for %q: %w", path, err)
		}
		g := grant{declared: clean, access: access}
		if decision.Refused {
			g.refusal = decision.Reason
		}
		grants = append(grants, g)
		return nil
	}

	for _, name := range selected.Manifests {
		m, ok := byName[name]
		if !ok {
			// Validation is expected to catch this earlier. Failing here
			// anyway keeps this function safe to call on a config that
			// reached it by some path validation did not cover, rather than
			// silently planning a profile with fewer grants than declared.
			return nil, fmt.Errorf("guard profile %q selects unknown manifest %q", profileName, name)
		}
		for _, p := range m.ReadOnly {
			if err := add(p, AccessReadFile); err != nil {
				return nil, err
			}
		}
		for _, p := range m.ReadOnlyDirectories {
			if err := add(p, AccessReadDirectory); err != nil {
				return nil, err
			}
		}
		for _, p := range m.ReadWrite {
			if err := add(p, AccessWriteFile); err != nil {
				return nil, err
			}
		}
		for _, p := range m.ReadWriteDirectories {
			if err := add(p, AccessWriteDirectory); err != nil {
				return nil, err
			}
		}
	}

	// Deterministic order so the outcome list, and any evidence derived from
	// it, is reproducible across runs and across map iteration order.
	sort.SliceStable(grants, func(i, j int) bool {
		if grants[i].declared != grants[j].declared {
			return grants[i].declared < grants[j].declared
		}
		return grants[i].access < grants[j].access
	})
	return grants, nil
}
