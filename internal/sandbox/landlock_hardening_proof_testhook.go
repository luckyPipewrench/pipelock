// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && mcp_hardening_test

package sandbox

import "github.com/landlock-lsm/go-landlock/landlock"

// ApplyLandlock reports an active test layer in the hardening proof build.
// The fixture needs the kernel's proc access decision to be observable without
// Landlock denying the same open first. Production binaries compile the real
// Landlock implementation.
func ApplyLandlock(Policy) (LayerStatus, error) {
	return LayerStatus{Name: LayerLandlock, Active: true, Version: 1}, nil
}

func buildRules(policy Policy) []landlock.Rule {
	var rules []landlock.Rule
	if len(policy.AllowReadDirs) > 0 {
		rules = append(rules, landlock.RODirs(policy.AllowReadDirs...).IgnoreIfMissing())
	}
	if len(policy.AllowReadFiles) > 0 {
		rules = append(rules, landlock.ROFiles(policy.AllowReadFiles...).IgnoreIfMissing())
	}
	if len(policy.AllowRWDirs) > 0 {
		rules = append(rules, landlock.RWDirs(policy.AllowRWDirs...).IgnoreIfMissing())
	}
	if len(policy.AllowRWFiles) > 0 {
		rules = append(rules, landlock.RWFiles(policy.AllowRWFiles...).IgnoreIfMissing())
	}
	return rules
}
