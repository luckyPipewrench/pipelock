// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !mcp_hardening_test

package sandbox

import (
	"fmt"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// ApplyLandlock restricts the calling process's filesystem access according
// to the given policy. This is permanent and inherited by all children.
//
// Uses BestEffort mode: on older kernels, the ruleset is automatically
// downgraded to the supported ABI level. Returns the active ABI version
// and any error. If Landlock is completely unavailable, returns
// ErrUnavailable.
func ApplyLandlock(policy Policy, proxySocket ...string) (LayerStatus, error) {
	status := LayerStatus{Name: LayerLandlock}

	abi, err := llsys.LandlockGetABIVersion()
	if err != nil {
		status.Reason = fmt.Sprintf("landlock not available: %v", err)
		return status, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if abi < 1 {
		status.Reason = "landlock ABI version 0 (not supported)"
		return status, fmt.Errorf("%w: ABI version 0", ErrUnavailable)
	}
	status.Version = abi

	// Build path rules from policy. BestEffort automatically downgrades
	// access rights the kernel doesn't support. IgnoreIfMissing skips
	// paths that don't exist on this distro (e.g., /lib64/, /etc/pki/).
	rules := buildRules(policy)
	if abi >= 9 && len(proxySocket) > 0 && proxySocket[0] != "" {
		// Admit the exact parent doorway inode, never its directory. Ordinary
		// filesystem grants do not authorize connections to host sockets.
		rules = append(rules, landlock.ROFiles(proxySocket[0]).WithResolveUnix())
	}

	if err := landlock.V9.BestEffort().RestrictPaths(rules...); err != nil {
		status.Reason = fmt.Sprintf("restrict failed: %v", err)
		return status, fmt.Errorf("applying landlock: %w", err)
	}
	if abi >= 6 {
		if err := landlock.V6.RestrictScoped(); err != nil {
			status.Reason = fmt.Sprintf("IPC scope failed: %v", err)
			return status, fmt.Errorf("applying landlock IPC scope: %w", err)
		}
	}

	status.Active = true
	return status, nil
}

// buildRules constructs landlock.Rule entries from the sandbox policy.
// Uses IgnoreIfMissing() so distro-specific paths (e.g., /lib64/, /etc/pki/)
// don't cause errors when absent.
func buildRules(policy Policy) []landlock.Rule {
	var rules []landlock.Rule

	// Read-only directories.
	if len(policy.AllowReadDirs) > 0 {
		rules = append(rules, landlock.RODirs(policy.AllowReadDirs...).IgnoreIfMissing())
	}

	// Read-only individual files.
	if len(policy.AllowReadFiles) > 0 {
		rules = append(rules, landlock.ROFiles(policy.AllowReadFiles...).IgnoreIfMissing())
	}

	// Read-write directories.
	if len(policy.AllowRWDirs) > 0 {
		rules = append(rules, landlock.RWDirs(policy.AllowRWDirs...).IgnoreIfMissing())
	}

	// Read-write individual files (e.g., /dev/null, /dev/urandom).
	if len(policy.AllowRWFiles) > 0 {
		rules = append(rules, landlock.RWFiles(policy.AllowRWFiles...).IgnoreIfMissing())
	}

	return rules
}
