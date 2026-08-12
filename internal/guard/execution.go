// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package guard

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// ExecControlOptions carries the fixed controls passed to the final pre-exec
// helper without exposing the developer environment in process metadata.
type ExecControlOptions struct {
	Declaration   config.Guard
	Profile       string
	PolicyHash    string
	Workspace     string
	TempDir       string
	Binary        string
	EnvironmentFD int
	StatusFD      int
}

// PrepareExecution merges Guard's selected state manifest with the fixed
// runtime paths needed to exec and run an ordinary process. Fixed system,
// temporary, and device grants are code-owned; caller-selected workspace and
// executable paths still pass the compiled floor before becoming grants.
func PrepareExecution(cfg *config.Config, profileName, workspace, tempDir, executable string, uid int) (*PreparedManifest, error) {
	if cfg == nil {
		return nil, fmt.Errorf("guard execution config is nil")
	}
	planned, err := executionProfileGrants(cfg, profileName)
	if err != nil {
		return nil, err
	}
	if err := ValidateExecutionPaths(workspace, tempDir, executable); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, len(planned)+32)
	for _, g := range planned {
		seen[string(g.access)+"\x00"+filepath.Clean(g.declared)] = struct{}{}
	}
	add := func(path string, access AccessKind, floorExempt bool) {
		if path == "" {
			return
		}
		clean := filepath.Clean(path)
		key := string(access) + "\x00" + clean
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		planned = append(planned, grant{declared: clean, access: access, floorExempt: floorExempt})
	}
	for _, path := range existingExecutionPaths([]string{
		"/usr", "/lib", "/lib64", "/bin", "/sbin",
	}) {
		add(path, AccessReadDirectory, true)
	}
	for _, path := range existingExecutionPaths([]string{
		"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/passwd", "/etc/group", "/usr/bin/env",
		"/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	}) {
		add(path, AccessReadFile, true)
	}
	for _, path := range existingExecutionPaths([]string{
		"/etc/ssl/certs", "/etc/pki/tls/certs", "/etc/pki/ca-trust/extracted",
	}) {
		add(path, AccessReadDirectory, true)
	}
	add(workspace, AccessWriteDirectory, false)
	add(tempDir, AccessWriteDirectory, false)
	// The init process resolves PATH before enforcement and passes the exact
	// executable here. Grant that inode, not its containing directory, so tools
	// installed outside /usr or the workspace can start without widening the
	// workload's filesystem view to an entire developer bin directory.
	add(executable, AccessReadFile, false)
	for _, path := range existingExecutionPaths(runtimeDevices) {
		add(path, accessRuntimeDevice, true)
	}

	return prepareGrants(planned, uid, config.ExplainGuardPathFloor)
}

var runtimeDevices = []string{"/dev/null", "/dev/zero", "/dev/urandom"}

// ValidateExecutionPaths applies the compiled floor to the caller-selected
// implicit grants. Fixed Pipelock runtime paths are code-owned, but the
// workspace and executable are operator inputs and cannot bypass the same
// floor that applies to manifest entries.
func ValidateExecutionPaths(workspace, tempDir, executable string) error {
	for _, required := range []struct {
		label  string
		path   string
		access config.GuardAccess
	}{
		{label: "workspace", path: workspace, access: config.GuardAccessWrite},
		{label: "temporary directory", path: tempDir, access: config.GuardAccessWrite},
		{label: "executable", path: executable, access: config.GuardAccessRead},
	} {
		if required.path == "" {
			continue
		}
		decision, explainErr := config.ExplainGuardPathFloor(required.path, required.access)
		if explainErr != nil {
			return fmt.Errorf("evaluating Guard %s %q: %w", required.label, required.path, explainErr)
		}
		if decision.Refused {
			return fmt.Errorf("guard %s %q is refused by the compiled floor: %s", required.label, required.path, decision.Reason)
		}
	}
	return nil
}

func existingExecutionPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			out = append(out, path)
		}
	}
	return out
}

func executionProfileGrants(cfg *config.Config, profileName string) ([]grant, error) {
	if profileName != "" {
		return planManifests(cfg, profileName)
	}
	if len(cfg.Guard.Profiles) != 0 {
		return nil, fmt.Errorf("guard profile is required when profiles are declared")
	}
	return []grant{}, nil
}
