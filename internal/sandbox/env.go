// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// safePassthroughKeys are the ONLY parent environment variables passed to the
// sandboxed child. This is an allowlist, not a blocklist — any variable not
// listed here is dropped. Matches the MCP proxy's safeEnv() approach to
// prevent accidental secret leakage (OPENAI_API_KEY, AWS_*, LD_PRELOAD, etc.).
var safePassthroughKeys = []string{
	"USER",
	"LANG",
	"LC_ALL",
	"TERM",
	"TZ",
}

// dangerousEnvKeys are environment variable keys that must NOT be passed
// into the sandbox via --env flags. These can subvert containment by
// injecting code before the agent process starts.
var dangerousEnvKeys = map[string]bool{
	"LD_PRELOAD":      true, // shared library injection
	"LD_LIBRARY_PATH": true, // library search path hijack
	"NODE_OPTIONS":    true, // Node.js arbitrary flag injection
	"PYTHONSTARTUP":   true, // Python executes this file on startup
	"PYTHONPATH":      true, // Python module search path hijack
	"RUBYOPT":         true, // Ruby arbitrary option injection
	"PERL5OPT":        true, // Perl arbitrary option injection
	"BASH_ENV":        true, // Bash executes this file on startup
	"ENV":             true, // sh executes this file on startup
	"CDPATH":          true, // directory traversal manipulation
}

// telemetrySuppression prevents package managers from hanging on network
// checks in the no-network sandbox environment.
var telemetrySuppression = map[string]string{
	"NPM_CONFIG_UPDATE_NOTIFIER":    "false",
	"PIP_DISABLE_PIP_VERSION_CHECK": "1",
	"HOMEBREW_NO_AUTO_UPDATE":       "1",
	"NO_UPDATE_NOTIFIER":            "1",
	"UV_NO_SYNC":                    "1",
	"DISABLE_TELEMETRY":             "1",
	"DO_NOT_TRACK":                  "1",
}

// SandboxHome is the directory name inside the sandbox temp area where the
// synthetic HOME and XDG directories are created.
const SandboxHome = "home"

// SyntheticEnv builds the environment for the sandboxed child process.
// It creates a synthetic HOME directory tree inside the sandbox temp area
// and returns a minimal, safe environment slice.
//
// SECURITY: This uses an allowlist model. Only variables in safePassthroughKeys
// are inherited from the parent. All other parent env vars are dropped. This
// prevents leaking secrets (API keys, AWS creds, proxy configs, LD_PRELOAD)
// into the sandboxed process.
//
// sandboxDir is the per-sandbox temp directory (e.g., /tmp/pipelock-sandbox-<pid>).
// workspace is the resolved absolute workspace path set as the child's CWD.
// extraEnv contains additional KEY=VALUE pairs from --env flags to pass through.
func SyntheticEnv(sandboxDir, workspace string, extraEnv []string) ([]string, error) {
	homeDir := filepath.Join(sandboxDir, SandboxHome)
	dirs := []string{
		homeDir,
		filepath.Join(homeDir, "config"),
		filepath.Join(homeDir, "cache"),
		filepath.Join(homeDir, "data"),
		filepath.Join(sandboxDir, "tmp"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, fmt.Errorf("creating sandbox dir %s: %w", d, err)
		}
	}

	// Start with an empty env. Only explicitly listed vars make it through.
	env := make([]string, 0, len(safePassthroughKeys)+len(telemetrySuppression)+len(extraEnv)+10)

	// Fixed sandbox-specific vars.
	env = append(env,
		"HOME="+homeDir,
		"XDG_CONFIG_HOME="+filepath.Join(homeDir, "config"),
		"XDG_CACHE_HOME="+filepath.Join(homeDir, "cache"),
		"XDG_DATA_HOME="+filepath.Join(homeDir, "data"),
		"TMPDIR="+filepath.Join(sandboxDir, "tmp"),
		"SHELL=/bin/sh",
		"PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin",
		"PWD="+workspace,
	)

	// Safe passthrough: only these vars from parent environment.
	for _, key := range safePassthroughKeys {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}

	// Telemetry suppression: prevent hangs on network checks.
	for k, v := range telemetrySuppression {
		env = append(env, k+"="+v)
	}

	// Explicit extra env from --env flags (user-requested passthrough).
	// Validate against dangerous keys that could subvert containment.
	for _, entry := range extraEnv {
		key, _, _ := strings.Cut(entry, "=")
		if dangerousEnvKeys[key] {
			return nil, fmt.Errorf("sandbox: env key %q is blocked (could subvert containment)", key)
		}
		env = append(env, entry)
	}

	return env, nil
}
