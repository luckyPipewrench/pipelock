// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// standaloneInitEnv signals the child is in standalone sandbox-init mode
// (with bridge proxy, unlike MCP mode which uses syscall.Exec).
const standaloneInitEnv = "__PIPELOCK_SANDBOX_STANDALONE"

// IsStandaloneInitMode returns true if the current process is a re-exec'd
// standalone sandbox child.
func IsStandaloneInitMode() bool {
	return os.Getenv(standaloneInitEnv) == "1"
}

// bringUpLoopback runs `ip link set lo up` inside the current namespace.
func bringUpLoopback() error {
	// Use absolute path because synthetic env PATH may not include /usr/sbin
	// (where ip lives on Fedora/RHEL). Fall back to PATH lookup.
	ipBin := "/usr/sbin/ip"
	if _, err := os.Stat(ipBin); err != nil {
		ipBin = "ip" // fall back to PATH lookup
	}
	cmd := exec.CommandContext(context.Background(), ipBin, "link", "set", "lo", "up") //nolint:gosec // G204: fixed command
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set lo up: %w (%s)", err, string(out))
	}
	return nil
}

// ProxySocketPath returns the Unix socket path for the parent's proxy,
// scoped to the given sandbox directory.
func ProxySocketPath(sandboxDir string) string {
	return filepath.Join(sandboxDir, "proxy.sock")
}
