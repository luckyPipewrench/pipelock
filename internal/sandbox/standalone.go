// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"os"
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

// bringUpLoopback brings up the loopback interface inside a new network
// namespace using raw netlink syscalls. No external tools required — works
// in minimal containers without iproute2.
func bringUpLoopback() error {
	return loopbackUp()
}

// ProxySocketPath returns the Unix socket path for the parent's proxy,
// scoped to the given sandbox directory.
func ProxySocketPath(sandboxDir string) string {
	return filepath.Join(sandboxDir, "proxy.sock")
}
