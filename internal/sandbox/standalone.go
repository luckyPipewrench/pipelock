// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// standaloneInitEnv signals the child is in standalone sandbox-init mode
// (with bridge proxy, unlike MCP mode which uses syscall.Exec).
const standaloneInitEnv = "__PIPELOCK_SANDBOX_STANDALONE"

const (
	standaloneGuardDeclarationEnv = "__PIPELOCK_SANDBOX_GUARD_DECLARATION"
	standaloneGuardProfileEnv     = "__PIPELOCK_SANDBOX_GUARD_PROFILE"
	standaloneGuardPolicyHashEnv  = "__PIPELOCK_SANDBOX_GUARD_POLICY_HASH"
	standaloneCommandJSONEnv      = "__PIPELOCK_SANDBOX_COMMAND_JSON"
)

// sandboxSocketEnv carries the parent Unix socket path used by sandbox
// bridge mode. The child-side loopback proxy forwards connections there.
const sandboxSocketEnv = "__PIPELOCK_SANDBOX_SOCKET"

// sandboxBridgeIdleTimeoutEnv carries the bridge proxy's idle-timeout
// override in seconds, sourced from cfg.ForwardProxy.IdleTimeoutSeconds at
// launch time so the child-side bridge matches the parent's configured
// idle behavior instead of BridgeProxy's own hardcoded default.
const sandboxBridgeIdleTimeoutEnv = "__PIPELOCK_SANDBOX_BRIDGE_IDLE_TIMEOUT_SECONDS"

// bridgeIdleTimeoutFromEnv parses sandboxBridgeIdleTimeoutEnv into a positive
// duration. It reports ok=false when the variable is unset, non-numeric, or
// not strictly positive, so the caller leaves BridgeProxy's own default in
// place rather than applying a zero or negative override.
func bridgeIdleTimeoutFromEnv() (time.Duration, bool) {
	raw := os.Getenv(sandboxBridgeIdleTimeoutEnv)
	if raw == "" {
		return 0, false
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

// IsStandaloneInitMode returns true if the current process is a re-exec'd
// standalone sandbox child.
func IsStandaloneInitMode() bool {
	return os.Getenv(standaloneInitEnv) == "1"
}

// bringUpLoopback brings up the loopback interface inside a new network
// namespace using raw netlink syscalls. No external tools required - works
// in minimal containers without iproute2.
func bringUpLoopback() error {
	return loopbackUp()
}

// ProxySocketPath returns the Unix socket path for the parent's proxy,
// scoped to the given sandbox directory.
func ProxySocketPath(sandboxDir string) string {
	return filepath.Join(sandboxDir, "proxy.sock")
}
