// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"net"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// StandaloneLaunchConfig configures the standalone sandbox launcher.
type StandaloneLaunchConfig struct {
	// Ctx controls the child's lifetime.
	Ctx context.Context
	// Command is the command and arguments to execute inside the sandbox.
	Command []string
	// Workspace is the resolved absolute workspace path.
	Workspace string
	// Policy overrides the default sandbox policy.
	Policy *Policy
	// Strict enables strict containment.
	Strict bool
	// BestEffort permits supported degraded containment.
	BestEffort bool
	// RequireNetNS rejects launches without a network namespace.
	RequireNetNS bool
	// ExtraEnv contains additional KEY=VALUE pairs for the child.
	ExtraEnv []string
	// DeveloperEnvironment is transported over an anonymous pipe.
	DeveloperEnvironment []string
	// UseDeveloperEnvironment selects DeveloperEnvironment.
	UseDeveloperEnvironment bool
	// ProxyHandler handles each connection from the sandboxed command.
	ProxyHandler func(net.Conn)
	// RequireProxyHandler rejects a nil ProxyHandler before child start.
	RequireProxyHandler bool
	// GuardDeclaration enables the Linux-only final pre-exec Guard helper.
	GuardDeclaration *config.Guard
	// GuardProfile selects the declaration profile.
	GuardProfile string
	// GuardPolicyHash binds the canonical runtime configuration.
	GuardPolicyHash string
	// GuardAppliedPreExec receives proof that the helper applied the filesystem
	// ruleset before attempting exec. Pipe completion cannot prove that the
	// operator command started; returning an error terminates the launch.
	GuardAppliedPreExec func(proof []byte) error
}
