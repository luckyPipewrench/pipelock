// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package identitykey centralizes stable per-actor key construction for
// stateful proxy detectors.
package identitykey

import "github.com/luckyPipewrench/pipelock/internal/envelope"

// AnonymousAgent is the unattributed agent name. It lives here because both
// this package and internal/proxy must agree on it exactly: if the two ever
// drift, one side would namespace an identity the other collapses to the client
// bucket, which is precisely the agent-name partitioning bypass CEESafeKey
// exists to prevent.
const AnonymousAgent = "anonymous"

// ForAgentAndClient builds the shared agent/client key shape. Named agents are
// namespaced ahead of the client identity; unnamed or anonymous agents collapse
// to the client identity alone.
func ForAgentAndClient(agent, client string) string {
	if agent == "" || agent == AnonymousAgent {
		return client
	}
	return agent + "|" + client
}

// CEESafeAgent returns the agent component that is safe for stateful buckets
// which must resist request-supplied agent-name partitioning.
func CEESafeAgent(agent string, auth envelope.ActorAuth) string {
	switch auth {
	case envelope.ActorAuthBound, envelope.ActorAuthConfigDefault:
		return agent
	default:
		return ""
	}
}

// CEESafeKey builds the partition-resistant state key used by CEE and MCP DoW.
func CEESafeKey(agent, client string, auth envelope.ActorAuth) string {
	return ForAgentAndClient(CEESafeAgent(agent, auth), client)
}
