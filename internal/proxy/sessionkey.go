// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
)

// sessionKeyFor builds the per-session key used for adaptive-enforcement
// tracking, behavioral profiling, airlock enforcement, and audit correlation.
// Bound and config-default agent identities keep their namespace. Self-declared,
// matched, and unknown identities fold to the client IP so request-controlled
// names cannot create independent adaptive state. RecordIPDomain continues to
// track domain bursts at the IP level for self-declared and matched identities.
//
// This is the single source of truth for session-key construction. Every
// transport (fetch, forward, CONNECT, WebSocket, TLS intercept) must build
// the key the same way, otherwise adaptive escalation and de-escalation would
// track different keys for the same logical session.
func sessionKeyFor(agent, clientIP string, auth envelope.ActorAuth) string {
	return identitykey.CEESafeKey(agent, clientIP, auth)
}

// whoamiAgentProvenance grades an agent name read on the admin whoami API,
// using the same envelope.ActorAuth vocabulary sessionKeyFor's callers use
// elsewhere. Unlike real proxied traffic, the admin API has no listener
// binding or source-CIDR context of its own, so it can never establish a
// bound or config-default identity for its own request: a supplied name is
// always self-declared (untrusted, request-controlled), and an absent one
// is unknown. This mirrors AdaptiveWhoami's key construction, which always
// grades the same way so a self-declared name cannot fold into a trusted
// namespace.
func whoamiAgentProvenance(agent string) string {
	if agent == "" {
		return string(envelope.ActorAuthUnknown)
	}
	return string(envelope.ActorAuthSelfDeclared)
}
