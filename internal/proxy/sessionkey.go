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
