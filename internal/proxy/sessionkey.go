// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
)

// stateIdentity projects a resolved request identity onto the identity that
// cross-request detection state is keyed by. It is the one place that decision
// lives; every HTTP-family consumer of a state key goes through it, so no two
// of them can place one peer in different buckets.
//
// With default_agent_identity set and bind_default_agent_identity off, a
// request that carries X-Pipelock-Agent is graded self-declared or matched and
// its own state would key to the bare client address, while the same peer
// sending no header is graded config-default and keys to "<default>|<client>".
// Sending or omitting one header must not move a peer between two detection
// buckets, so every grade other than bound is keyed as the configured default.
// A bound identity (per-agent listener or source_cidrs) keeps its own bucket,
// and a bound default (bind_default_agent_identity) is already config-default.
//
// The returned pair is for building state keys and the issuer evidence trust
// gate only. The request keeps its declared grade for policy, receipts, logs
// and the per-IP domain tracker, which exists to catch header rotation and
// must still see a header-supplied name as untrusted.
func stateIdentity(cfg *config.Config, agent string, auth envelope.ActorAuth) (string, envelope.ActorAuth) {
	if cfg == nil || cfg.DefaultAgentIdentity == "" || cfg.BindDefaultAgentIdentity {
		return agent, auth
	}
	switch auth {
	case envelope.ActorAuthBound, envelope.ActorAuthConfigDefault:
		return agent, auth
	default:
		return edition.ConfigDefaultName(cfg.DefaultAgentIdentity), envelope.ActorAuthConfigDefault
	}
}

// sessionKeyFor builds the per-session key used for adaptive-enforcement
// tracking, behavioral profiling, airlock enforcement, and audit correlation.
// Bound and config-default agent identities keep their namespace. Self-declared,
// matched, and unknown identities fold to the client IP so request-controlled
// names cannot create independent adaptive state, except that an unbound
// configured default pins them to that default's bucket (see stateIdentity).
// RecordIPDomain continues to track domain bursts at the IP level for
// self-declared and matched identities.
//
// This is the single source of truth for session-key construction. Every
// transport (fetch, forward, CONNECT, WebSocket, TLS intercept) must build
// the key the same way, otherwise adaptive escalation and de-escalation would
// track different keys for the same logical session.
func sessionKeyFor(cfg *config.Config, agent, clientIP string, auth envelope.ActorAuth) string {
	agent, auth = stateIdentity(cfg, agent, auth)
	return identitykey.CEESafeKey(agent, clientIP, auth)
}

// newCEEIdentity builds the cross-request detection owner for a request through
// the same projection sessionKeyFor uses.
func newCEEIdentity(cfg *config.Config, agent, clientIP string, auth envelope.ActorAuth) identitykey.CEEIdentity {
	agent, auth = stateIdentity(cfg, agent, auth)
	return identitykey.NewCEEIdentity(agent, clientIP, auth)
}
