// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

// CrossAgentBoundary identifies the proxied surface over which a contaminated
// session emits to another agent. These are the boundaries pipelock already
// sees in-line; it does not correlate distinct network identities (that is the
// Pro multi-agent layer).
type CrossAgentBoundary string

const (
	// CrossAgentBoundaryA2ARequest marks an outbound A2A request body emitted
	// by a contaminated session to a peer agent.
	CrossAgentBoundaryA2ARequest CrossAgentBoundary = "a2a_request"
	// CrossAgentBoundaryMCPToolCall marks an outbound MCP tools/call emitted by
	// a contaminated session to a tool/peer agent.
	CrossAgentBoundaryMCPToolCall CrossAgentBoundary = "mcp_tool_call"
)

// TaintSourceKindCrossAgent is the TaintSourceRef.Kind recorded when session
// contamination propagates across an agent boundary pipelock proxies. The kind
// is set only by pipelock internally; agent-supplied content can never forge it
// because cross-agent refs are synthesized here, not parsed from the payload.
const TaintSourceKindCrossAgent = "cross_agent"

// crossAgentMatchReasonPrefix is the stable MatchReason prefix for cross-agent
// taint sources. The boundary is appended so evidence distinguishes A2A from
// MCP propagation.
const crossAgentMatchReasonPrefix = "cross_agent"

// ClassifyCrossAgentObservation builds the taint observation appended when a
// contaminated session emits to another agent over a proxied boundary.
//
// It propagates the session's EXISTING contamination level (floored at
// TaintExternalUntrusted so Contaminated stays sticky) and never lowers it.
// The propagation deliberately does not re-assert PromptHit: the session's own
// PromptHit is already sticky from the original ingest, and re-asserting it
// here would re-trigger hostile escalation inside Observe on every hop. The
// contamination origin URL is carried onto the cross_agent ref so the origin
// survives as evidence even if the bounded source list later evicts the
// original ingest ref.
//
// Callers must invoke this only for sessions already determined to be
// contaminated; the classifier propagates, it does not decide contamination.
func ClassifyCrossAgentObservation(current SessionRisk, boundary CrossAgentBoundary) RiskObservation {
	level := current.Level
	if level < TaintExternalUntrusted {
		level = TaintExternalUntrusted
	}
	return RiskObservation{
		Source: TaintSourceRef{
			URL:         current.LastExternalURL,
			Kind:        TaintSourceKindCrossAgent,
			Level:       level,
			MatchReason: crossAgentMatchReason(boundary),
		},
	}
}

func crossAgentMatchReason(boundary CrossAgentBoundary) string {
	if boundary == "" {
		return crossAgentMatchReasonPrefix
	}
	return crossAgentMatchReasonPrefix + "_" + string(boundary)
}
