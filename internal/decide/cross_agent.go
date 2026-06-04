// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// CrossAgentResult reports what a cross-agent contamination observation did.
type CrossAgentResult struct {
	// Contaminated is true when the session was contaminated (or, when its risk
	// state was unreadable, fail-closed treated as contaminated) at the agent
	// boundary.
	Contaminated bool
	// SourceRecorded is true when a cross_agent taint source was appended.
	SourceRecorded bool
	// Indeterminate is true when contamination state could not be read and the
	// flow was fail-closed treated as contaminated.
	Indeterminate bool
	// ShouldEscalate is true when the caller should record
	// SignalCrossAgentContamination on the adaptive-enforcement path. It is set
	// for hostile-level propagation and for fail-closed indeterminate flows.
	ShouldEscalate bool
}

// ObserveCrossAgentContamination records cross-agent taint propagation when a
// contaminated session emits to another agent over a proxied boundary (an A2A
// request body or an MCP tools/call).
//
// When the session is contaminated it appends a bounded "cross_agent" taint
// source (evidence), deduplicating consecutive same-boundary refs so a chatty
// agent cannot flood the bounded source list and evict the contamination
// origin. The adaptive-enforcement escalation signal is left to the caller
// (which owns the EscalationParams) and requested via ShouldEscalate so the
// side effect stays at the transport's block-dispatch site.
//
// Fail-closed: when taint is enabled and a session recorder is present but its
// risk state cannot be read, the flow is treated as contaminated and escalation
// is requested rather than passing through clean.
func ObserveCrossAgentContamination(rec session.Recorder, taintCfg *config.TaintConfig, boundary session.CrossAgentBoundary) CrossAgentResult {
	if taintCfg == nil || !taintCfg.Enabled || rec == nil {
		return CrossAgentResult{}
	}
	rs, ok := rec.(session.RiskState)
	if !ok {
		// Indeterminate: enabled + session present, risk unreadable. Fail-closed.
		return CrossAgentResult{Contaminated: true, Indeterminate: true, ShouldEscalate: true}
	}
	snap := rs.RiskSnapshot()
	if !snap.Contaminated {
		return CrossAgentResult{}
	}

	result := CrossAgentResult{
		Contaminated:   true,
		ShouldEscalate: snap.PromptHit || snap.Level >= session.TaintExternalHostile,
	}

	obs := session.ClassifyCrossAgentObservation(snap, boundary)
	if crossAgentSourceIsDuplicate(snap.Sources, obs.Source) {
		return result
	}
	obs.MaxSources = taintCfg.RecentSources
	rs.ObserveRisk(obs)
	result.SourceRecorded = true
	return result
}

// crossAgentSourceIsDuplicate reports whether the most recent source is already
// a cross_agent ref for the same boundary (same MatchReason). Bounding repeated
// same-boundary refs keeps the bounded source list from being diluted to all
// cross_agent entries, which would evict the contamination origin.
func crossAgentSourceIsDuplicate(sources []session.TaintSourceRef, candidate session.TaintSourceRef) bool {
	if len(sources) == 0 {
		return false
	}
	last := sources[len(sources)-1]
	return last.Kind == session.TaintSourceKindCrossAgent && last.MatchReason == candidate.MatchReason
}
