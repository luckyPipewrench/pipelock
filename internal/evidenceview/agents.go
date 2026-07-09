// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidenceview

import "sort"

// AgentRollup is a per-scorecard-line COUNT breakdown across an agent's
// sessions. There is intentionally no single aggregate state; the UI reads
// individual counts.
type AgentRollup struct {
	ChainsIntact      int
	ChainsBroken      int
	NotReported       int
	AnchoredExternal  int
	NotAnchored       int
	TrustedKeyPresent int
	Unverified        int
}

// AgentGroup groups sessions by agent and provides bounded rollup counts.
type AgentGroup struct {
	Agent        string
	SessionIDs   []string
	SessionCount int
	Summaries    []SessionSummary
	Rollup       AgentRollup
}

// GroupByAgent groups summaries by SessionSummary.Agent, computing rollup
// counts per agent. The result is sorted by agent name for deterministic
// ordering.
func GroupByAgent(summaries []SessionSummary) []AgentGroup {
	if len(summaries) == 0 {
		return nil
	}

	// Group by agent, preserving insertion order within each group.
	agentOrder := make([]string, 0)
	groups := make(map[string]*AgentGroup)
	for _, s := range summaries {
		agent := s.Agent
		g, ok := groups[agent]
		if !ok {
			g = &AgentGroup{Agent: agent}
			groups[agent] = g
			agentOrder = append(agentOrder, agent)
		}
		g.SessionIDs = append(g.SessionIDs, s.ID)
		g.Summaries = append(g.Summaries, s)
	}

	// Sort agents for deterministic output.
	sort.Strings(agentOrder)

	result := make([]AgentGroup, 0, len(agentOrder))
	for _, agent := range agentOrder {
		g := groups[agent]
		g.SessionCount = len(g.SessionIDs)
		g.Rollup = computeRollup(g.Summaries)
		result = append(result, *g)
	}
	return result
}

func computeRollup(summaries []SessionSummary) AgentRollup {
	var r AgentRollup
	for _, s := range summaries {
		if !s.ReceiptsEnabled {
			r.NotReported++
			continue
		}
		// Use the pip states to compute rollup counts.
		for _, pip := range s.Pips {
			switch pip.Label {
			case "A":
				switch pip.State {
				case StateVerify:
					r.TrustedKeyPresent++
				case StateWarn, StateFail, StateLimited:
					r.Unverified++
				}
			case "U":
				switch pip.State {
				case StateVerify:
					r.ChainsIntact++
				case StateFail:
					r.ChainsBroken++
				case StateLimited:
					// Read-limited: count as not fully verified but not broken.
					r.ChainsIntact++
				}
			case "N":
				switch pip.State {
				case StateVerify:
					r.AnchoredExternal++
				case StateWarn:
					r.NotAnchored++
				}
			}
		}
	}
	return r
}
