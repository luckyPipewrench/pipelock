// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "fmt"

// Action divergence: a sub-detector whose action is weaker than the action of
// the section that encloses it.
//
// An operator who sets a section to `block` reasonably believes that section
// enforces. When an independently-enabled sub-detector inside it carries its
// own weaker action, findings from that sub-detector are only warned about,
// and nothing anywhere says so. The config reads as enforcement the operator
// does not have.
//
// This analyzer is ADVISORY ONLY. It changes no enforcement decision. Two
// deliberate non-goals, both of which would be worse than the silence:
//
//   - It does NOT make the child inherit the parent. That would silently
//     strengthen enforcement for every existing deployment on upgrade, turning
//     a documentation defect into an availability incident.
//   - It does NOT reject the config. A weaker child is frequently the correct
//     operational choice; entropy-based detectors in particular produce
//     findings on ordinary developer traffic (a 1.3 KB base64 image exceeds a
//     4096-bit budget on its first legitimate call), so blocking on them by
//     default gets the whole control switched off.
//
// MEMBERSHIP RULE (this is the part that has to survive new code):
//
// A pair is reported only when the child is an unkeyed, independently enabled
// sub-detector whose terminal action is consumed INSTEAD OF its enclosing
// section's action for the same traffic decision.
//
// Membership is therefore a property of how the action is CONSUMED at runtime,
// not of how the config struct is shaped. Struct nesting is the wrong test in
// both directions: `request_body_scanning.content_entropy_action` is a
// flattened sibling field and IS a member, while several genuinely nested
// action fields are NOT. The excluded classes:
//
//   - Selector overrides — `mcp_tool_policy.rules[].action`,
//     `request_body_scanning.pattern_actions`,
//     `tool_chain_detection.custom_patterns[].action`. Making a targeted
//     exception is the entire purpose of these knobs, so reporting them would
//     be noise, and an advisory an operator learns to ignore is worth nothing.
//   - Fallback/aggregate actions — a rule action that falls back to the parent
//     when omitted, or matching rules combined by strictest result. Nothing is
//     lost, so there is nothing to report.
//   - Distinct-condition actions — `address_protection.unknown_action`,
//     `mcp_session_binding.no_baseline_action`, parse-error actions. These
//     govern a different condition, not a weaker version of the same one.
//   - Inert fields — `dlp.patterns[].action` is reserved and rejected by
//     validation, so it is never silently weaker; it never applies at all.
//
// Not covered here, and deliberately so: `response_scanning.mcp_servers[].trust`
// resolves to an action only at runtime, so a `block` response action coexists
// with a `reasoning` server that warns. That is the same operator surprise
// reached through a different mechanism and needs its own analysis rather than
// being forced into this table.
type actionDivergence struct {
	// parentField and childField are the operator-facing YAML paths, so the
	// warning names what to actually go and edit.
	parentField string
	childField  string
	// trigger describes, in operator terms, which findings resolve to the
	// weaker action. Without this the warning says something is weaker but
	// not what it costs.
	trigger string
	// enabled reports whether both the enclosing section and the sub-detector
	// are active. A disabled sub-detector decides nothing, so a weaker action
	// on it is not a divergence and must not be reported.
	enabled func(c *Config) bool
	parent  func(c *Config) string
	child   func(c *Config) string
}

// independentSubDetectors is the declared membership table. Each entry is a
// case where the child action is consumed instead of the parent's.
//
// Adding an entry is a claim about runtime behavior. Verify it by finding the
// consumer that reads the child action and confirming the parent's does not
// also apply to that finding, then add a test that fails when the consumer is
// switched to read the parent instead.
var independentSubDetectors = []actionDivergence{
	{
		// internal/mcp/cee.go reads EntropyBudget.Action for a budget
		// crossing; CrossRequestDetection.Action governs fragment DLP
		// matches only.
		parentField: "cross_request_detection.action",
		childField:  "cross_request_detection.entropy_budget.action",
		trigger:     "per-session entropy budget crossings",
		enabled: func(c *Config) bool {
			return c.CrossRequestDetection.Enabled && c.CrossRequestDetection.EntropyBudget.Enabled
		},
		parent: func(c *Config) string { return c.CrossRequestDetection.Action },
		child:  func(c *Config) string { return c.CrossRequestDetection.EntropyBudget.Action },
	},
	{
		// internal/proxy/intercept.go and forward.go read
		// SSEStreaming.Action for inline event-stream findings.
		parentField: "response_scanning.action",
		childField:  "response_scanning.sse_streaming.action",
		trigger:     "inline text/event-stream scanning findings",
		enabled: func(c *Config) bool {
			return c.ResponseScanning.Enabled && c.ResponseScanning.SSEStreaming.Enabled
		},
		parent: func(c *Config) string { return c.ResponseScanning.Action },
		child:  func(c *Config) string { return c.ResponseScanning.SSEStreaming.Action },
	},
	{
		// internal/proxy/bodyscan.go accumulates from an empty action and
		// contributes ContentEntropyAction for an entropy finding, so when
		// entropy is the only finding the parent action never applies.
		parentField: "request_body_scanning.action",
		childField:  "request_body_scanning.content_entropy_action",
		trigger:     "opaque high-entropy request body and frame findings",
		enabled: func(c *Config) bool {
			return c.RequestBodyScanning.Enabled && c.RequestBodyScanning.ContentEntropyEnabled
		},
		parent: func(c *Config) string { return c.RequestBodyScanning.Action },
		child:  func(c *Config) string { return c.RequestBodyScanning.ContentEntropyAction },
	},
}

// ActionDivergenceWarnings returns one advisory warning per enabled
// sub-detector whose action is weaker than its enclosing section's.
//
// This is the single analyzer behind every surface that reports divergence:
// startup and reload reach it through ValidateWithWarnings, and the doctor and
// check commands consume it directly. Keeping one implementation is the point
// — an operator who fixes what startup reported must not still see it in
// doctor, and a second copy of this logic would drift the moment a new
// sub-detector is added to only one of them.
//
// It never returns an error and never mutates the config.
func (c *Config) ActionDivergenceWarnings() []Warning {
	var warnings []Warning
	for _, d := range independentSubDetectors {
		if !d.enabled(c) {
			continue
		}
		parent, child := d.parent(c), d.child(c)
		if !actionWeakerThan(child, parent) {
			continue
		}
		warnings = append(warnings, Warning{
			Field: d.childField,
			Message: fmt.Sprintf(
				"action %q is weaker than %s %q, so %s resolve to %q; "+
					"set it to %q to enforce, or leave it and treat %s as advisory",
				child, d.parentField, parent, d.trigger, child, parent, d.trigger),
		})
	}
	return warnings
}

// validateActionDivergence accumulates the advisory into the validation
// warning path consumed by startup and accepted reloads.
func (c *Config) validateActionDivergence(warnings *[]Warning) {
	*warnings = append(*warnings, c.ActionDivergenceWarnings()...)
}

// actionWeakerThan reports whether a is strictly weaker than b.
//
// It reuses reloadActionStrength, the same total ordering the reload-downgrade
// warnings use, so a parent/child comparison and an old/new comparison can
// never disagree about which of two actions is stronger. Unrecognized or empty
// actions return not-ok there, and this reports false for them: an action this
// package cannot rank is not evidence of weakening, and a false alarm on a
// value we simply do not understand is the failure that gets the advisory
// ignored. Note that actionRank in action.go is a DIFFERENT, coarser ordering
// that ranks only block and warn; it is not usable here.
func actionWeakerThan(a, b string) bool {
	aStrength, aOK := reloadActionStrength(a)
	bStrength, bOK := reloadActionStrength(b)
	return aOK && bOK && aStrength < bStrength
}
