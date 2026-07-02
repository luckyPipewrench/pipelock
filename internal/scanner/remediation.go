// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

// ScannerBodyDLP identifies request-body DLP blocks emitted outside the URL
// scanner pipeline.
const ScannerBodyDLP = "body_dlp"

const (
	bodyDLPOperatorKnob = "Request body DLP matched. For false positives, add a top-level suppress: entry with rule: set to the matched rule name and path: scoped to the request path."

	ssrfOperatorKnob = "If the destination is a trusted internal service, add the hostname to top-level `trusted_domains` (hostname-based) or the resolved range to `ssrf.ip_allowlist` (IP-based). " +
		"This verdict depends on DNS resolution at runtime; explain reports it without resolving."
	ssrfOperatorBroader = "Disabling SSRF entirely (`internal: []`) removes private-range protection for ALL destinations — never do this to fix one host."

	injectionTraversalOperatorKnob = "This sequence is never legitimate in a normal URL (header injection / directory escape). There is no exemption knob — the URL must be corrected at the source."
	parseContextOperatorKnob       = "This is not a policy block: the request context was unavailable/cancelled, or the URL could not be parsed. Correct the input and retry."

	secretAgentReason             = "Request blocked: the destination or content matched a secret/credential pattern."
	highEntropyAgentReason        = "Request blocked: high-entropy content resembling exfiltration was detected."
	protectedAddressAgentReason   = "Request blocked: the destination resolves to protected internal or metadata infrastructure."
	protectiveCeilingAgentReason  = "Request blocked: a protective request ceiling was exceeded."
	injectionTraversalAgentReason = "Request blocked: the URL contains an injection/traversal sequence."
	// destinationNotPermittedAgentReason is shared by the blocklist and allowlist
	// blocks. It deliberately does NOT name which mechanism (blocklist vs strict
	// allowlist) rejected the destination: telling a blocked agent whether it is
	// in blocklist mode or strict-allowlist mode is containment-posture recon that
	// helps it reason about how boxed-in it is. The operator sees the exact
	// mechanism + knob via OperatorKnob; the agent gets only the terse "why".
	destinationNotPermittedAgentReason = "Request blocked: the destination is not permitted."
)

// RemediationGuidance describes how a blocked scan should be explained, split
// by audience. Operator fields name the exact allow-path; AgentReason is terse
// and non-procedural (never teaches the self-unblock knob).
type RemediationGuidance struct {
	OperatorKnob    string // exact narrowest verified config change; "" if none
	OperatorBroader string // broader option + its tradeoff; "" if none
	Immutable       bool   // true = safety floor; not disableable wholesale by config
	AgentReason     string // terse WHY, NO knob/path/how-to-unblock
}

// remediationGuidance is the canonical per-label block-remediation table. Each
// entry pairs the operator's exact allow-path with the terse, non-procedural
// reason shown to the agent. Consumers read it via GuidanceFor; the parity and
// confused-deputy guards in remediation_test.go keep it correct.
var remediationGuidance = map[string]RemediationGuidance{
	ScannerDLP: {
		OperatorKnob: "Add the destination host to that pattern's `dlp.patterns[].exempt_domains`. " +
			"URL DLP does NOT consult the top-level `suppress:` list (that is body-DLP and response-scanning only) — a `suppress:` entry here is inert. " +
			"If the value is a long token in the query string, you may ALSO need `fetch_proxy.monitoring.query_entropy_exclusions` (a separate gate).",
		OperatorBroader: "`tls_interception.passthrough_domains` exempts the host in one line but blinds Pipelock to ALL inner TLS (method, path, body, response) for that host — only acceptable for can't-scan-by-construction hosts, never as the fix for a single-pattern false positive.",
		AgentReason:     secretAgentReason,
	},
	ScannerCoreDLP: {
		OperatorKnob: "Core DLP is an immutable safety floor for critical credential shapes and cannot be exempted by config. If this is a genuine false positive, the pattern itself must be tightened in a release; there is no per-host carve-out.",
		Immutable:    true,
		AgentReason:  secretAgentReason,
	},
	ScannerEntropy: {
		// ScannerEntropy also has a query-entropy variant; later consumer rewiring
		// can preserve that nuance from Result.Reason. The table default is path
		// entropy because a plain scanner label cannot distinguish the two.
		OperatorKnob: "Add the host to `fetch_proxy.monitoring.subdomain_entropy_exclusions` (exact or `*.example.com` wildcard), or govern the exact host+path with `request_policy` so path entropy is exempted only for that route. " +
			"This is the path-entropy gate; `fetch_proxy.monitoring.query_entropy_exclusions` does NOT lift path entropy blocks.",
		OperatorBroader: "Raising `fetch_proxy.monitoring.entropy_threshold` lowers sensitivity globally for every destination — broader blast radius; prefer the per-host exclusion.",
		AgentReason:     highEntropyAgentReason,
	},
	ScannerSubdomainEntropy: {
		OperatorKnob:    "Add the host to `fetch_proxy.monitoring.subdomain_entropy_exclusions` (exact or `*.example.com` wildcard). This is the subdomain-entropy gate (high-entropy DNS labels), distinct from the query-entropy gate.",
		OperatorBroader: "Raising `fetch_proxy.monitoring.subdomain_entropy_threshold` lowers subdomain sensitivity globally — prefer the per-host exclusion.",
		AgentReason:     highEntropyAgentReason,
	},
	ScannerBlocklist: {
		OperatorKnob: "Remove the entry from `fetch_proxy.monitoring.blocklist` (or narrow it) if the domain is legitimate.",
		AgentReason:  destinationNotPermittedAgentReason,
	},
	ScannerAllowlist: {
		OperatorKnob:    "Add the host to `api_allowlist`. In strict mode only allowlisted domains are reachable.",
		OperatorBroader: "Switching `mode` from `strict` to `balanced` permits monitored web browsing for all destinations — much broader; prefer adding the single host to `api_allowlist`.",
		AgentReason:     destinationNotPermittedAgentReason,
	},
	ScannerSSRF: {
		OperatorKnob:    ssrfOperatorKnob,
		OperatorBroader: ssrfOperatorBroader,
		AgentReason:     protectedAddressAgentReason,
	},
	ScannerSSRFMetadata: {
		OperatorKnob:    ssrfOperatorKnob,
		OperatorBroader: ssrfOperatorBroader,
		AgentReason:     protectedAddressAgentReason,
	},
	ScannerCoreSSRF: {
		OperatorKnob: "Core SSRF blocks private/loopback/link-local IP literals as an immutable floor. `ssrf.ip_allowlist` is the only override and is honored even by the core check; there is no way to disable the floor wholesale.",
		Immutable:    true,
		AgentReason:  protectedAddressAgentReason,
	},
	ScannerRateLimit: {
		OperatorKnob: "This is a protective ceiling, not a threat detection. Raise `fetch_proxy.monitoring.max_requests_per_minute` or retry after the window.",
		AgentReason:  protectiveCeilingAgentReason,
	},
	ScannerLength: {
		OperatorKnob: "Raise `fetch_proxy.monitoring.max_url_length`, or inspect the URL for data stuffing in query parameters.",
		AgentReason:  protectiveCeilingAgentReason,
	},
	ScannerDataBudget: {
		OperatorKnob: "This is a protective per-domain data ceiling. Adjust the session data budget configuration if the volume is legitimate.",
		AgentReason:  protectiveCeilingAgentReason,
	},
	ScannerCRLF: {
		OperatorKnob: injectionTraversalOperatorKnob,
		Immutable:    true,
		AgentReason:  injectionTraversalAgentReason,
	},
	ScannerPathTraversal: {
		OperatorKnob: injectionTraversalOperatorKnob,
		Immutable:    true,
		AgentReason:  injectionTraversalAgentReason,
	},
	ScannerScheme: {
		OperatorKnob: "Only `http` and `https` schemes are permitted. There is no knob to allow other schemes — use an http/https URL.",
		Immutable:    true,
		AgentReason:  "Request blocked: the URL scheme is not permitted.",
	},
	ScannerCoreResponse: {
		OperatorKnob: "Core response scanning is an immutable injection floor and cannot be disabled by config.",
		Immutable:    true,
		AgentReason:  "Response blocked: a prompt-injection pattern was detected.",
	},
	ScannerContext: {
		OperatorKnob: parseContextOperatorKnob,
		AgentReason:  "Request blocked: the scan could not complete.",
	},
	ScannerParser: {
		OperatorKnob: parseContextOperatorKnob,
		AgentReason:  "Request blocked: the URL could not be parsed.",
	},
	ScannerBodyDLP: {
		OperatorKnob: bodyDLPOperatorKnob,
		AgentReason:  secretAgentReason,
	},
}

// GuidanceFor returns the remediation guidance for a scanner/block label. The
// second return is false for an unknown label — callers get no guidance rather
// than a wrong one (fail-safe).
func GuidanceFor(label string) (RemediationGuidance, bool) {
	g, ok := remediationGuidance[label]
	return g, ok
}
