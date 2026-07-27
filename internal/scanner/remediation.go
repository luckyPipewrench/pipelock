// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import "strings"

// ScannerBodyDLP and ScannerDenialOfWallet identify blocks emitted outside the
// URL scanner pipeline.
const (
	ScannerBodyDLP        = "body_dlp"
	AuditBodyEntropy      = "body_entropy"
	ScannerDenialOfWallet = "denial_of_wallet"

	// Audit* labels identify enforcement and warning families emitted outside
	// the URL scanner pipeline. Keeping their operator guidance in this table
	// gives generic blocked/anomaly events and dedicated audit events one source
	// of truth.
	AuditResponseScan         = "response_scan"
	AuditHeaderDLP            = "header_dlp"
	AuditBodyPromptInjection  = "body_prompt_injection"
	AuditAddressProtection    = "address_protection"
	AuditChainDetection       = "chain_detection"
	AuditProvenance           = "provenance"
	AuditMediaPolicy          = "media_policy"
	AuditRequestPolicy        = "request_policy"
	AuditAgentIdentity        = "agent_identity"
	AuditTaintPolicy          = "taint_policy"
	AuditSessionAnomaly       = "session_anomaly"
	AuditAdaptiveEnforcement  = "adaptive_enforcement"
	AuditMCPSessionBinding    = "mcp_session_binding"
	AuditFrozenTool           = "frozen_tool"
	AuditSNIMismatch          = "sni_mismatch"
	AuditKillSwitch           = "kill_switch"
	AuditAirlock              = "airlock"
	AuditCrossRequestEntropy  = "cross_request_entropy"
	AuditCrossRequestFragment = "cross_request_fragment"
	AuditGitProtection        = "git_protection"
	AuditAgentBudget          = "budget"
	AuditResponseSize         = "response_size"
	AuditShieldOversize       = "shield_oversize"
	AuditContract             = "contract"
	AuditSSEStream            = "sse_stream"
	AuditUnscannable          = "unscannable_passthrough"
	AuditA2AScan              = "a2a_scan"
	AuditA2ACardSignature     = "a2a_card_signature"
	AuditRedaction            = "redaction"
	AuditScannerUnavailable   = "scanner_unavailable"
	AuditMediationEnvelope    = "mediation_envelope"
	AuditReceiptEmission      = "receipt_emission"
	AuditReverseSubmit        = "reverse_proxy_submit"
	AuditA2AHeader            = "a2a_header"
	AuditA2AResponse          = "a2a_response"
	AuditBudgetTruncated      = "budget_truncated"
	AuditTLSResponseBlocked   = "tls_response_blocked"
	AuditSessionDeny          = "session_deny"
	AuditTLSHandshakeError    = "tls_handshake_error"
	AuditTLSAuthorityMismatch = "tls_authority_mismatch"
)

// Decide*Label values identify non-URL blocks emitted by internal/decide.
// They are not URL scanner pipeline labels, but they share the remediation
// table so operator and agent guidance cannot drift by surface.
const (
	DecideInjectionLabel  = "injection"
	DecidePolicyLabel     = "policy"
	DecideStructuralLabel = "decide"
)

const (
	bodyDLPOperatorKnob        = "Request body DLP matched. For false positives, add a top-level suppress: entry with rule: set to the matched rule name and path: scoped to the request path."
	bodyEntropyOperatorKnob    = "If this destination is trusted to receive opaque body or WebSocket-frame content, add only that host to `request_body_scanning.content_entropy_exclusions`; for a WebSocket-only endpoint, prefer `websocket_proxy.content_entropy_exclusions`. `trusted_domains` is broader because it also affects SSRF trust."
	bodyEntropyOperatorBroader = "Raising `request_body_scanning.content_entropy_threshold` or setting `request_body_scanning.content_entropy_action: warn` affects opaque body/frame entropy for every destination; prefer a per-host exclusion first."
	denialOfWalletOperatorKnob = "Correct the denial-of-wallet condition named by the reason. `runaway expansion` and alternating `cycle detected` use fixed detector thresholds and have no per-detector limit knob. " +
		"To audit instead of block, set the matched `agents._default.budget.dow_action` (or `agents.<name>.budget.dow_action`) to `warn`; this changes enforcement for every denial-of-wallet finding."
	denialOfWalletToolCallsOperatorKnob = "Raise `agents._default.budget.max_tool_calls_per_session` (or the matched `agents.<name>.budget.max_tool_calls_per_session`) if the session's tool-call budget is intentionally higher."
	denialOfWalletWallClockOperatorKnob = "Raise `agents._default.budget.max_wall_clock_minutes` (or the matched `agents.<name>.budget.max_wall_clock_minutes`) if the session is intentionally longer-lived."
	denialOfWalletRetriesOperatorKnob   = "Raise `agents._default.budget.max_retries_per_tool` (or the matched `agents.<name>.budget.max_retries_per_tool`) if repeated identical calls are expected."
	responseScanOperatorKnob            = "For a false-positive response finding, add a top-level `suppress:` entry with `rule:` set to the event's matched pattern and `path:` scoped to the exact request path. `response_scanning.exempt_domains` is broader: it disables injection scanning for every response from that host."
	headerDLPOperatorKnob               = "For a false-positive header finding, add a top-level `suppress:` entry with `rule:` set to the matched DLP pattern and `path:` scoped to the exact request path. Header scanning calls this suppression list before enforcing the finding."
	bodyPromptInjectionOperatorKnob     = "Correct the outbound request body. The only destination carve-out this hard-block path consults is `response_scanning.exempt_domains`; adding a host there also disables injection scanning for every inbound response from that host, so it is a broad trust decision rather than a single-finding suppression."
	addressProtectionOperatorKnob       = "After independently verifying the intended destination, add the exact address to `address_protection.allowed_addresses` (or the matched `agents.<name>.allowed_addresses`). Do not weaken similarity thresholds to approve one address."
	chainDetectionOperatorKnob          = "If the event's named chain is expected, set that exact key under `tool_chain_detection.pattern_overrides` to `warn`; for a custom pattern, narrow its `sequence` or `action`. This changes only that named pattern."
	provenanceOperatorKnob              = "In `pipelock` mode, sign the tool metadata with an Ed25519 key present in `mcp_tool_provenance.trusted_keys`. `mcp_tool_provenance.action: warn` downgrades unsigned tools only; invalid signatures, verification errors, and malformed tools/list responses always fail closed. Sigstore trust fields are not consumed by this verifier, so they are not a remediation path."
	mediaPolicyOperatorKnob             = "Tune the media control identified by the reason under `media_policy`: `strip_audio`, `strip_video`, `strip_images`, `allowed_image_types`, or `max_image_bytes`. Parse/read failures have no exemption; correct the malformed media or upstream response."
	requestPolicyOperatorKnob           = "Edit the exact matched entry under `request_policy.rules` (the event reason names it), narrowing its route/predicate or changing that rule's action. For parser/opaque findings, tune only `request_policy.on_parse_error` or `request_policy.on_opaque_operation`; allowing either is broader and fail-open for matching body predicates."
	agentIdentityOperatorKnob           = "Use a non-reserved self-declared agent identity. Reserved control-actor names are a non-tunable identity boundary; there is no exemption knob."
	taintPolicyOperatorKnob             = "After inspecting the recorded source and action, add a narrow, expiring `taint.trust_overrides` entry matching that source/action, or correct the source classification. Changing `taint.policy` weakens all taint decisions and is broader."
	sessionAnomalyOperatorKnob          = "For a legitimate domain burst, raise the matched `session_profiling.domain_burst` threshold (global or per-agent) or the global-only `session_profiling.window_minutes`. For a behavioral baseline deviation, inspect the profile and explicitly relearn/ratify it with the baseline operator commands; do not auto-ratify an unexplained deviation."
	adaptiveEnforcementOperatorKnob     = "Wait for the event's auto-recovery time, or inspect and reset only the affected identity session with the session operator commands after confirming the traffic is legitimate. Changing `adaptive_enforcement.levels` or thresholds affects every session and is broader."
	mcpSessionBindingOperatorKnob       = "Refresh the MCP session only after verifying the server's current tool inventory. If inventory drift is intentionally non-blocking, change `mcp_session_binding.unknown_tool_action` (or `no_baseline_action` for a missing baseline) to `warn`; that applies to every matching inventory event."
	sniMismatchOperatorKnob             = "Correct the CONNECT hostname or TLS client so the SNI name matches the requested authority. `forward_proxy.sni_verification: false` disables domain-fronting protection for every tunnel and is not a narrow remediation."
	killSwitchOperatorKnob              = "Inspect and clear the active kill-switch source named by the event. Config, API, remote kill, stale bundle, SIGUSR1, and sentinel-file sources are OR-composed, so every active source must clear. HTTP and intercepted-request gates consult `kill_switch.allowlist_ips`; Pipelock health, metrics, and main-listener API endpoints have their own exemption flags. Raw/MCP kill-switch gates do not consult those HTTP exemptions."
	airlockOperatorKnob                 = "Inspect the affected session and wait for its configured `airlock.timers` recovery, or use the authenticated session operator command to lower/reset only that session after confirming the traffic is legitimate. Weakening global triggers or tiers is broader."
	crossRequestEntropyOperatorKnob     = "For a verified high-entropy destination, add only that host to `cross_request_detection.entropy_budget.exempt_domains`, or raise `bits_per_window` if the session-wide volume is expected. Changing `action` to `warn` affects every entropy-budget finding."
	crossRequestFragmentOperatorKnob    = "The fragment reassembly DLP path has no per-host or per-rule exemption. Correct the split secret-like payload; the only config relief is the broad `cross_request_detection.action: warn` (or disabling `fragment_reassembly`), which weakens this detector for every session."
	gitProtectionOperatorKnob           = "Add only the intended owner/repository to `git_protection.allowed_push_repos` after verifying the remote. Disabling `git_protection` permits pushes to every repository and is broader."
	agentBudgetOperatorKnob             = "Raise only the limit named by the reason under the matched `agents.<name>.budget`: `max_requests_per_session`, `max_bytes_per_session`, or `max_unique_domains_per_session`. Zero disables that ceiling and is broader."
	responseSizeOperatorKnob            = "Raise only the exact transport response ceiling named in the reason. A `response_scanning.size_exempt_domains` entry is not a universal override: fetch-handler response-size blocks do not consult it."
	shieldOversizeOperatorKnob          = "Raise `browser_shield.max_shield_bytes` for the expected response size, or add only the trusted host to `browser_shield.exempt_domains`. Changing `browser_shield.oversize_action` to `warn` or `scan_head` permits incompletely shielded content and is broader."
	contractOperatorKnob                = "Correct the action to match the active contract, or inspect and ratify a narrowly updated contract through the contract operator workflow. Disabling contract enforcement or broadening the manifest without review is not a safe remediation."
	sseStreamOperatorKnob               = "For a false-positive SSE finding, add a top-level `suppress:` entry for the matched response rule and exact path. For event-size failures, raise `response_scanning.sse_streaming.max_event_bytes`; changing its action to `warn` affects every SSE finding."
	unscannableOperatorKnob             = "Remove or narrow the matching `response_scanning.unscannable_passthrough` entry to restore fail-closed scanning, or make the upstream response scannable. This event records an explicit full-content visibility gap; do not broaden the entry."
	a2aScanOperatorKnob                 = "Correct the flagged A2A content. There is no per-finding suppression, and `a2a_scanning.action` is not a universal override: malformed/uninspectable payloads and hostname-exfiltration findings hard-block without consulting it."
	a2aCardSignatureOperatorKnob        = "Sign the Agent Card with a key whose exact origin is authorized by `a2a_scanning.trusted_agent_card_keys`, or add the verified signer/origin pair there. Disabling signed-card requirements trusts every unsigned card and is broader."
	redactionOperatorKnob               = "The requested redaction could not be applied safely. Correct the redaction profile or input and retry; there is no exemption knob because forwarding the unredacted payload would leak the protected value."
	scannerUnavailableOperatorKnob      = "Scanner acquisition failed closed during a reload/runtime transition. Restore scanner health or correct the rejected configuration and retry; there is no policy exemption for running without a scanner."
	mediationEnvelopeOperatorKnob       = "Mediation-envelope signing or verification failed closed. Restore the configured signing key/trust material or correct the envelope; there is no bypass knob when an envelope is required."
	receiptEmissionOperatorKnob         = "Required receipt emission failed closed. Restore the configured receipt sink/key and retry; there is no bypass knob while receipt-required enforcement is active."
	reverseSubmitOperatorKnob           = "Correct the submission to the configured `reverse_proxy` submit profile. This admission gate consults only `reverse_proxy.allowed_methods`, `reverse_proxy.allowed_paths`, and the effective minimum of `reverse_proxy.max_body_bytes` and `request_body_scanning.max_body_bytes`. Raw-path canonicality failures have no exemption."
	tlsFailureOperatorKnob              = "Correct the TLS handshake, certificate, or authority mismatch at the client/upstream and retry. These checks fail closed and have no per-request exemption; disabling TLS interception or SNI verification is a broad loss of visibility."

	decideInjectionOperatorKnob  = "Prompt-injection scanning matched content in the action. Shell/file/tool Decide paths consult `response_scanning.enabled` and `response_scanning.action`; they call `ScanResponse` without the top-level `suppress:` list, so a suppression entry is inert here. MCP Decide input consults `mcp_input_scanning.enabled` and `mcp_input_scanning.action`."
	decidePolicyOperatorKnob     = "Tool policy denied the action. Edit the matching `mcp_tool_policy.rules` entry, or narrow/add a rule for the intended tool call."
	decideStructuralOperatorKnob = "The action could not be evaluated safely (unknown event, malformed tool input, or uninspectable input). There is no allow-path knob for the structural failure; correct the action shape and retry."

	ssrfOperatorKnob = "If the destination is a trusted internal service, add the hostname to top-level `trusted_domains` (hostname-based) or the resolved range to `ssrf.ip_allowlist` (IP-based). " +
		"Cloud-metadata, link-local, and multicast addresses are a non-overridable deny — neither knob exempts them (config validation rejects such entries). " +
		"This verdict depends on DNS resolution at runtime; explain reports it without resolving."
	ssrfOperatorBroader = "Disabling SSRF entirely (`internal: []`) removes private-range protection for ALL destinations — never do this to fix one host."

	// Cloud metadata endpoints are a credential-theft target and a
	// non-overridable SSRF deny: ssrf.ip_allowlist and trusted_domains cannot
	// exempt them (both config validation and the scanner refuse). There is no
	// allow-path knob by design.
	ssrfMetadataOperatorKnob = "Cloud instance-metadata endpoints are a non-overridable SSRF deny: `ssrf.ip_allowlist` and `trusted_domains` cannot exempt them (config validation rejects such entries and the scanner ignores them). " +
		"There is no allow knob — if an agent legitimately needs instance data, expose it through a dedicated internal service on a different address rather than allowing metadata access."

	// Link-local, multicast, and unspecified addresses share the metadata
	// deny's non-overridable status but are not metadata, so they get their own
	// wording rather than talking about "instance-metadata endpoints".
	ssrfNonOverridableOperatorKnob = "This is a non-overridable SSRF deny (link-local, multicast, or unspecified address): `ssrf.ip_allowlist` and `trusted_domains` cannot exempt it (config validation rejects such entries and the scanner ignores them). " +
		"There is no allow knob — reach the intended service by its ordinary routable or private address instead."

	injectionTraversalOperatorKnob = "This sequence is never legitimate in a normal URL (header injection / directory escape). There is no exemption knob — the URL must be corrected at the source."
	parseContextOperatorKnob       = "This is not a policy block: the request context was unavailable/cancelled, or the URL could not be parsed. Correct the input and retry."

	// Query entropy shares the ScannerEntropy label with path/subdomain entropy
	// but is a distinct gate with a distinct knob. The table is keyed by label
	// alone, so this variant is selected by GuidanceForResult from the scan
	// Reason. The path-entropy default lives in the table's ScannerEntropy entry.
	queryEntropyOperatorKnob = "If the blocked URL is a known exact endpoint and parameter, add that tuple to `fetch_proxy.monitoring.query_entropy_param_exclusions`; this skips only query-value entropy for that exact scheme+host+path+param. " +
		"If the whole host legitimately carries opaque query values across many endpoints, use `fetch_proxy.monitoring.query_entropy_exclusions` as the broader host-wide fallback. Query entropy is SEPARATE from URL DLP — exempting a DLP pattern does NOT lift an entropy block, and vice versa."
	queryEntropyOperatorBroader = "Raising `fetch_proxy.monitoring.entropy_threshold` lowers sensitivity globally for every destination — broader blast radius; prefer the endpoint-parameter exemption first, then the host-wide exclusion only when the broad host contract needs it."

	secretAgentReason             = "Request blocked: the destination or content matched a secret/credential pattern."
	highEntropyAgentReason        = "Request blocked: high-entropy content resembling exfiltration was detected."
	protectedAddressAgentReason   = "Request blocked: the destination resolves to protected internal or metadata infrastructure."
	protectiveCeilingAgentReason  = "Request blocked: a protective request ceiling was exceeded."
	denialOfWalletAgentReason     = "Request blocked: the MCP action exceeded its denial-of-wallet budget."
	injectionTraversalAgentReason = "Request blocked: the URL contains an injection/traversal sequence."
	promptInjectionAgentReason    = "Request blocked: the content matched a prompt-injection pattern."
	toolPolicyAgentReason         = "Request blocked: the tool call is not permitted by policy."
	decideStructuralAgentReason   = "Request blocked: the action could not be evaluated."
	auditContentAgentReason       = "Request blocked: protected content or an unsafe instruction pattern was detected."
	auditPolicyAgentReason        = "Request blocked: an operator-defined safety boundary denied the action."
	auditRuntimeAgentReason       = "Request blocked: a required security control could not complete safely."
	auditAnomalyAgentReason       = "Activity was flagged because it crossed an operator-defined safety boundary."
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
			"If the value is a long token in the query string, you may ALSO need `fetch_proxy.monitoring.query_entropy_param_exclusions` for an exact endpoint+parameter, or `fetch_proxy.monitoring.query_entropy_exclusions` as the broader host-wide fallback (a separate gate).",
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
		OperatorKnob: ssrfMetadataOperatorKnob,
		Immutable:    true,
		AgentReason:  protectedAddressAgentReason,
	},
	ScannerCoreSSRF: {
		OperatorKnob: "Core SSRF blocks private/loopback/link-local IP literals as an immutable floor. `ssrf.ip_allowlist` can exempt a specific private or loopback address, but cloud-metadata, link-local, and multicast addresses are non-overridable — no allowlist entry exempts them. There is no way to disable the floor wholesale.",
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
		OperatorKnob: "This is the URL scanner's per-domain sliding-window data ceiling. Raise `fetch_proxy.monitoring.max_data_per_minute` if the response volume is legitimate; zero disables this ceiling for every destination.",
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
		OperatorKnob: "Core response scanning cannot be disabled wholesale, even when `response_scanning.enabled` is false. For a proven false positive, `ScanResponseWithSuppress` does consult the top-level `suppress:` list: match the exact core pattern name and scope `path:` to the affected response path.",
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
	AuditBodyEntropy: {
		OperatorKnob:    bodyEntropyOperatorKnob,
		OperatorBroader: bodyEntropyOperatorBroader,
		AgentReason:     highEntropyAgentReason,
	},
	ScannerDenialOfWallet: {
		OperatorKnob: denialOfWalletOperatorKnob,
		AgentReason:  denialOfWalletAgentReason,
	},
	AuditResponseScan:         {OperatorKnob: responseScanOperatorKnob, AgentReason: auditContentAgentReason},
	AuditHeaderDLP:            {OperatorKnob: headerDLPOperatorKnob, AgentReason: secretAgentReason},
	AuditBodyPromptInjection:  {OperatorKnob: bodyPromptInjectionOperatorKnob, AgentReason: auditContentAgentReason},
	AuditAddressProtection:    {OperatorKnob: addressProtectionOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditChainDetection:       {OperatorKnob: chainDetectionOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditProvenance:           {OperatorKnob: provenanceOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditMediaPolicy:          {OperatorKnob: mediaPolicyOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditRequestPolicy:        {OperatorKnob: requestPolicyOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditAgentIdentity:        {OperatorKnob: agentIdentityOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditTaintPolicy:          {OperatorKnob: taintPolicyOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditSessionAnomaly:       {OperatorKnob: sessionAnomalyOperatorKnob, AgentReason: auditAnomalyAgentReason},
	AuditAdaptiveEnforcement:  {OperatorKnob: adaptiveEnforcementOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditMCPSessionBinding:    {OperatorKnob: mcpSessionBindingOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditSNIMismatch:          {OperatorKnob: sniMismatchOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditKillSwitch:           {OperatorKnob: killSwitchOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditAirlock:              {OperatorKnob: airlockOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditCrossRequestEntropy:  {OperatorKnob: crossRequestEntropyOperatorKnob, AgentReason: auditAnomalyAgentReason},
	AuditCrossRequestFragment: {OperatorKnob: crossRequestFragmentOperatorKnob, AgentReason: auditContentAgentReason},
	AuditGitProtection:        {OperatorKnob: gitProtectionOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditAgentBudget:          {OperatorKnob: agentBudgetOperatorKnob, AgentReason: protectiveCeilingAgentReason},
	AuditResponseSize:         {OperatorKnob: responseSizeOperatorKnob, AgentReason: protectiveCeilingAgentReason},
	AuditShieldOversize:       {OperatorKnob: shieldOversizeOperatorKnob, AgentReason: protectiveCeilingAgentReason},
	AuditContract:             {OperatorKnob: contractOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditSSEStream:            {OperatorKnob: sseStreamOperatorKnob, AgentReason: auditContentAgentReason},
	AuditUnscannable:          {OperatorKnob: unscannableOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditA2AScan:              {OperatorKnob: a2aScanOperatorKnob, AgentReason: auditContentAgentReason},
	AuditA2ACardSignature:     {OperatorKnob: a2aCardSignatureOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditRedaction:            {OperatorKnob: redactionOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditScannerUnavailable:   {OperatorKnob: scannerUnavailableOperatorKnob, Immutable: true, AgentReason: auditRuntimeAgentReason},
	AuditMediationEnvelope:    {OperatorKnob: mediationEnvelopeOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditReceiptEmission:      {OperatorKnob: receiptEmissionOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditReverseSubmit:        {OperatorKnob: reverseSubmitOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditFrozenTool:           {OperatorKnob: airlockOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditA2AHeader:            {OperatorKnob: a2aScanOperatorKnob, AgentReason: auditContentAgentReason},
	AuditA2AResponse:          {OperatorKnob: a2aScanOperatorKnob, AgentReason: auditContentAgentReason},
	AuditBudgetTruncated:      {OperatorKnob: agentBudgetOperatorKnob, AgentReason: protectiveCeilingAgentReason},
	AuditTLSResponseBlocked:   {OperatorKnob: responseScanOperatorKnob, AgentReason: auditContentAgentReason},
	AuditSessionDeny:          {OperatorKnob: adaptiveEnforcementOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditTLSHandshakeError:    {OperatorKnob: tlsFailureOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditTLSAuthorityMismatch: {OperatorKnob: tlsFailureOperatorKnob, AgentReason: auditRuntimeAgentReason},
	DecideInjectionLabel: {
		OperatorKnob: decideInjectionOperatorKnob,
		AgentReason:  promptInjectionAgentReason,
	},
	DecidePolicyLabel: {
		OperatorKnob: decidePolicyOperatorKnob,
		AgentReason:  toolPolicyAgentReason,
	},
	DecideStructuralLabel: {
		OperatorKnob: decideStructuralOperatorKnob,
		Immutable:    true,
		AgentReason:  decideStructuralAgentReason,
	},
}

// GuidanceFor returns the remediation guidance for a scanner/block label. The
// second return is false for an unknown label — callers get no guidance rather
// than a wrong one (fail-safe).
func GuidanceFor(label string) (RemediationGuidance, bool) {
	g, ok := remediationGuidance[label]
	return g, ok
}

// OperatorHintFor returns the operator allow-path (OperatorKnob) for a label, or
// "" when the label has no guidance. Convenience for string-valued operator
// surfaces such as the audit remediation_hint field. Never use it for an
// agent-facing surface — that is what AgentReason (via GuidanceFor) is for.
//
// Prefer OperatorHintForResult when the scan Reason is available: a label alone
// cannot distinguish same-label variants (query vs path entropy), so this can
// return the wrong knob for a query-entropy block.
func OperatorHintFor(label string) string {
	g, _ := GuidanceFor(label)
	return g.OperatorKnob
}

// GuidanceForResult returns guidance using the scan Reason to disambiguate
// same-label variants. ScannerEntropy distinguishes query from path/subdomain
// entropy, while ScannerDenialOfWallet distinguishes budget-limit reasons.
// Every other label falls through to the label-keyed table. This is the single
// place that disambiguation lives, so explain, audit, and future consumers agree.
func GuidanceForResult(label, reason string) (RemediationGuidance, bool) {
	// Some transports retain historical audit labels for the same enforcing
	// family. Normalize them before reason routing so alternate labels cannot
	// drift to a less accurate hint.
	switch label {
	case AuditTLSResponseBlocked:
		label = AuditResponseScan
	case AuditBudgetTruncated:
		label = AuditAgentBudget
	case AuditSessionDeny:
		label = AuditAdaptiveEnforcement
	case AuditA2AHeader, AuditA2AResponse:
		label = AuditA2AScan
	}

	lowerReason := strings.ToLower(reason)
	if label == AuditCrossRequestEntropy && strings.Contains(lowerReason, "cross-request entropy") {
		return RemediationGuidance{
			OperatorKnob: "For MCP cross-request entropy, raise `cross_request_detection.entropy_budget.bits_per_window` if the session-wide volume is expected. Changing `cross_request_detection.entropy_budget.action` to `warn` affects every MCP entropy-budget finding. The MCP gate does not consult `entropy_budget.exempt_domains`.",
			AgentReason:  auditAnomalyAgentReason,
		}, true
	}
	if label == AuditResponseScan {
		switch {
		case strings.Contains(lowerReason, "compressed"),
			strings.Contains(lowerReason, "read error"),
			strings.Contains(lowerReason, "read_error"),
			strings.Contains(lowerReason, "cannot be scanned"),
			strings.Contains(lowerReason, "parse error"),
			strings.Contains(lowerReason, "parse_error"):
			return RemediationGuidance{
				OperatorKnob: "This is a scan-integrity failure, not a pattern false positive: correct the compressed, unreadable, or malformed upstream response and retry. A `suppress:` entry cannot make content scannable; `response_scanning.exempt_domains` would disable scanning for every response from the host and is not a narrow fix.",
				AgentReason:  auditRuntimeAgentReason,
			}, true
		case strings.Contains(lowerReason, "size-exempt response scan") && strings.Contains(lowerReason, "inflight"):
			return RemediationGuidance{
				OperatorKnob: "Raise `response_scanning.size_exempt_scan_max_inflight_bytes` only if this proxy instance has enough memory for the larger aggregate reservation. The in-flight admission gate reads that field directly.",
				AgentReason:  protectiveCeilingAgentReason,
			}, true
		case strings.Contains(lowerReason, "size-exempt response"):
			return RemediationGuidance{
				OperatorKnob: "Raise `response_scanning.size_exempt_scan_max_bytes` only to the largest whole response this trusted host needs. `response_scanning.unscannable_passthrough` is a broader, explicit visibility gap for deliberately opaque content.",
				AgentReason:  protectiveCeilingAgentReason,
			}, true
		case strings.Contains(lowerReason, "response size"),
			strings.Contains(lowerReason, "scan ceiling"),
			strings.Contains(lowerReason, "oversized"):
			return RemediationGuidance{
				OperatorKnob: responseSizeOperatorKnob,
				AgentReason:  protectiveCeilingAgentReason,
			}, true
		}
	}
	if label == AuditMediaPolicy {
		operatorKnob := ""
		switch {
		case strings.Contains(lowerReason, "audio stripped"):
			operatorKnob = "If this agent intentionally consumes audio, set `media_policy.strip_audio: false`. This permits all otherwise-allowed audio types because Pipelock cannot inspect instructions embedded in audio."
		case strings.Contains(lowerReason, "video stripped"):
			operatorKnob = "If this agent intentionally consumes video, set `media_policy.strip_video: false`. This permits all otherwise-allowed video types because Pipelock cannot inspect instructions embedded in video."
		case strings.Contains(lowerReason, "images stripped"):
			operatorKnob = "If this agent intentionally consumes images, set `media_policy.strip_images: false`; keep `allowed_image_types`, metadata stripping, and `max_image_bytes` constrained."
		case strings.Contains(lowerReason, "not in allowed list"):
			operatorKnob = "After verifying the format is required and non-active, add only that exact image media type to `media_policy.allowed_image_types`. SVG remains unsupported because it is active content."
		case strings.Contains(lowerReason, "exceeds limit"):
			operatorKnob = "Raise `media_policy.max_image_bytes` only to the largest verified image size the agent needs; the limit is the decompression-bomb and memory ceiling."
		case strings.Contains(lowerReason, "parse error"),
			strings.Contains(lowerReason, "re-marshal"),
			strings.Contains(lowerReason, "read error"):
			operatorKnob = "The media could not be parsed or transported safely. Correct the malformed media/upstream response and retry; there is no exemption knob for forwarding an unvalidated media payload."
		}
		if operatorKnob != "" {
			return RemediationGuidance{OperatorKnob: operatorKnob, AgentReason: auditPolicyAgentReason}, true
		}
	}
	if label == AuditRequestPolicy {
		switch {
		case strings.Contains(lowerReason, "exceeds max_body_bytes"):
			return RemediationGuidance{
				OperatorKnob: "Raise `request_body_scanning.max_body_bytes` only to the largest verified request body this route needs; request-policy body predicates consume that same bounded-read ceiling.",
				AgentReason:  protectiveCeilingAgentReason,
			}, true
		case strings.Contains(lowerReason, "could not be inspected"):
			return RemediationGuidance{
				OperatorKnob: "The request body could not be read and therefore cannot be forwarded intact. Correct the client/body stream and retry; `request_policy.on_parse_error` does not control read failures and no exemption can restore consumed bytes.",
				AgentReason:  auditRuntimeAgentReason,
			}, true
		}
	}
	if label == AuditReverseSubmit {
		switch {
		case strings.Contains(lowerReason, "not in allowed_methods"):
			return RemediationGuidance{
				OperatorKnob: "If this method is intentionally accepted by the submit listener, add only that method to `reverse_proxy.allowed_methods`; this gate reads that list before any scanner work.",
				AgentReason:  auditPolicyAgentReason,
			}, true
		case strings.Contains(lowerReason, "not in allowed_paths"):
			return RemediationGuidance{
				OperatorKnob: "If this exact canonical path is intentional, add only it under `reverse_proxy.allowed_paths[].exact`; prefix and regex exemptions are not supported.",
				AgentReason:  auditPolicyAgentReason,
			}, true
		case strings.Contains(lowerReason, "body exceeds"), strings.Contains(lowerReason, "body cap"):
			return RemediationGuidance{
				OperatorKnob: "Raise the smaller active body ceiling: `reverse_proxy.max_body_bytes` or `request_body_scanning.max_body_bytes`. The submit gate enforces their minimum before forwarding.",
				AgentReason:  protectiveCeilingAgentReason,
			}, true
		case strings.Contains(lowerReason, "raw path"), strings.Contains(lowerReason, "path is not canonical"):
			return RemediationGuidance{
				OperatorKnob: "Send the canonical decoded path without encoded traversal, encoded separators, semicolon parameters, or dot segments. This fail-closed path check has no exemption knob.",
				AgentReason:  auditPolicyAgentReason,
			}, true
		}
	}
	if label == AuditRedaction && strings.Contains(lowerReason, "non_json_body") {
		return RemediationGuidance{
			OperatorKnob: "If this exact non-JSON route is intentionally safe to forward without redaction, add the narrow host/path match to `redaction.allowlist_unparseable_routes`. `redaction.allowlist_unparseable` is the broader host-wide fallback. Both paths forward the body unredacted, so verify it cannot carry the protected value first.",
			AgentReason:  auditRuntimeAgentReason,
		}, true
	}
	if label == AuditA2AScan {
		switch {
		case strings.Contains(lowerReason, "invalid json"),
			strings.Contains(lowerReason, "duplicate json"),
			strings.Contains(lowerReason, "maximum inspectable nesting"),
			strings.Contains(lowerReason, "could not be read"),
			strings.Contains(lowerReason, "request body exceeds"):
			return RemediationGuidance{
				OperatorKnob: "Correct the malformed, unreadable, oversized, or uninspectable A2A payload and retry. This structural fail-closed path does not consult `a2a_scanning.action` and has no exemption knob.",
				AgentReason:  auditRuntimeAgentReason,
			}, true
		case strings.Contains(lowerReason, "hostname exfiltration"):
			return RemediationGuidance{
				OperatorKnob: "Remove the secret-like hostname payload. A2A hostname-exfiltration is a hard block and does not consult `a2a_scanning.action`; there is no A2A suppression knob.",
				AgentReason:  auditContentAgentReason,
			}, true
		case strings.Contains(lowerReason, "url/ssrf finding"):
			return RemediationGuidance{
				OperatorKnob: "Correct the embedded URL or remediate the underlying URL/SSRF scanner finding. Do not rely on `a2a_scanning.action`: hostname-exfiltration URL findings hard-block before that field is consulted.",
				AgentReason:  auditContentAgentReason,
			}, true
		case strings.Contains(lowerReason, "payload exceeded node budget"),
			strings.Contains(lowerReason, "a2a-extensions header"),
			strings.Contains(lowerReason, "injection:"),
			strings.Contains(lowerReason, "dlp:"),
			strings.Contains(lowerReason, "agent card drift"):
			return RemediationGuidance{
				OperatorKnob: "Correct the flagged A2A content. If this non-structural finding is intentionally audit-only, set `a2a_scanning.action: warn`; this path derives its effective action from that field.",
				AgentReason:  auditContentAgentReason,
			}, true
		}
	}
	if label == AuditAgentBudget {
		operatorKnob := ""
		switch {
		case strings.Contains(lowerReason, "request budget"):
			operatorKnob = "Raise only `agents.<name>.budget.max_requests_per_session` if the session's request count is expected."
		case strings.Contains(lowerReason, "domain budget"):
			operatorKnob = "Raise only `agents.<name>.budget.max_unique_domains_per_session` if the session's destination diversity is expected."
		case strings.Contains(lowerReason, "byte budget"):
			operatorKnob = "Raise only `agents.<name>.budget.max_bytes_per_session` if the session's response volume is expected."
		}
		if operatorKnob != "" {
			return RemediationGuidance{OperatorKnob: operatorKnob, AgentReason: protectiveCeilingAgentReason}, true
		}
	}
	if label == AuditSessionAnomaly {
		switch {
		case strings.Contains(lowerReason, "baseline_deviation"):
			return RemediationGuidance{
				OperatorKnob: "Inspect the behavioral profile with `pipelock baseline show <agent>`. If the new behavior is legitimate, deliberately relearn and ratify it with the baseline operator commands; do not enable `behavioral_baseline.auto_ratify` to silence an unexplained deviation.",
				AgentReason:  auditAnomalyAgentReason,
			}, true
		case strings.Contains(lowerReason, "domain_burst"):
			return RemediationGuidance{
				OperatorKnob: "Raise the matched `session_profiling.domain_burst` threshold (global or `agents.<name>.session_profiling.domain_burst`) or adjust the global-only `session_profiling.window_minutes` if this destination burst is expected.",
				AgentReason:  auditAnomalyAgentReason,
			}, true
		}
	}
	if label == ScannerEntropy && strings.Contains(reason, "query ") {
		return RemediationGuidance{
			OperatorKnob:    queryEntropyOperatorKnob,
			OperatorBroader: queryEntropyOperatorBroader,
			AgentReason:     highEntropyAgentReason,
		}, true
	}
	if label == ScannerDenialOfWallet {
		operatorKnob := ""
		switch {
		case strings.Contains(reason, "tool call limit exceeded"):
			operatorKnob = denialOfWalletToolCallsOperatorKnob
		case strings.Contains(reason, "wall clock budget exceeded"):
			operatorKnob = denialOfWalletWallClockOperatorKnob
		case strings.Contains(reason, "loop detected"):
			operatorKnob = denialOfWalletRetriesOperatorKnob
		}
		if operatorKnob != "" {
			return RemediationGuidance{
				OperatorKnob: operatorKnob,
				AgentReason:  denialOfWalletAgentReason,
			}, true
		}
	}
	// The dial-time SSRF guard logs metadata blocks under the generic
	// ScannerSSRF label (the metadata classification lives in the reason
	// string), and non-metadata link-local/multicast blocks use the same generic
	// label with "non-overridable" in the reason. A label-only lookup would hand
	// back the ssrfOperatorKnob that names ssrf.ip_allowlist/trusted_domains -
	// knobs that cannot exempt these targets. Route those reason-specific SSRF
	// blocks to the non-overridable guidance regardless of which SSRF label
	// carried them.
	if label == ScannerSSRF || label == ScannerSSRFMetadata || label == ScannerCoreSSRF {
		if strings.Contains(reason, "metadata") {
			return RemediationGuidance{
				OperatorKnob: ssrfMetadataOperatorKnob,
				Immutable:    true,
				AgentReason:  protectedAddressAgentReason,
			}, true
		}
		if strings.Contains(reason, "non-overridable") {
			return RemediationGuidance{
				OperatorKnob: ssrfNonOverridableOperatorKnob,
				Immutable:    true,
				AgentReason:  protectedAddressAgentReason,
			}, true
		}
	}
	return GuidanceFor(label)
}

// OperatorHintForResult is OperatorHintFor with Reason-based disambiguation. Use
// it wherever the scan Reason is in hand (audit, block responses) so a
// query-entropy block gets the query-entropy knob rather than the path default.
func OperatorHintForResult(label, reason string) string {
	g, _ := GuidanceForResult(label, reason)
	return g.OperatorKnob
}
