// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Golden-file canonical-hash stability fixtures. These pin the current
// CanonicalPolicyHash output against fixed-input Configs so that a
// mechanical refactor of internal/config (TD-2b) cannot silently shift
// ph and invalidate every signed receipt and mediation envelope that
// already attests the v2.2.0 policy surface.
//
// If one of these hashes drifts, the change broke canonical hash
// stability. That is admission-grade: every receipt emitted since
// v2.2.0 carries ph derived from CanonicalPolicyHash, and every
// cross-implementation verifier (the Python reference, any third-party
// consumer) expects the same hash for the same effective policy.
//
// If you INTENTIONALLY change canonical-hash semantics - a new policy
// field added to policySemanticView, a set-like slice graduated to
// behavioral ordering, the default pattern corpus expanded - update
// the constant to match the new value and note the bump in the PR
// body. Do not silently regenerate: the whole point of this test is to
// make the drift visible in review.

const (
	// goldenHashDefaults pins CanonicalPolicyHash for a freshly
	// constructed Defaults() config, post-ApplyDefaults + Validate.
	// This is the "out of the box" hash a user gets from `pipelock
	// run` with no --config flag.
	// Bumped for the contract-compile observation pipeline schema:
	// Defaults() now includes the Learn top-level block (enabled=false,
	// privacy.public_allowlist_default=true). New policy surface → ph
	// must shift so verifiers detect the schema change.
	// Re-bumped on the inference-engine wiring PR: Learn now carries an
	// inference.floors substruct (min_sessions/min_events/min_windows).
	// Floors are detection-relevant (they decide stable vs
	// never_confirmed at compile time), so they must flow into ph so
	// verifiers detect deployments that loosen the exposure gates.
	// Re-bumped on the path-normalization wiring PR: Learn now also
	// carries an inference.normalization substruct (algorithm,
	// min_events, min_distinct_values, entropy_threshold_bits,
	// reserved_segments_extra, cardinality_cap_per_host,
	// tail_promotion_block_pct). Normalization knobs are
	// policy-relevant because they decide which path segments collapse
	// to wildcards at compile time. An operator who lowers the entropy
	// threshold or raises the cardinality cap silently widens the
	// wildcard surface of every emitted contract; the verifier must
	// observe the schema change through ph.
	// Re-bumped on the same PR after policySemanticView started
	// resolving zero-valued floors and normalization fields to their
	// effective defaults before hashing. The change closes a verifier-
	// drift hole: a YAML omitting learn.inference.floors and a YAML
	// setting them explicitly to 5/20/3 now hash identically because
	// they describe the same effective policy.
	// Re-bumped for federation plumbing: mediation_envelope now carries
	// actor_format/trust_domain and inbound verify/replay settings.
	// These change the attested envelope trust contract, so ph must move.
	// Re-bumped for federation hardening: mediation_envelope now carries
	// signature_expires (operator-tunable signer lifetime, paired with
	// the inbound replay window), and verify_inbound.trust_list[].
	// trust_domains (per-key actor binding so a compromised partner key
	// cannot impersonate another peer's trust domain). Both change the
	// attested envelope trust contract.
	// Re-bumped for route-scoped redaction non-JSON exceptions:
	// redaction.allowlist_unparseable_routes is new policy surface that
	// constrains which opaque request formats may skip JSON rewriting.
	// Re-bumped to close documented skill-poisoning vector gaps:
	// Memory Persistence Directive, Credential Solicitation, and Covert
	// Action Directive each widened their alternation to catch three
	// vectors that escaped the prior pattern set (memory persistence
	// using "future sessions"/"for all future", credential solicitation
	// of plural ".aws/credentials" files, covert exfil verbs including
	// exfiltrate/leak/stream/transmit/relay/forward/smuggle). See
	// TestSkillPoisoningCorpus for the six-vector regression suite.
	// Re-bumped for production-readiness tuning: Browser Shield
	// oversize handling now defaults to scan_head, TLS passthrough has a
	// googlevideo baseline, Browser Shield has a small large-site exempt
	// baseline, and adaptive enforcement defaults to downweighting
	// cooperative tool burst anomalies.
	// Re-bumped to include the effective session-profiling defaults in
	// Defaults() itself, so programmatic enablement gets the same domain
	// burst/window/volume baselines as YAML-loaded configs.
	// Re-bumped for signed MCP binary-integrity manifests:
	// mcp_binary_integrity now carries signature trust settings that can
	// make runtime launch fail closed before any MCP traffic is handled.
	// Re-bumped for Spanish prompt-injection coverage: the default
	// response-scanning corpus now includes Spanish instruction override
	// and system-prompt disclosure patterns.
	// Re-bumped for cross-lingual prompt-injection coverage: the default
	// response-scanning corpus now includes mixed English/Spanish instruction
	// override and system-prompt disclosure patterns.
	// 2026-05-21: rotated for ToolChainDetection.SensitivityLabels (v2.6
	// lethal-trifecta detection). Adds a policy-semantic field to the
	// canonical hash surface.
	// Re-bumped on the Databricks PAT pattern tightening: the default DLP
	// regex moves from `dapi[a-z0-9]{30,}` to `dapi[0-9a-f]{32,}`. This
	// matches the documented 32-char hex Databricks token format and removes
	// a false-positive surface that fired on random base64 image payloads.
	// Re-bumped for DLP false-positive sprint hardening: high-risk
	// short-prefix provider patterns were narrowed to bounded documented
	// shapes, and package-host path entropy exclusions were added.
	// Re-bumped for DLP false-positive hardening pass 2: Vault, Supabase,
	// Linear, and Sentry provider-token patterns were tightened to
	// documented shapes and leading/trailing token boundaries.
	// Re-bumped again after the Supabase right edge was adjusted to keep
	// matching valid base64url checksums that end in '-'.
	// Re-bumped for the dns.host_overrides addition: dns is policy-relevant
	// (it changes the destination IPs the SSRF check evaluates) and so it
	// participates in the canonical view; the field is present but empty
	// in Defaults().
	// Re-bumped for file_sentry.action: adding the warn/block enforcement
	// enum to FileSentry is a policy-semantics change. The default "warn"
	// preserves current behavior; "block" causes the consumer to cancel
	// the proxy ctx on agent-attributed findings, which is observably
	// different enforcement.
	// Re-bumped for the request_policy section: adding the request_policy
	// operation-rails config (allow-by-default deny/warn rules over outbound
	// API operations) is a policy-semantics change. The field is present but
	// empty (disabled, no rules) in Defaults(), so it shifts the baseline hash.
	// Re-bumped for request_policy fail-closed parse/opaque-operation actions:
	// these control whether unreadable GraphQL operations block, warn, or pass.
	// Bumped for the request_policy.batch section (JSON batch endpoint
	// recursion): adding the policy-affecting field changes the canonical hash.
	// Bumped for fetch_proxy.monitoring.query_entropy_exclusions: per-host
	// bypass for the query parameter entropy gate is a policy-semantic
	// change. Empty by default but the field is part of the canonical view.
	// Re-bumped for the file_sentry max_file_bytes field: see note above.
	// Bumped when mcp_tool_policy.quarantine_dir was removed from the
	// canonical view: its default is derived from os.TempDir(), which made
	// this hash depend on the ambient TMPDIR. Excluding the operational path
	// makes the hash environment-independent (identical policy -> identical
	// hash), which is the admission-grade contract.
	// Re-bumped for the Twilio + Mailgun DLP pattern boundary tightening
	// (defaults.go DLP set): SK[a-f0-9]{32} -> \bSK[a-f0-9]{32}\b and
	// key-[a-zA-Z0-9]{32} -> \bkey-[a-zA-Z0-9]{32}\b.
	// Re-bumped for the secret-pattern expansion (defaults.go DLP set,
	// 48 -> 62): added DB connection-string patterns (postgres/mysql/mongodb/
	// redis with embedded creds), the remaining GitLab token families
	// (gldt-/glrt-/glcbt-/glptt-/gloas-/glsoat-/grouped service tokens), and
	// cloud SA key patterns (GCP private_key_id, Azure storage account key,
	// Azure SAS signature). The GCP service_account marker is core DLP, not a
	// default pattern.
	// Re-bumped again: the "Private Key Header" pattern now also matches PGP
	// armor and the trailing BLOCK keyword, aligning DLP detection with the
	// ssh-private-key redaction class.
	// Re-bumped for A2A Agent Card signature verification: a2a_scanning gained
	// the require_signed_agent_cards and trusted_agent_card_keys policy fields,
	// which are enforcement-relevant and so belong in the canonical policy hash.
	// Re-bumped for response_scanning.size_exempt_domains: trusted per-host
	// oversize response passthrough changes response-size enforcement.
	// Re-bumped for git_protection.allowed_push_repos. The field is
	// policy-semantic because it changes whether visible git-receive-pack
	// pushes are allowed at the proxy.
	// Re-bumped for DLP precision: the "Environment Variable Secret" and
	// "Credential in URL" default patterns now require a secret-plausible
	// leading value character so the whitespace-collapsed DLP view cannot
	// over-match benign shell env-var references; the "Credential in URL"
	// value tail additionally excludes ';' so a semicolon-separated param
	// does not bleed into the captured credential. Detection-relevant change.
	// Re-bumped for flight_recorder.require_receipts: the default is false,
	// but explicit true changes enforcement by blocking otherwise-allowed
	// requests when a required receipt cannot be emitted.
	// Re-bumped for response-injection precision: the "Hidden Instruction"
	// default pattern now matches the directive-marker form
	// (hidden instruction:) instead of the bare noun, and "Credential
	// Solicitation" narrows the "include" verb to direct include-your-secret
	// requests while rehoming include-secret-path forms to "Credential Path
	// Directive", so security-standards/docs prose that DESCRIBES these attacks
	// no longer over-matches while imperative credential asks still block.
	// Detection-relevant change.
	// Re-bumped for "Credential Solicitation" direction-anchoring: the default
	// (and immutable core floor) now require a hand-over verb + credential noun
	// to co-occur with an explicit "send it back to the requester" cue within
	// one sentence, instead of the prior verb-near-noun .{0,80} rule that
	// hard-blocked ordinary credential setup documentation ("provide your API
	// key in config"). Imperative solicitations to the requester still block.
	// Detection-relevant change.
	goldenHashDefaults = "1a92ec956d0ee2e605ccdb523f8088ce7277675989ef617ad9697b0c1dabf9ab"

	// goldenHashRichConfig pins the hash for goldenRichYAML loaded via
	// config.Load, post-ApplyDefaults + Validate. Covers a broad,
	// representative policy-semantic fixture with emphasis on the
	// sections most likely to drift during TD-2b.
	// Bumped for the contract-compile observation pipeline schema:
	// the rich fixture now carries a Learn block with enabled=false +
	// privacy.public_allowlist_default=true defaults, so ph must shift
	// in lockstep with the Defaults() bump above.
	// Re-bumped on the inference-engine wiring PR: see goldenHashDefaults
	// note above. Floors decode as zero in the rich fixture (which does
	// not set them) and Resolved() supplies defaults at runtime, so the
	// rich-config hash shifts in lockstep with Defaults().
	// Re-bumped on the path-normalization wiring PR: see goldenHashDefaults
	// note above. Normalization knobs decode as zero in the rich fixture
	// (which does not set them) and Resolved() supplies defaults at
	// runtime, so the rich-config hash shifts in lockstep with Defaults().
	// Re-bumped on the same PR after policySemanticView started
	// resolving zero-valued floors and normalization fields to their
	// effective defaults before hashing. See goldenHashDefaults note
	// above. The rich fixture omits the inference substruct, so
	// resolved-default values flow into ph identically to Defaults().
	// Re-bumped for federation plumbing: see goldenHashDefaults note.
	// Re-bumped for federation hardening: see goldenHashDefaults note.
	// Re-bumped for route-scoped redaction non-JSON exceptions: see
	// goldenHashDefaults note.
	// Re-bumped for skill-poisoning pattern broadening: see
	// goldenHashDefaults note. The rich fixture inherits the response
	// scanning pattern set from Defaults(), so the hash shifts in
	// lockstep.
	// Re-bumped for production-readiness tuning: see
	// goldenHashDefaults note.
	// Re-bumped for signed MCP binary-integrity manifests: see
	// goldenHashDefaults note above.
	// Re-bumped for Spanish prompt-injection coverage: see
	// goldenHashDefaults note above.
	// Re-bumped for cross-lingual prompt-injection coverage: see
	// goldenHashDefaults note above.
	// 2026-05-21: rotated for ToolChainDetection.SensitivityLabels
	// (v2.6 lethal-trifecta detection). The new field participates in
	// policy semantics: operator-provided sensitivity overrides change
	// which tools classify into untrusted_source / sensitive_source /
	// external_sink, which changes which sequences emit the lethal-
	// trifecta verdict.
	// Re-bumped for the Databricks PAT pattern tightening from
	// `dapi[a-z0-9]{30,}` to `dapi[0-9a-f]{32,}` (defaults.go DLP set), which
	// closes a false-positive surface in random base64 image payloads while
	// still matching the documented 32-char hex Databricks token format.
	// Re-bumped for DLP false-positive sprint hardening: see
	// goldenHashDefaults note. The rich fixture inherits the default DLP
	// pattern and entropy-exclusion defaults, so the hash shifts in
	// lockstep.
	// Re-bumped for DLP false-positive hardening pass 2: see
	// goldenHashDefaults note above. The rich fixture inherits the default
	// DLP pattern set, so the hash shifts in lockstep.
	// Re-bumped again for the Supabase base64url checksum right-edge fix:
	// see goldenHashDefaults note above.
	// Re-bumped for the dns.host_overrides addition: see goldenHashDefaults
	// note. The rich fixture omits dns:, so the field is empty but still
	// part of the canonical view.
	// Re-bumped for file_sentry.action: same rationale as goldenHashDefaults.
	// Re-bumped for the request_policy section: same rationale as
	// goldenHashDefaults. The rich fixture omits request_policy, so the field
	// is empty but still part of the canonical view; the hash shifts in lockstep.
	// Re-bumped for request_policy fail-closed parse/opaque-operation actions:
	// see goldenHashDefaults note above.
	// Bumped for the request_policy.batch section (see goldenHashDefaults).
	// Bumped for fetch_proxy.monitoring.query_entropy_exclusions: see the
	// goldenHashDefaults note above.
	// Re-bumped for the file_sentry max_file_bytes field: see goldenHashDefaults note.
	// Re-bumped for A2A Agent Card signature verification fields: see
	// goldenHashDefaults note above.
	// Re-bumped for the Twilio + Mailgun DLP boundary tightening and again for
	// the secret-pattern expansion: see goldenHashDefaults note above. The rich
	// fixture inherits the default DLP pattern set, so the hash shifts in lockstep.
	// Re-bumped for response_scanning.size_exempt_domains: see the
	// goldenHashDefaults note above.
	// Re-bumped for git_protection.allowed_push_repos: see goldenHashDefaults
	// note above. The rich fixture omits the field, but the empty allowlist is
	// still part of the canonical policy view.
	// Re-bumped for DLP precision on the env-var-secret / credential-in-URL
	// patterns: see goldenHashDefaults note above.
	// Re-bumped for flight_recorder.require_receipts: see goldenHashDefaults
	// note above.
	// Re-bumped for "Credential Solicitation" direction-anchoring: see
	// goldenHashDefaults note above. The rich fixture inherits the default
	// response-scanning pattern set, so the hash shifts in lockstep.
	goldenHashRichConfig = "970f1850a72693cac6d95ee0f29e882aa433dbb7529cb555fb70ed7969baa18f"
)

// goldenRichYAML is the canonical fixture for goldenHashRichConfig. It
// exercises a representative policy-semantic cross-section: the API
// allowlist, SSRF internal CIDRs, trusted domains, fetch/forward/
// websocket/reverse proxy enforcement-relevant fields (NOT listen /
// upstream addresses, which are noise), DLP patterns including the
// include_defaults toggle, response scanning with exempt_domains, MCP
// input/tool scanning, MCP session binding, MCP tool policy with
// rules and patterns, kill switch with an API token, cross-request
// detection with entropy + fragment trackers, scan API auth + kinds,
// taint with protected paths + trust overrides, and mediation envelope
// with signed_components.
//
// Fixture 3 (invariant-under-allowlist-order) reverses the set-like
// slices that policySemanticView explicitly canonicalises today
// (api_allowlist, internal, trusted_domains) to verify sortedCopy
// still collapses the two onto the same hash. Fixture 4
// (invariant-under-ops-fields) swaps representative noise-only fields
// (listen addresses, logging, emit destinations, sentry, license,
// envelope key path, flight recorder dir, agents map) to verify those
// are zeroed by policySemanticView.
const goldenRichYAML = `version: 1
mode: balanced
enforce: true

api_allowlist:
  - api.anthropic.com
  - api.openai.com
  - api.example.internal

internal:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16

trusted_domains:
  - trusted.example.com
  - internal.example.com

fetch_proxy:
  listen: "127.0.0.1:8888"
  timeout_seconds: 30
  max_response_mb: 10
  user_agent: "Pipelock/test"
  monitoring:
    max_url_length: 2048
    entropy_threshold: 4.5
    subdomain_entropy_threshold: 4.0
    max_requests_per_minute: 60
    blocklist:
      - "*.pastebin.com"
      - "*.hastebin.com"

forward_proxy:
  enabled: true
  max_tunnel_seconds: 300
  idle_timeout_seconds: 120
  sni_verification: true

websocket_proxy:
  enabled: false

reverse_proxy:
  enabled: false

dlp:
  include_defaults: true
  patterns:
    - name: "Custom Secret"
      regex: "CUSTOM-[A-Z0-9]{16}"
      severity: "high"

response_scanning:
  enabled: true
  action: "warn"
  exempt_domains:
    - allowlisted.example.com

mcp_input_scanning:
  enabled: true
  action: "block"
  on_parse_error: "block"

mcp_tool_scanning:
  enabled: true
  action: "warn"
  detect_drift: true

mcp_session_binding:
  enabled: true
  unknown_tool_action: "block"
  no_baseline_action: "warn"

mcp_tool_policy:
  enabled: true
  action: "warn"
  rules:
    - name: "block-dangerous-writes"
      tool_pattern: "^write_.*$"
      arg_pattern: "^/etc/.*"
      action: "block"

kill_switch:
  enabled: true
  api_token: "test-token-XXXX"

metrics_listen: "127.0.0.1:19090"

cross_request_detection:
  enabled: true
  entropy_budget:
    enabled: true
    bits_per_window: 256
    window_minutes: 60
  fragment_reassembly:
    enabled: true
    max_buffer_bytes: 4096
    window_minutes: 5

scan_api:
  listen: "127.0.0.1:19091"
  auth:
    bearer_tokens:
      - "scan-api-token-1"
  kinds:
    url: true
    dlp: true
    prompt_injection: true
    tool_call: true
  rate_limit:
    requests_per_minute: 60
    burst: 10
  max_body_bytes: 65536
  timeouts:
    read: "2s"
    write: "2s"
    scan: "1s"

taint:
  enabled: true
  policy: "balanced"
  protected_paths:
    - "/etc/**"
    - "/root/**"
  elevated_paths:
    - "/home/**"
  trust_overrides:
    - scope: "action"
      action_match: "read"
      expires_at: 2030-01-01T00:00:00Z
      granted_by: "operator@example.com"
      reason: "routine telemetry read"

mediation_envelope:
  enabled: true
  sign: false
  signed_components:
    - "@method"
    - "@target-uri"
    - "@authority"

logging:
  format: "json"
  output: "stdout"
  include_allowed: false
  include_blocked: true
`

// goldenRichYAMLReversedSlices is goldenRichYAML with the set-like
// slices that policySemanticView currently canonicalises
// (api_allowlist, internal, trusted_domains) reversed.
// sortedCopy must collapse these onto the same hash as goldenRichYAML.
const goldenRichYAMLReversedSlices = `version: 1
mode: balanced
enforce: true

api_allowlist:
  - api.example.internal
  - api.openai.com
  - api.anthropic.com

internal:
  - 192.168.0.0/16
  - 172.16.0.0/12
  - 10.0.0.0/8

trusted_domains:
  - internal.example.com
  - trusted.example.com

fetch_proxy:
  listen: "127.0.0.1:8888"
  timeout_seconds: 30
  max_response_mb: 10
  user_agent: "Pipelock/test"
  monitoring:
    max_url_length: 2048
    entropy_threshold: 4.5
    subdomain_entropy_threshold: 4.0
    max_requests_per_minute: 60
    blocklist:
      - "*.pastebin.com"
      - "*.hastebin.com"

forward_proxy:
  enabled: true
  max_tunnel_seconds: 300
  idle_timeout_seconds: 120
  sni_verification: true

websocket_proxy:
  enabled: false

reverse_proxy:
  enabled: false

dlp:
  include_defaults: true
  patterns:
    - name: "Custom Secret"
      regex: "CUSTOM-[A-Z0-9]{16}"
      severity: "high"

response_scanning:
  enabled: true
  action: "warn"
  exempt_domains:
    - allowlisted.example.com

mcp_input_scanning:
  enabled: true
  action: "block"
  on_parse_error: "block"

mcp_tool_scanning:
  enabled: true
  action: "warn"
  detect_drift: true

mcp_session_binding:
  enabled: true
  unknown_tool_action: "block"
  no_baseline_action: "warn"

mcp_tool_policy:
  enabled: true
  action: "warn"
  rules:
    - name: "block-dangerous-writes"
      tool_pattern: "^write_.*$"
      arg_pattern: "^/etc/.*"
      action: "block"

kill_switch:
  enabled: true
  api_token: "test-token-XXXX"

metrics_listen: "127.0.0.1:19090"

cross_request_detection:
  enabled: true
  entropy_budget:
    enabled: true
    bits_per_window: 256
    window_minutes: 60
  fragment_reassembly:
    enabled: true
    max_buffer_bytes: 4096
    window_minutes: 5

scan_api:
  listen: "127.0.0.1:19091"
  auth:
    bearer_tokens:
      - "scan-api-token-1"
  kinds:
    url: true
    dlp: true
    prompt_injection: true
    tool_call: true
  rate_limit:
    requests_per_minute: 60
    burst: 10
  max_body_bytes: 65536
  timeouts:
    read: "2s"
    write: "2s"
    scan: "1s"

taint:
  enabled: true
  policy: "balanced"
  protected_paths:
    - "/etc/**"
    - "/root/**"
  elevated_paths:
    - "/home/**"
  trust_overrides:
    - scope: "action"
      action_match: "read"
      expires_at: 2030-01-01T00:00:00Z
      granted_by: "operator@example.com"
      reason: "routine telemetry read"

mediation_envelope:
  enabled: true
  sign: false
  signed_components:
    - "@method"
    - "@target-uri"
    - "@authority"

logging:
  format: "json"
  output: "stdout"
  include_allowed: false
  include_blocked: true
`

// goldenRichYAMLWithOpsFieldsChanged is goldenRichYAML with
// representative noise-only fields swapped. policySemanticView must
// zero these so the hash stays equal to goldenHashRichConfig:
//
//   - fetch_proxy.listen (different port)
//   - reverse_proxy.listen and reverse_proxy.upstream
//   - metrics_listen (different port)
//   - logging.output, logging.format, logging.file, logging.include_allowed
//   - emit.webhook.url and severity routing
//   - sentry.dsn, environment, and debug flag
//   - flight_recorder.dir (operational path)
//   - mediation_envelope.signing_key_path (different path)
//   - license_key (not in policy surface)
//   - agents map (resolved per-agent, not in the global view)
//
// If any of these flip the hash, policySemanticView is under-zeroing.
const goldenRichYAMLWithOpsFieldsChanged = `version: 1
mode: balanced
enforce: true

api_allowlist:
  - api.anthropic.com
  - api.openai.com
  - api.example.internal

internal:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16

trusted_domains:
  - trusted.example.com
  - internal.example.com

fetch_proxy:
  listen: "127.0.0.1:28888"
  timeout_seconds: 30
  max_response_mb: 10
  user_agent: "Pipelock/test"
  monitoring:
    max_url_length: 2048
    entropy_threshold: 4.5
    subdomain_entropy_threshold: 4.0
    max_requests_per_minute: 60
    blocklist:
      - "*.pastebin.com"
      - "*.hastebin.com"

forward_proxy:
  enabled: true
  max_tunnel_seconds: 300
  idle_timeout_seconds: 120
  sni_verification: true

websocket_proxy:
  enabled: false

reverse_proxy:
  enabled: false
  listen: "127.0.0.1:28990"
  upstream: "http://127.0.0.1:28991"

dlp:
  include_defaults: true
  patterns:
    - name: "Custom Secret"
      regex: "CUSTOM-[A-Z0-9]{16}"
      severity: "high"

response_scanning:
  enabled: true
  action: "warn"
  exempt_domains:
    - allowlisted.example.com

mcp_input_scanning:
  enabled: true
  action: "block"
  on_parse_error: "block"

mcp_tool_scanning:
  enabled: true
  action: "warn"
  detect_drift: true

mcp_session_binding:
  enabled: true
  unknown_tool_action: "block"
  no_baseline_action: "warn"

mcp_tool_policy:
  enabled: true
  action: "warn"
  rules:
    - name: "block-dangerous-writes"
      tool_pattern: "^write_.*$"
      arg_pattern: "^/etc/.*"
      action: "block"

kill_switch:
  enabled: true
  api_token: "test-token-XXXX"

metrics_listen: "127.0.0.1:39090"

cross_request_detection:
  enabled: true
  entropy_budget:
    enabled: true
    bits_per_window: 256
    window_minutes: 60
  fragment_reassembly:
    enabled: true
    max_buffer_bytes: 4096
    window_minutes: 5

scan_api:
  listen: "127.0.0.1:19091"
  auth:
    bearer_tokens:
      - "scan-api-token-1"
  kinds:
    url: true
    dlp: true
    prompt_injection: true
    tool_call: true
  rate_limit:
    requests_per_minute: 60
    burst: 10
  max_body_bytes: 65536
  timeouts:
    read: "2s"
    write: "2s"
    scan: "1s"

taint:
  enabled: true
  policy: "balanced"
  protected_paths:
    - "/etc/**"
    - "/root/**"
  elevated_paths:
    - "/home/**"
  trust_overrides:
    - scope: "action"
      action_match: "read"
      expires_at: 2030-01-01T00:00:00Z
      granted_by: "operator@example.com"
      reason: "routine telemetry read"

mediation_envelope:
  enabled: true
  sign: false
  signed_components:
    - "@method"
    - "@target-uri"
    - "@authority"
  signing_key_path: "/etc/pipelock/envelope.key"

logging:
  format: "text"
  output: "file"
  file: "/var/log/pipelock/test.log"
  include_allowed: true
  include_blocked: true

emit:
  webhook:
    url: "https://events.example.com/pipelock"
    min_severity: "critical"

sentry:
  dsn: "https://public@example.com/1"
  environment: "staging"
  debug: true

flight_recorder:
  enabled: false
  dir: "/var/lib/pipelock/fr"

license_key: "test-license-key-XXXX"

agents:
  reviewer:
    mode: "strict"
`

// loadGoldenConfig writes yamlSrc to a temp file, loads it through the
// full Load pipeline, and returns the resulting Config. Load already
// parses, applies defaults, validates, and warms the canonical hash
// cache before returning; these tests call computeCanonicalPolicyHash
// explicitly so they exercise the uncached value on that loaded
// snapshot. Failure here means the fixture itself is invalid, not a
// hash drift - treat it as a test-infra bug, not a production
// regression.
func loadGoldenConfig(t *testing.T, yamlSrc string) *Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "golden.yaml")
	if err := os.WriteFile(path, []byte(yamlSrc), 0o600); err != nil {
		t.Fatalf("write golden yaml: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load golden yaml: %v", err)
	}
	return cfg
}

// TestCanonicalPolicyHash_GoldenDefaults pins the canonical hash of
// the out-of-the-box Defaults() config. Any drift in this value after
// a refactor means Defaults() or a component of policySemanticView
// shifted. For the TD-2b mechanical split this MUST stay byte-stable.
func TestCanonicalPolicyHash_GoldenDefaults(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Defaults() must validate: %v", err)
	}
	got := cfg.computeCanonicalPolicyHash()
	if got != goldenHashDefaults {
		t.Errorf("Defaults() canonical hash drifted.\n  want %s\n  got  %s\n\nIf this is an intentional policy-semantics change, update goldenHashDefaults and document the bump in the PR body.", goldenHashDefaults, got)
	}
}

// TestCanonicalPolicyHash_GoldenRichConfig pins the hash for the rich
// YAML fixture. This is the hash any mechanical refactor of the
// config package MUST preserve.
func TestCanonicalPolicyHash_GoldenRichConfig(t *testing.T) {
	t.Parallel()
	cfg := loadGoldenConfig(t, goldenRichYAML)
	got := cfg.computeCanonicalPolicyHash()
	if got != goldenHashRichConfig {
		t.Errorf("rich-config canonical hash drifted.\n  want %s\n  got  %s\n\nIf this is an intentional policy-semantics change, update goldenHashRichConfig and document the bump in the PR body.", goldenHashRichConfig, got)
	}
}

// TestCanonicalPolicyHash_GoldenInvariantUnderAllowlistOrder verifies
// that reversing every set-like slice (api_allowlist, internal,
// trusted_domains) in the rich fixture produces the SAME hash. Proves
// sortedCopy canonicalisation inside policySemanticView is still
// running after the TD-2b split.
func TestCanonicalPolicyHash_GoldenInvariantUnderAllowlistOrder(t *testing.T) {
	t.Parallel()
	cfg := loadGoldenConfig(t, goldenRichYAMLReversedSlices)
	got := cfg.computeCanonicalPolicyHash()
	if got != goldenHashRichConfig {
		t.Errorf("allowlist-order invariance broken.\n  want %s (rich-config golden)\n  got  %s\n\nEither sortedCopy is not being invoked on one of api_allowlist/internal/trusted_domains, or the slice was re-classified as behavioral ordering.", goldenHashRichConfig, got)
	}
}

// TestCanonicalPolicyHash_GoldenInvariantUnderOpsFields verifies that
// swapping every "noise-only" field in the rich fixture produces the
// SAME hash. Proves policySemanticView is still zeroing operational
// plumbing (listen addresses, logging, license, envelope key path,
// flight recorder dir, agents map).
//
// If this test drifts, policySemanticView is under-zeroing - a noise
// field is leaking into ph, and every deployment that touches that
// field would emit receipts with a different hash despite having
// identical effective policy.
func TestCanonicalPolicyHash_GoldenInvariantUnderOpsFields(t *testing.T) {
	t.Parallel()
	cfg := loadGoldenConfig(t, goldenRichYAMLWithOpsFieldsChanged)
	got := cfg.computeCanonicalPolicyHash()
	if got != goldenHashRichConfig {
		t.Errorf("ops-field invariance broken.\n  want %s (rich-config golden)\n  got  %s\n\nA field in policySemanticView is not being zeroed. Check the field list in canonical.go:policySemanticView against the ops-field swap set in goldenRichYAMLWithOpsFieldsChanged.", goldenHashRichConfig, got)
	}
}
