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
// If you INTENTIONALLY change canonical-hash semantics — a new policy
// field added to policySemanticView, a set-like slice graduated to
// behavioral ordering, the default pattern corpus expanded — update
// the constant to match the new value and note the bump in the PR
// body. Do not silently regenerate: the whole point of this test is to
// make the drift visible in review.

const (
	// goldenHashDefaults pins CanonicalPolicyHash for a freshly
	// constructed Defaults() config, post-ApplyDefaults + Validate.
	// This is the "out of the box" hash a user gets from `pipelock
	// run` with no --config flag.
	// Bumped for the generic SSE streaming feature: Defaults() now
	// includes ResponseScanning.SSEStreaming with its enabled/action/
	// max_event_bytes defaults. New policy knob → ph must shift.
	goldenHashDefaults = "bbc0e8d8ee618bedfd61b19f74af01b3786b12c181fd7abb1b1d262a0f060477"

	// goldenHashRichConfig pins the hash for goldenRichYAML loaded via
	// config.Load, post-ApplyDefaults + Validate. Covers a broad,
	// representative policy-semantic fixture with emphasis on the
	// sections most likely to drift during TD-2b.
	// Bumped for the generic SSE streaming feature: ResponseScanning now
	// carries an SSEStreaming sub-struct that policySemanticView hashes
	// through its shallow copy. Adding a new policy knob must bump ph
	// so verifiers detect the semantics change.
	goldenHashRichConfig = "5a7f7b603b2fcba853d333c8c7583b37fbca548260e8d963cbb20438e1d54544"
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
// hash drift — treat it as a test-infra bug, not a production
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
// If this test drifts, policySemanticView is under-zeroing — a noise
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
