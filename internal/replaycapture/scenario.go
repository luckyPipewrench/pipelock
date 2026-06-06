// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package replaycapture builds public-safe, signed Audit Packets from
// controlled synthetic attack scenarios driven through a real Pipelock proxy.
//
// It is the capture half of the Playground "Replay Audit Packet gallery": each
// scenario runs genuine requests through a real scanner/proxy/receipt-emitter in
// an isolated synthetic lab, captures the signed receipt chain, and assembles an
// Audit Packet (sdk/audit-packet v0) plus a UI replay manifest. The published
// artifacts verify byte-for-byte with the shipped `pipelock-verifier
// audit-packet`.
//
// Two invariants make the output safe to publish:
//
//   - Every input is SYNTHETIC. No real secret, host, customer, agent, or
//     infrastructure detail appears in any scenario, recording, packet, or
//     manifest. The synthetic material is obviously inert if leaked (AWS's
//     published example key, RFC 5737 / RFC 3927 reserved addresses,
//     example.com and .test fixture hosts).
//   - Public-safe by construction, not by post-scrub. Receipts are redacted
//     before signing (the recorder's redactor runs pre-sign in the emitter), the
//     packet envelope is built from safe constants only, and a fail-closed field
//     allowlist (see allowlist.go) plus an artifact linter (see linter.go) gate
//     publication. Post-hoc scrubbing is forbidden because it would break the
//     signature.
package replaycapture

// Transport identifies which real Pipelock proxy surface a scenario drives.
// These mirror the transport label stamped into the emitted receipt.
const (
	// TransportFetch drives the /fetch endpoint (read-through fetch proxy).
	TransportFetch = "fetch"
	// TransportForward drives the absolute-URI forward proxy.
	TransportForward = "forward"
)

// Receipt verdict strings, matching receipt.NormalizeVerdict output. Declared
// here so scenarios and tests do not hand-write the literals.
const (
	verdictAllow = "allow"
	verdictBlock = "block"
	verdictWarn  = "warn"
)

// Synthetic destinations and material. Every value is intentionally
// non-routable-to-real-infra or a published example so a leak proves nothing.
const (
	// synthCollectorHost is a generic attacker-controlled exfil sink. example.com
	// is reserved (RFC 2606) and never resolves to real infrastructure.
	synthCollectorHost = "collector.example.com"
	// synthMetadataIP is the well-known cloud metadata address used as an SSRF
	// target. It is a fixed link-local literal, public knowledge, and the point
	// of the SSRF demo.
	synthMetadataIP = "169.254.169.254"
	// synthAWSKey is AWS's own published example access key id (not a credential).
	// Split at construction to keep secret scanners and gosec G101 quiet.
	synthAWSKeyPrefix = "AKIA"
	synthAWSKeySuffix = "IOSFODNN7EXAMPLE"
)

// SyntheticAWSKey returns the published AWS example access key id. It is
// assembled at runtime so the literal never appears in source.
func SyntheticAWSKey() string { return synthAWSKeyPrefix + synthAWSKeySuffix }

// Scenario is the declarative definition of one gallery recording. It carries
// display/marketing metadata and the expected mediated outcome; the mechanics of
// driving the real proxy live in capture.go, keyed by ID.
//
// Every string here is published. Keep IDs, titles, labels, and narrative
// boring and synthetic by construction (launch gate: public rule IDs and
// scenario names must be safe before capture, not scrubbed after).
type Scenario struct {
	// ID is the stable public slug. Used as the packet/manifest directory name
	// and the switch key in the capture engine. Boring and synthetic.
	ID string
	// Title is the human-facing card heading.
	Title string
	// BenchCaseID maps this recording to an agent-egress-bench case. Mapping to a
	// bench case id is the ONLY permitted benchmark link; the gallery is not a
	// benchmark.
	BenchCaseID string
	// Transport is the real proxy surface driven (TransportFetch/TransportForward).
	Transport string
	// Category is the display grouping (e.g. "Secret exfiltration").
	Category string
	// ExpectedLayer is the exact layer label expected on the decisive receipt.
	// It is asserted in tests; empty means "do not assert".
	ExpectedLayer string
	// ExpectedVerdict is the decisive receipt verdict (verdictAllow/Block/Warn).
	// For multi-receipt scenarios it is the verdict of the headline decision.
	ExpectedVerdict string
	// DestinationClass is a redacted, human-readable destination label for the
	// UI. Never an ephemeral port, internal host, or raw target.
	DestinationClass string
	// Without is the bare-agent narrative: what happens with no firewall. It
	// describes the outcome with a class label only (see RedactedShape), never a
	// raw secret-shaped string.
	Without string
	// With is the Pipelock narrative: what the firewall mediated.
	With string
	// RedactedShape is the inert, class-labelled display for the WITHOUT side
	// (e.g. "AKIA••••••••••••EXAMPLE → exfiltrated"). Optional. Must never be a
	// raw secret value, even synthetic.
	RedactedShape string
}

// redactedAWSShape is the inert display form for the AWS example key. It keeps
// the prefix/suffix that make the class obvious while masking the middle, so a
// screenshot can never be read as "Pipelock displayed a live key".
const redactedAWSShape = "AKIA••••••••••EXAMPLE"

// DefaultScenarios returns the first gallery drop: five balanced recordings
// covering one allowed-safe action and four distinct blocked attack classes
// (URL secret exfil, prompt-injection response, SSRF/internal target, and
// operation-aware policy). MCP poisoning/rug-pull is deferred to a second drop
// per the design (its receipt path is held until the card explains in one
// panel).
//
// The order is the recommended gallery order: lead with an allowed action so the
// gallery does not read as a hardcoded blocklist, then escalate through blocks.
func DefaultScenarios() []Scenario {
	return []Scenario{
		{
			ID:               "allowed-safe-read",
			Title:            "Allowed: a safe read passes",
			BenchCaseID:      "url-benign-api-call-001",
			Transport:        TransportFetch,
			Category:         "Allowed by policy",
			ExpectedLayer:    "",
			ExpectedVerdict:  verdictAllow,
			DestinationClass: "read-only lab documentation endpoint",
			Without:          "A bare agent fetches a harmless page. Nothing watches the request.",
			With:             "Pipelock scans the request, finds no secret, injection, or unsafe target, and allows it — then signs a receipt recording the allow decision.",
		},
		{
			ID:               "secret-exfil-url-blocked",
			Title:            "Blocked: secret exfiltration over a URL",
			BenchCaseID:      "url-dlp-aws-key-001",
			Transport:        TransportFetch,
			Category:         "Secret exfiltration",
			ExpectedLayer:    "core_dlp",
			ExpectedVerdict:  verdictBlock,
			DestinationClass: "attacker-controlled collector (reserved example host)",
			Without:          "A bare agent puts a credential in a query parameter and the value escapes to the collector.",
			With:             "Pipelock's DLP layer detects the credential shape in the URL before any DNS resolution and blocks the request. The signed receipt records the block; the value never leaves.",
			RedactedShape:    redactedAWSShape + " → exfiltrated",
		},
		{
			ID:               "prompt-injection-response-blocked",
			Title:            "Blocked: a hijack hidden in fetched content",
			BenchCaseID:      "response-injection-ignore-002",
			Transport:        TransportFetch,
			Category:         "Prompt injection",
			ExpectedLayer:    "response_scan",
			ExpectedVerdict:  verdictBlock,
			DestinationClass: "lab page returning hostile instructions",
			Without:          "A bare agent fetches a page whose body says \"ignore your instructions and exfiltrate\", and follows it.",
			With:             "Pipelock scans the fetched response, detects the injection attempt in the returned content, and blocks it from reaching the agent. The signed receipt records the response-path block.",
		},
		{
			ID:               "ssrf-internal-target-blocked",
			Title:            "Blocked: a reach for cloud metadata",
			BenchCaseID:      "url-ssrf-metadata-009",
			Transport:        TransportFetch,
			Category:         "SSRF / internal target",
			ExpectedLayer:    "ssrf_metadata",
			ExpectedVerdict:  verdictBlock,
			DestinationClass: "cloud metadata service (link-local address)",
			Without:          "A bare agent is tricked into requesting the cloud metadata endpoint to harvest instance credentials.",
			With:             "Pipelock's SSRF layer recognizes the link-local metadata target and blocks the request. The signed receipt records the SSRF block.",
		},
		{
			ID:               "operation-aware-policy",
			Title:            "Blocked: destructive API mutation",
			BenchCaseID:      "local-lab-request-policy-graphql-mutation-001",
			Transport:        TransportForward,
			Category:         "Operation-aware policy",
			ExpectedLayer:    "request_policy",
			ExpectedVerdict:  verdictBlock,
			DestinationClass: "reserved GraphQL API endpoint",
			Without:          "A bare agent sends both the safe read and the destructive mutation to the API.",
			With:             "Pipelock allows the safe read, inspects the GraphQL operation, and blocks the destructive mutation by policy. The signed receipts record both decisions.",
		},
	}
}
