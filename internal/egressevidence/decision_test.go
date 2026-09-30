// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package egressevidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	decisionTestActionID   = "01990000-0000-7000-8000-000000000001"
	decisionTestDecisionID = "01990000-0000-7000-8000-000000000002"
	decisionTestOtherID    = "01990000-0000-7000-8000-000000000003"
	decisionTestSiteID     = "proxy.forward.body.original"
	decisionTestHost       = "api.vendor.example"
)

func decisionFixture() Decision {
	return Decision{
		Version: ContractVersion, ActionID: decisionTestActionID,
		DecisionID: decisionTestDecisionID, SiteID: decisionTestSiteID,
		Plane: PlaneProxy, Transport: TransportForward, Location: LocationBody,
		View: ViewOriginal, Boundary: BoundaryUpstreamRequest, Phase: PhaseIntent,
		DestinationKind: DestinationNetwork, DestinationRef: decisionTestHost,
		PatternClass: PatternConfigured, RuleID: "configured.sample_rule",
		FindingDisposition: FindingObserve, PlannedByteForm: ByteFormOriginal,
		Authorization:     Authorization{Kind: AuthorizationNone},
		PersistencePolicy: PersistenceRequired,
	}
}

func decisionOutcomeFixture() Decision {
	d := decisionFixture()
	d.Phase = PhaseOutcome
	d.Outcome = &Outcome{Release: ReleaseComplete, ByteForm: ByteFormOriginal}
	return d
}

func marshalDecisionFixture(t *testing.T, d Decision) []byte {
	t.Helper()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return raw
}

func TestDecisionValidFindingHandling(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		disposition FindingDisposition
		form        ByteForm
		authority   Authorization
	}{
		{"block", FindingBlock, ByteFormNone, Authorization{Kind: AuthorizationNone}},
		{"redact", FindingRedact, ByteFormTransformed, Authorization{Kind: AuthorizationNone}},
		{"redact_without_release", FindingRedact, ByteFormNone, Authorization{Kind: AuthorizationNone}},
		{"observe", FindingObserve, ByteFormOriginal, Authorization{Kind: AuthorizationNone}},
		{"authorize", FindingAuthorize, ByteFormOriginal, Authorization{Kind: AuthorizationPermit, Ref: "authorization:sample", Origin: PolicyOriginOperator}},
		{"exempt", FindingExempt, ByteFormOriginal, Authorization{Kind: AuthorizationExemption, Ref: "exemption:sample", Origin: PolicyOriginBuiltin}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := decisionFixture()
			d.FindingDisposition, d.PlannedByteForm, d.Authorization = tc.disposition, tc.form, tc.authority
			if err := d.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			got, err := ParseDecision(marshalDecisionFixture(t, d))
			if err != nil || got != d {
				t.Fatalf("round trip: got %#v, err %v", got, err)
			}
		})
	}
}

func TestDecisionValidDomains(t *testing.T) {
	t.Parallel()
	for _, transport := range []Transport{
		TransportFetch, TransportForward, TransportConnect,
		TransportIntercept, TransportReverse, TransportWebSocket, TransportMCPStdio,
		TransportMCPHTTPUpstream, TransportMCPHTTPListener, TransportMCPWS,
	} {
		d := decisionFixture()
		d.Transport = transport
		if transport == TransportConnect {
			d.Boundary = BoundaryTunnel
		}
		if transport == TransportMCPStdio {
			d.DestinationKind, d.DestinationRef = DestinationLocalProcess, "mcp.sample_upstream"
		}
		if err := d.Validate(); err != nil {
			t.Errorf("transport %s: %v", transport, err)
		}
	}
	for _, location := range []Location{LocationURL, LocationHeader, LocationBody, LocationToolArguments, LocationEnvelope, LocationFrame} {
		d := decisionFixture()
		d.Location = location
		if err := d.Validate(); err != nil {
			t.Errorf("location %s: %v", location, err)
		}
	}
	for _, view := range []View{ViewOriginal, ViewNormalized, ViewPostTransform, ViewReassembled, ViewAuthorization} {
		d := decisionFixture()
		d.View = view
		if err := d.Validate(); err != nil {
			t.Errorf("view %s: %v", view, err)
		}
	}
	for _, boundary := range []Boundary{BoundaryUpstreamRequest, BoundaryUpstreamFrame, BoundaryTunnel, BoundaryToolDispatch} {
		d := decisionFixture()
		d.Boundary = boundary
		switch boundary {
		case BoundaryUpstreamFrame:
			d.Transport = TransportWebSocket
		case BoundaryTunnel:
			d.Transport = TransportConnect
		case BoundaryToolDispatch:
			d.Transport = TransportMCPStdio
			d.DestinationKind, d.DestinationRef = DestinationLocalProcess, "mcp.sample_upstream"
		}
		if err := d.Validate(); err != nil {
			t.Errorf("boundary %s: %v", boundary, err)
		}
	}
	for _, patternClass := range []PatternClass{PatternCoreFloor, PatternConfigured} {
		d := decisionFixture()
		d.PatternClass = patternClass
		d.FindingDisposition, d.PlannedByteForm = FindingBlock, ByteFormNone
		if err := d.Validate(); err != nil {
			t.Errorf("pattern class %s: %v", patternClass, err)
		}
	}
	for _, policy := range []PersistencePolicy{PersistenceRequired, PersistenceBestEffort} {
		d := decisionFixture()
		d.PersistencePolicy = policy
		if err := d.Validate(); err != nil {
			t.Errorf("persistence policy %s: %v", policy, err)
		}
	}
}

// The expected strings are grounded in producer assignments, independently of
// the candidate enum. This checks vocabulary, not site inventory or coverage.
func TestDecisionProducerTransportVocabulary(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		transport Transport
		boundary  Boundary
		local     bool
	}{
		// internal/proxy/{proxy,forward,intercept,reverse,websocket}.go.
		{"fetch", TransportFetch, BoundaryUpstreamRequest, false},
		{"forward", TransportForward, BoundaryUpstreamRequest, false},
		{"connect", TransportConnect, BoundaryTunnel, false},
		{"intercept", TransportIntercept, BoundaryUpstreamRequest, false},
		{"reverse", TransportReverse, BoundaryUpstreamRequest, false},
		{"websocket", TransportWebSocket, BoundaryUpstreamFrame, false},
		// internal/mcp/{proxy,mcp_http_forward,proxy_ws,mcp_http_reverse}.go.
		{"mcp_stdio", TransportMCPStdio, BoundaryToolDispatch, true},
		{"mcp_http_upstream", TransportMCPHTTPUpstream, BoundaryToolDispatch, false},
		{"mcp_ws", TransportMCPWS, BoundaryToolDispatch, false},
		{"mcp_http_listener", TransportMCPHTTPListener, BoundaryToolDispatch, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.transport) != tc.name {
				t.Fatalf("candidate transport %q differs from producer %q", tc.transport, tc.name)
			}
			d := decisionFixture()
			d.Transport, d.Boundary = Transport(tc.name), tc.boundary
			if tc.local {
				d.DestinationKind, d.DestinationRef = DestinationLocalProcess, "mcp.sample_upstream"
			}
			if _, err := ParseDecision(marshalDecisionFixture(t, d)); err != nil {
				t.Fatalf("producer transport rejected: %v", err)
			}
		})
	}
	// These are a legacy direct-scan fallback and an invented carrier label,
	// respectively; neither names one of the actual proxy producer modes.
	for _, name := range []Transport{"mcp_http", "mcp_websocket"} {
		d := decisionFixture()
		d.Transport = name
		if _, err := ParseDecision(marshalDecisionFixture(t, d)); err == nil {
			t.Fatalf("non-producer transport accepted: %q", name)
		}
	}
}

func TestDecisionDestinationCarrierMatrix(t *testing.T) {
	t.Parallel()
	for _, transport := range []Transport{
		TransportFetch, TransportForward, TransportConnect,
		TransportIntercept, TransportReverse, TransportWebSocket, TransportMCPStdio,
		TransportMCPHTTPUpstream, TransportMCPHTTPListener, TransportMCPWS,
	} {
		for _, kind := range []DestinationKind{DestinationNetwork, DestinationLocalProcess} {
			d := decisionFixture()
			d.Transport, d.DestinationKind = transport, kind
			if transport == TransportConnect {
				d.Boundary = BoundaryTunnel
			}
			if kind == DestinationLocalProcess {
				d.DestinationRef = "mcp.sample_upstream"
			}
			wantValid := (transport == TransportMCPStdio) == (kind == DestinationLocalProcess)
			if err := d.Validate(); (err == nil) != wantValid {
				t.Errorf("transport=%s kind=%s valid=%t: %v", transport, kind, wantValid, err)
			}
			if _, err := ParseDecision(marshalDecisionFixture(t, d)); (err == nil) != wantValid {
				t.Errorf("parse transport=%s kind=%s valid=%t: %v", transport, kind, wantValid, err)
			}
		}
	}
}

// The MCP input path can remove a core-only finding by redaction followed by a
// clean rescan. These facts represent that selected handling and transformed
// release; parsing alone does not prove that the required rescan occurred.
func TestDecisionCoreFloorRedactionWithTransformedRelease(t *testing.T) {
	t.Parallel()
	intent := decisionFixture()
	intent.PatternClass, intent.FindingDisposition = PatternCoreFloor, FindingRedact
	intent.PlannedByteForm = ByteFormTransformed
	outcome := intent
	outcome.Phase = PhaseOutcome
	outcome.Outcome = &Outcome{Release: ReleaseComplete, ByteForm: ByteFormTransformed}
	parsed, err := ParseDecision(marshalDecisionFixture(t, outcome))
	if err != nil {
		t.Fatalf("discarded core redaction evidence: %v", err)
	}
	if err := parsed.ValidateOutcomeOf(intent); err != nil {
		t.Fatalf("core redaction outcome pairing: %v", err)
	}
	if parsed.FindingDisposition != FindingRedact || parsed.Outcome.ByteForm != ByteFormTransformed {
		t.Fatal("parsing changed the redaction or transformed release facts")
	}
}

// MCP restores original findings as observe evidence after successful redaction
// and a clean rescan. Observing the pre-transform finding is not evidence that
// the matched original bytes were forwarded, nor a scalar policy violation.
func TestDecisionPreTransformObserveEvidenceIsRetained(t *testing.T) {
	t.Parallel()
	intent := decisionFixture()
	intent.PatternClass, intent.FindingDisposition = PatternCoreFloor, FindingObserve
	intent.View, intent.PlannedByteForm = ViewOriginal, ByteFormTransformed
	outcome := intent
	outcome.Phase = PhaseOutcome
	outcome.Outcome = &Outcome{Release: ReleaseComplete, ByteForm: ByteFormTransformed}
	parsed, err := ParseDecision(marshalDecisionFixture(t, outcome))
	if err != nil {
		t.Fatalf("discarded retained pre-transform evidence: %v", err)
	}
	if err := parsed.ValidateOutcomeOf(intent); err != nil {
		t.Fatalf("retained evidence outcome pairing: %v", err)
	}
	if parsed.View != ViewOriginal || parsed.PatternClass != PatternCoreFloor ||
		parsed.FindingDisposition != FindingObserve || parsed.Outcome.ByteForm != ByteFormTransformed {
		t.Fatal("parsing conflated the finding view with the released byte form")
	}
}

func TestDecisionNamedPolicyOrigins(t *testing.T) {
	t.Parallel()
	for _, origin := range []PolicyOrigin{PolicyOriginBuiltin, PolicyOriginOperator} {
		for _, kind := range []AuthorizationKind{AuthorizationPermit, AuthorizationExemption} {
			d := decisionFixture()
			d.Authorization = Authorization{Kind: kind, Ref: "named.sample_policy", Origin: origin}
			d.FindingDisposition = FindingAuthorize
			if kind == AuthorizationExemption {
				d.FindingDisposition = FindingExempt
			}
			if _, err := ParseDecision(marshalDecisionFixture(t, d)); err != nil {
				t.Fatalf("kind=%s origin=%s: %v", kind, origin, err)
			}
		}
	}
	// Compiled credential audiences can legitimately permit a core credential
	// at its intended destination. This benign fixture records the named basis;
	// the parser does not authenticate it or widen the configured scanner floor.
	d := decisionFixture()
	d.PatternClass, d.View = PatternCoreFloor, ViewAuthorization
	d.FindingDisposition = FindingAuthorize
	d.Authorization = Authorization{Kind: AuthorizationPermit, Ref: "builtin.credential_audience.sample", Origin: PolicyOriginBuiltin}
	if _, err := ParseDecision(marshalDecisionFixture(t, d)); err != nil {
		t.Fatalf("discarded named built-in core authorization: %v", err)
	}
}

func TestDecisionRewriteFallbackFacts(t *testing.T) {
	t.Parallel()
	for _, reason := range []RewriteFallbackReason{
		RewriteUnparseableBody, RewriteNoSafeRawSpan,
		RewriteUnsupportedEncoding, RewriteUnsupportedShape, RewriteOpaqueArguments,
	} {
		for _, origin := range []PolicyOrigin{PolicyOriginBuiltin, PolicyOriginOperator} {
			intent := decisionFixture()
			intent.RewriteFallback = &RewriteFallback{Reason: reason, PolicyRef: "fallback.sample", PolicyOrigin: origin}
			outcome := intent
			outcome.Phase = PhaseOutcome
			outcome.Outcome = &Outcome{Release: ReleaseComplete, ByteForm: ByteFormOriginal}
			parsed, err := ParseDecision(marshalDecisionFixture(t, outcome))
			if err != nil {
				t.Fatalf("parse fallback: %v", err)
			}
			if parsed.RewriteFallback == intent.RewriteFallback {
				t.Fatal("round trip unexpectedly retained pointer identity")
			}
			if err := parsed.ValidateOutcomeOf(intent); err != nil {
				t.Fatalf("fallback value equality: %v", err)
			}
		}
	}
	// A rewrite failure and a named fallback policy may still result in a block.
	// The metadata does not grant permission to send the residual core finding.
	blocked := decisionFixture()
	blocked.PatternClass, blocked.FindingDisposition, blocked.PlannedByteForm = PatternCoreFloor, FindingBlock, ByteFormNone
	blocked.RewriteFallback = &RewriteFallback{Reason: RewriteUnparseableBody, PolicyRef: "builtin.block_residual", PolicyOrigin: PolicyOriginBuiltin}
	if _, err := ParseDecision(marshalDecisionFixture(t, blocked)); err != nil {
		t.Fatalf("blocked fallback: %v", err)
	}
}

func TestDecisionInvalidPolicyReferences(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(*Decision)
	}{
		{"authority_origin_missing", func(d *Decision) {
			d.FindingDisposition = FindingAuthorize
			d.Authorization = Authorization{Kind: AuthorizationPermit, Ref: "named.sample"}
		}},
		{"authority_origin_invalid", func(d *Decision) {
			d.FindingDisposition = FindingAuthorize
			d.Authorization = Authorization{Kind: AuthorizationPermit, Ref: "named.sample", Origin: "unknown"}
		}},
		{"no_authority_with_origin", func(d *Decision) { d.Authorization.Origin = PolicyOriginBuiltin }},
		{"fallback_reason_missing", func(d *Decision) {
			d.RewriteFallback = &RewriteFallback{PolicyRef: "fallback.sample", PolicyOrigin: PolicyOriginOperator}
		}},
		{"fallback_reason_invalid", func(d *Decision) {
			d.RewriteFallback = &RewriteFallback{Reason: "unknown", PolicyRef: "fallback.sample", PolicyOrigin: PolicyOriginOperator}
		}},
		{"fallback_ref_missing", func(d *Decision) {
			d.RewriteFallback = &RewriteFallback{Reason: RewriteNoSafeRawSpan, PolicyOrigin: PolicyOriginOperator}
		}},
		{"fallback_ref_invalid", func(d *Decision) {
			d.RewriteFallback = &RewriteFallback{Reason: RewriteNoSafeRawSpan, PolicyRef: "sample policy", PolicyOrigin: PolicyOriginOperator}
		}},
		{"fallback_ref_too_long", func(d *Decision) {
			d.RewriteFallback = &RewriteFallback{Reason: RewriteNoSafeRawSpan, PolicyRef: strings.Repeat("a", 129), PolicyOrigin: PolicyOriginOperator}
		}},
		{"fallback_origin_missing", func(d *Decision) {
			d.RewriteFallback = &RewriteFallback{Reason: RewriteNoSafeRawSpan, PolicyRef: "fallback.sample"}
		}},
		{"fallback_origin_invalid", func(d *Decision) {
			d.RewriteFallback = &RewriteFallback{Reason: RewriteNoSafeRawSpan, PolicyRef: "fallback.sample", PolicyOrigin: "unknown"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := decisionFixture()
			tc.mutate(&d)
			if err := d.Validate(); err == nil {
				t.Fatal("validated malformed policy facts")
			}
			if _, err := ParseDecision(marshalDecisionFixture(t, d)); err == nil {
				t.Fatal("parsed malformed policy facts")
			}
		})
	}
}

func TestDecisionPairingPinsPolicyFacts(t *testing.T) {
	t.Parallel()
	intent := decisionFixture()
	intent.FindingDisposition = FindingAuthorize
	intent.Authorization = Authorization{Kind: AuthorizationPermit, Ref: "named.sample", Origin: PolicyOriginOperator}
	intent.RewriteFallback = &RewriteFallback{Reason: RewriteNoSafeRawSpan, PolicyRef: "fallback.sample", PolicyOrigin: PolicyOriginOperator}
	outcome := intent
	outcome.Phase = PhaseOutcome
	outcome.Outcome = &Outcome{Release: ReleaseComplete, ByteForm: ByteFormOriginal}
	for _, tc := range []struct {
		name   string
		mutate func(*Decision)
	}{
		{"authorization_ref", func(d *Decision) { d.Authorization.Ref = "named.other" }},
		{"authorization_origin", func(d *Decision) { d.Authorization.Origin = PolicyOriginBuiltin }},
		{"fallback_reason", func(d *Decision) { d.RewriteFallback.Reason = RewriteUnsupportedEncoding }},
		{"fallback_ref", func(d *Decision) { d.RewriteFallback.PolicyRef = "fallback.other" }},
		{"fallback_origin", func(d *Decision) { d.RewriteFallback.PolicyOrigin = PolicyOriginBuiltin }},
		{"fallback_removed", func(d *Decision) { d.RewriteFallback = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := outcome
			fallbackCopy := *outcome.RewriteFallback
			changed.RewriteFallback = &fallbackCopy
			tc.mutate(&changed)
			if err := changed.Validate(); err != nil {
				t.Fatalf("expected structurally valid changed facts: %v", err)
			}
			if err := changed.ValidateOutcomeOf(intent); err == nil {
				t.Fatal("pairing accepted changed policy facts")
			}
		})
	}
	withoutFallback := intent
	withoutFallback.RewriteFallback = nil
	if err := outcome.ValidateOutcomeOf(withoutFallback); err == nil {
		t.Fatal("pairing accepted newly added fallback")
	}
}

// Inputs are documentation-range addresses, inert DNS references and invalid
// numeric strings. This tests string identity only; nothing is resolved,
// dialed, or used to exercise an enforcement path.
func TestDecisionCanonicalDestinationIdentity(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		host  string
		valid bool
	}{
		{decisionTestHost, true},
		{"123.api.vendor.example", true},
		{"0x.api.vendor.example", true},
		{"api.vendor.0xnothex", true},
		{"192.0.2.1", true},
		{"2001:db8::1", true},
		{"0xc0000201", false},
		{"3221225985", false},
		{"0300.0.2.1", false},
		{"192.513", false},
		{"192.0.513", false},
		{"::ffff:192.0.2.1", false},
		{"2001:0db8:0000:0000:0000:0000:0000:0001", false},
		{"2001:db8::1%example", false},
		{"[2001:db8::1]", false},
		{"192.0.2.1.", false},
		{" 192.0.2.1", false},
		{"192.0.2.999", false},
		{"999.0.2.1", false},
		{"192.0.2.1.1", false},
		{"192.0.2.09", false},
		{"4294967296", false},
		{"0x100000000", false},
		{"0x", false},
		{"api.vendor.123", false},
		{"api.vendor.0x", false},
		{"api.vendor.0xff", false},
	} {
		d := decisionFixture()
		d.DestinationRef = tc.host
		if err := d.Validate(); (err == nil) != tc.valid {
			t.Errorf("destination %q valid=%t: %v", tc.host, tc.valid, err)
		}
	}
}

func TestParseDecisionStrictPolicyObjects(t *testing.T) {
	t.Parallel()
	d := decisionFixture()
	d.RewriteFallback = &RewriteFallback{Reason: RewriteNoSafeRawSpan, PolicyRef: "fallback.sample", PolicyOrigin: PolicyOriginOperator}
	raw := string(marshalDecisionFixture(t, d))
	for name, input := range map[string]string{
		"none_explicit_empty_ref":    strings.Replace(raw, `"kind":"none"`, `"kind":"none","ref":""`, 1),
		"none_explicit_empty_origin": strings.Replace(raw, `"kind":"none"`, `"kind":"none","origin":""`, 1),
		"none_null_origin":           strings.Replace(raw, `"kind":"none"`, `"kind":"none","origin":null`, 1),
		"authority_kind_wrong_type":  strings.Replace(raw, `"kind":"none"`, `"kind":1`, 1),
		"authority_origin_alias":     strings.Replace(raw, `"kind":"none"`, `"kind":"none","Origin":"builtin"`, 1),
		"fallback_missing_reason":    strings.Replace(raw, `"reason":"no_safe_raw_span",`, ``, 1),
		"fallback_missing_ref":       strings.Replace(raw, `"policy_ref":"fallback.sample",`, ``, 1),
		"fallback_missing_origin":    strings.Replace(raw, `,"policy_origin":"operator"`, ``, 1),
		"fallback_null_reason":       strings.Replace(raw, `"reason":"no_safe_raw_span"`, `"reason":null`, 1),
		"fallback_null_ref":          strings.Replace(raw, `"policy_ref":"fallback.sample"`, `"policy_ref":null`, 1),
		"fallback_null_origin":       strings.Replace(raw, `"policy_origin":"operator"`, `"policy_origin":null`, 1),
		"fallback_duplicate":         strings.Replace(raw, `"reason":"no_safe_raw_span"`, `"reason":"no_safe_raw_span","reason":"no_safe_raw_span"`, 1),
		"fallback_unknown":           strings.Replace(raw, `"reason":"no_safe_raw_span"`, `"reason":"no_safe_raw_span","fsync_success":true`, 1),
		"fallback_case_alias":        strings.Replace(raw, `"policy_ref":"fallback.sample"`, `"Policy_ref":"fallback.sample"`, 1),
		"fallback_null_object":       strings.Replace(raw, `{"reason":"no_safe_raw_span","policy_ref":"fallback.sample","policy_origin":"operator"}`, `null`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDecision([]byte(input)); err == nil {
				t.Fatal("parsed malformed policy object")
			}
		})
	}
}

func TestDecisionInvalidFields(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(*Decision)
	}{
		{"version_zero", func(d *Decision) { d.Version = 0 }},
		{"version_unknown", func(d *Decision) { d.Version = 2 }},
		{"action_id_missing", func(d *Decision) { d.ActionID = "" }},
		{"action_id_invalid", func(d *Decision) { d.ActionID = "action" }},
		{"decision_id_invalid", func(d *Decision) { d.DecisionID = "decision" }},
		{"aliased_ids", func(d *Decision) { d.DecisionID = d.ActionID }},
		{"noncanonical_id", func(d *Decision) { d.ActionID = "0199000A-0000-7000-8000-000000000001" }},
		{"site_missing", func(d *Decision) { d.SiteID = "" }},
		{"site_invalid", func(d *Decision) { d.SiteID = "site with spaces" }},
		{"site_too_long", func(d *Decision) { d.SiteID = SiteID(strings.Repeat("a", 129)) }},
		{"plane_unknown", func(d *Decision) { d.Plane = "future" }},
		{"hook_not_in_initial_contract", func(d *Decision) { d.Plane, d.Transport, d.Boundary = PlaneHook, TransportHook, BoundaryHookDecision }},
		{"plane_transport_mismatch", func(d *Decision) { d.Transport = TransportHook }},
		{"plane_boundary_mismatch", func(d *Decision) { d.Boundary = BoundaryHookDecision }},
		{"transport_unknown", func(d *Decision) { d.Transport = "future" }},
		{"location_unknown", func(d *Decision) { d.Location = "future" }},
		{"view_unknown", func(d *Decision) { d.View = "future" }},
		{"boundary_unknown", func(d *Decision) { d.Boundary = "future" }},
		{"rule_missing", func(d *Decision) { d.RuleID = "" }},
		{"rule_content", func(d *Decision) { d.RuleID = "sample rule value" }},
		{"rule_too_long", func(d *Decision) { d.RuleID = strings.Repeat("a", 129) }},
		{"pattern_class_unknown", func(d *Decision) { d.PatternClass = "future" }},
		{"destination_kind_unknown", func(d *Decision) { d.DestinationKind = "future" }},
		{"destination_missing", func(d *Decision) { d.DestinationRef = "" }},
		{"destination_url", func(d *Decision) { d.DestinationRef = "https://api.vendor.example" }},
		{"destination_path", func(d *Decision) { d.DestinationRef = "api.vendor.example/path" }},
		{"destination_query", func(d *Decision) { d.DestinationRef = "api.vendor.example?sample=value" }},
		{"destination_fragment", func(d *Decision) { d.DestinationRef = "api.vendor.example#sample" }},
		{"destination_userinfo", func(d *Decision) { d.DestinationRef = "sample@api.vendor.example" }},
		{"destination_port", func(d *Decision) { d.DestinationRef = "api.vendor.example:443" }},
		{"destination_case", func(d *Decision) { d.DestinationRef = "API.vendor.example" }},
		{"destination_trailing_dot", func(d *Decision) { d.DestinationRef = "api.vendor.example." }},
		{"destination_empty_label", func(d *Decision) { d.DestinationRef = "api..vendor.example" }},
		{"destination_leading_hyphen", func(d *Decision) { d.DestinationRef = "-api.vendor.example" }},
		{"destination_trailing_hyphen", func(d *Decision) { d.DestinationRef = "api-.vendor.example" }},
		{"destination_long_label", func(d *Decision) { d.DestinationRef = strings.Repeat("a", 64) + ".vendor.example" }},
		{"destination_too_long", func(d *Decision) { d.DestinationRef = strings.Repeat("a", 254) }},
		{"local_process_non_mcp", func(d *Decision) {
			d.DestinationKind, d.DestinationRef = DestinationLocalProcess, "mcp.sample_upstream"
		}},
		{"local_process_argv", func(d *Decision) {
			d.Transport = TransportMCPStdio
			d.DestinationKind, d.DestinationRef = DestinationLocalProcess, "sample --argument"
		}},
		{"planned_unknown", func(d *Decision) { d.PlannedByteForm = ByteFormUnknown }},
		{"planned_missing", func(d *Decision) { d.PlannedByteForm = "" }},
		{"finding_unknown", func(d *Decision) { d.FindingDisposition = "future" }},
		{"block_original", func(d *Decision) { d.FindingDisposition = FindingBlock }},
		{"redact_original", func(d *Decision) { d.FindingDisposition = FindingRedact }},
		{"authority_unknown", func(d *Decision) { d.Authorization.Kind = "future" }},
		{"authority_missing", func(d *Decision) { d.Authorization.Kind = "" }},
		{"unused_authority_ref", func(d *Decision) { d.Authorization.Ref = "authorization:sample" }},
		{"authorization_kind_mismatch", func(d *Decision) {
			d.FindingDisposition = FindingAuthorize
			d.Authorization = Authorization{Kind: AuthorizationExemption, Ref: "sample"}
		}},
		{"exemption_kind_mismatch", func(d *Decision) {
			d.FindingDisposition = FindingExempt
			d.Authorization = Authorization{Kind: AuthorizationPermit, Ref: "sample"}
		}},
		{"authority_ref_missing", func(d *Decision) { d.FindingDisposition = FindingAuthorize; d.Authorization.Kind = AuthorizationPermit }},
		{"authority_ref_invalid", func(d *Decision) {
			d.FindingDisposition = FindingAuthorize
			d.Authorization = Authorization{Kind: AuthorizationPermit, Ref: "sample approval"}
		}},
		{"persistence_unknown", func(d *Decision) { d.PersistencePolicy = "fsync_confirmed" }},
		{"phase_unknown", func(d *Decision) { d.Phase = "future" }},
		{"intent_has_outcome", func(d *Decision) { d.Outcome = &Outcome{Release: ReleaseNone, ByteForm: ByteFormNone} }},
		{"outcome_missing", func(d *Decision) { d.Phase = PhaseOutcome }},
		{"release_unknown_enum", func(d *Decision) {
			d.Phase = PhaseOutcome
			d.Outcome = &Outcome{Release: "future", ByteForm: ByteFormOriginal}
		}},
		{"observed_form_unknown_enum", func(d *Decision) {
			d.Phase = PhaseOutcome
			d.Outcome = &Outcome{Release: ReleaseComplete, ByteForm: "future"}
		}},
		{"no_release_has_form", func(d *Decision) {
			d.Phase = PhaseOutcome
			d.Outcome = &Outcome{Release: ReleaseNone, ByteForm: ByteFormOriginal}
		}},
		{"release_has_no_form", func(d *Decision) {
			d.Phase = PhaseOutcome
			d.Outcome = &Outcome{Release: ReleaseComplete, ByteForm: ByteFormNone}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := decisionFixture()
			tc.mutate(&d)
			if err := d.Validate(); err == nil {
				t.Fatal("Validate accepted invalid fields")
			}
			if _, err := ParseDecision(marshalDecisionFixture(t, d)); err == nil {
				t.Fatal("ParseDecision accepted invalid fields")
			}
		})
	}
}

func TestDecisionObservedOutcomeCombinations(t *testing.T) {
	t.Parallel()
	for _, release := range []Release{ReleaseNone, ReleasePartial, ReleaseComplete, ReleaseUnknown} {
		for _, form := range []ByteForm{ByteFormNone, ByteFormOriginal, ByteFormTransformed, ByteFormUnknown} {
			d := decisionOutcomeFixture()
			d.Outcome = &Outcome{Release: release, ByteForm: form}
			valid := (release == ReleaseNone) == (form == ByteFormNone)
			if err := d.Validate(); (err == nil) != valid {
				t.Errorf("release=%s form=%s valid=%t err=%v", release, form, valid, err)
			}
		}
	}
}

func TestDecisionOutcomePreservesIdentityAndHonestMismatch(t *testing.T) {
	t.Parallel()
	intent := decisionFixture()
	intent.PatternClass = PatternCoreFloor
	intent.FindingDisposition, intent.PlannedByteForm = FindingBlock, ByteFormNone
	outcome := intent
	outcome.Phase = PhaseOutcome
	outcome.Outcome = &Outcome{Release: ReleaseComplete, ByteForm: ByteFormOriginal}
	if err := outcome.ValidateOutcomeOf(intent); err != nil {
		t.Fatalf("honest enforcement mismatch was erased: %v", err)
	}
	raw := marshalDecisionFixture(t, outcome)
	parsed, err := ParseDecision(raw)
	if err != nil {
		t.Fatalf("ParseDecision: %v", err)
	}
	if err := parsed.ValidateOutcomeOf(intent); err != nil {
		t.Fatalf("parsed pairing: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Decision)
	}{
		{"action_id", func(d *Decision) { d.ActionID = decisionTestOtherID }},
		{"decision_id", func(d *Decision) { d.DecisionID = decisionTestOtherID }},
		{"site_id", func(d *Decision) { d.SiteID = "proxy.forward.body.normalized" }},
		{"policy", func(d *Decision) { d.PersistencePolicy = PersistenceBestEffort }},
		{"rule_id", func(d *Decision) { d.RuleID = "configured.other_rule" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := outcome
			tc.mutate(&changed)
			if err := changed.ValidateOutcomeOf(intent); err == nil {
				t.Fatal("pairing accepted changed decision identity or facts")
			}
		})
	}
	if err := intent.ValidateOutcomeOf(intent); err == nil {
		t.Fatal("paired two intents")
	}
	if err := outcome.ValidateOutcomeOf(outcome); err == nil {
		t.Fatal("paired two outcomes")
	}
	invalid := intent
	invalid.Version = 0
	if err := outcome.ValidateOutcomeOf(invalid); err == nil {
		t.Fatal("paired invalid intent")
	}
	invalid = outcome
	invalid.Version = 0
	if err := invalid.ValidateOutcomeOf(intent); err == nil {
		t.Fatal("paired invalid outcome")
	}
}

func TestDecisionValidateAtRegistry(t *testing.T) {
	t.Parallel()
	d := decisionFixture()
	registry, err := NewRegistry([]Site{d.site()})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := d.ValidateAt(registry); err != nil {
		t.Fatalf("ValidateAt: %v", err)
	}
	if err := d.ValidateAt(nil); err == nil {
		t.Fatal("nil registry claimed membership")
	}
	for _, change := range []func(*Decision){
		func(d *Decision) { d.SiteID = "unknown.site" },
		func(d *Decision) { d.Transport = TransportFetch },
		func(d *Decision) { d.Location = LocationHeader },
		func(d *Decision) { d.View = ViewNormalized },
		func(d *Decision) { d.Boundary = BoundaryUpstreamFrame },
		func(d *Decision) { d.Version = 0 },
	} {
		changed := d
		change(&changed)
		if err := changed.ValidateAt(registry); err == nil {
			t.Fatal("accepted unregistered or changed site")
		}
	}
}

func TestParseDecisionStrictShape(t *testing.T) {
	t.Parallel()
	intent := string(marshalDecisionFixture(t, decisionFixture()))
	outcome := string(marshalDecisionFixture(t, decisionOutcomeFixture()))
	for name, raw := range map[string]string{
		"empty": "", "whitespace": " ", "null": "null", "array": "[]", "scalar": "1", "malformed": "{",
		"trailing_value": intent + " {}", "trailing_token": intent + " x",
		"duplicate":            strings.Replace(intent, `"version":1`, `"version":1,"version":1`, 1),
		"duplicate_nested":     strings.Replace(intent, `"kind":"none"`, `"kind":"none","kind":"none"`, 1),
		"unknown":              strings.Replace(intent, `"version":1`, `"version":1,"unknown":true`, 1),
		"self_attested_fsync":  strings.Replace(intent, `"version":1`, `"version":1,"fsync_confirmed":true`, 1),
		"case_alias":           strings.Replace(intent, `"version":1`, `"Version":1`, 1),
		"case_alias_collision": strings.Replace(intent, `"version":1`, `"version":1,"Version":1`, 1),
		"nested_case_alias":    strings.Replace(intent, `"kind":"none"`, `"Kind":"none"`, 1),
		"nested_unknown":       strings.Replace(intent, `"kind":"none"`, `"kind":"none","persisted":true`, 1),
		"nested_null":          strings.Replace(intent, `"kind":"none"`, `"kind":null`, 1),
		"object_null":          strings.Replace(intent, `{"kind":"none"}`, `null`, 1),
		"value_null":           strings.Replace(intent, `"version":1`, `"version":null`, 1),
		"wrong_type":           strings.Replace(intent, `"version":1`, `"version":"1"`, 1),
		"wrong_nested_type":    strings.Replace(intent, `{"kind":"none"}`, `[]`, 1),
		"missing_nested_key":   strings.Replace(intent, `{"kind":"none"}`, `{}`, 1),
		"outcome_unknown":      strings.Replace(outcome, `"release":"complete"`, `"release":"complete","fsync_confirmed":true`, 1),
		"outcome_case_alias":   strings.Replace(outcome, `"byte_form":"original"`, `"Byte_form":"original"`, 1),
		"outcome_missing_key":  strings.Replace(outcome, `,"byte_form":"original"`, ``, 1),
		"outcome_null":         strings.Replace(outcome, `{"release":"complete","byte_form":"original"}`, `null`, 1),
		"invalid_utf8":         strings.Replace(intent, decisionTestHost, string([]byte{0xff}), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDecision([]byte(raw)); err == nil {
				t.Fatal("accepted invalid JSON contract")
			}
		})
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(intent), &fields); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	for key, value := range fields {
		delete(fields, key)
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatalf("marshal incomplete object: %v", err)
		}
		if _, err := ParseDecision(raw); err == nil {
			t.Errorf("accepted missing mandatory field %s", key)
		}
		fields[key] = value
	}
}

func TestParseDecisionInputBound(t *testing.T) {
	t.Parallel()
	raw := marshalDecisionFixture(t, decisionFixture())
	padded := append(raw, []byte(strings.Repeat(" ", maxDecisionBytes-len(raw)))...)
	if _, err := ParseDecision(padded); err != nil {
		t.Fatalf("maximum-size input: %v", err)
	}
	if _, err := ParseDecision(append(padded, ' ')); err == nil {
		t.Fatal("accepted oversized input")
	}
}

func TestDecisionGoldenFixtures(t *testing.T) {
	t.Parallel()
	const directory = "testdata/decision-v1"
	var manifest struct {
		ContractVersion int    `json:"contract_version"`
		Status          string `json:"status"`
		Fixtures        []struct {
			ID            string `json:"id"`
			File          string `json:"file"`
			Valid         bool   `json:"valid"`
			IntentID      string `json:"intent_id"`
			ErrorContains string `json:"error_contains"`
		} `json:"fixtures"`
	}
	raw, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.ContractVersion != ContractVersion || manifest.Status != "candidate_model_only" || len(manifest.Fixtures) != 10 {
		t.Fatal("fixture contract metadata changed")
	}
	decisions := make(map[string]Decision)
	seen := make(map[string]bool)
	for _, fixture := range manifest.Fixtures {
		if fixture.ID == "" || seen[fixture.ID] || filepath.Base(fixture.File) != fixture.File {
			t.Fatal("invalid fixture identity or filename")
		}
		seen[fixture.ID] = true
		raw, err := os.ReadFile(filepath.Join(directory, fixture.File))
		if err != nil {
			t.Fatalf("read %s: %v", fixture.ID, err)
		}
		decision, err := ParseDecision(raw)
		if fixture.Valid {
			if err != nil || fixture.ErrorContains != "" {
				t.Fatalf("valid fixture %s: %v", fixture.ID, err)
			}
			decisions[fixture.ID] = decision
		} else if fixture.ErrorContains == "" || err == nil || !strings.Contains(err.Error(), fixture.ErrorContains) {
			t.Fatalf("invalid fixture %s: got %v, want %q", fixture.ID, err, fixture.ErrorContains)
		}
	}
	for _, fixture := range manifest.Fixtures {
		if fixture.IntentID == "" {
			continue
		}
		intent, ok := decisions[fixture.IntentID]
		if !ok || !fixture.Valid {
			t.Fatalf("invalid intent reference for %s", fixture.ID)
		}
		if err := decisions[fixture.ID].ValidateOutcomeOf(intent); err != nil {
			t.Fatalf("pair fixture %s: %v", fixture.ID, err)
		}
	}
	if decisions["outcome-mismatch"].PlannedByteForm != ByteFormNone ||
		decisions["outcome-mismatch"].Outcome == nil ||
		decisions["outcome-mismatch"].Outcome.ByteForm != ByteFormOriginal {
		t.Fatal("fixture lost truthful planned/observed mismatch")
	}
	rawFallback := decisions["raw-unrewritable-outcome"]
	if rawFallback.RewriteFallback == nil || rawFallback.RewriteFallback.PolicyOrigin != PolicyOriginOperator ||
		rawFallback.Outcome == nil || rawFallback.Outcome.ByteForm != ByteFormOriginal {
		t.Fatal("fixture lost operator policy or observed unrewritable release")
	}
	blockedFallback := decisions["blocked-fallback-outcome"]
	if blockedFallback.RewriteFallback == nil || blockedFallback.RewriteFallback.PolicyOrigin != PolicyOriginBuiltin ||
		blockedFallback.Outcome == nil || blockedFallback.Outcome.Release != ReleaseNone {
		t.Fatal("fixture lost blocked residual or built-in fallback policy")
	}
	builtinAuthorization := decisions["builtin-core-authorization"]
	if builtinAuthorization.PatternClass != PatternCoreFloor || builtinAuthorization.Authorization.Origin != PolicyOriginBuiltin ||
		builtinAuthorization.Authorization.Ref == "" || builtinAuthorization.PlannedByteForm != ByteFormOriginal {
		t.Fatal("fixture lost the named built-in core authorization")
	}
}
