// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestSessionRiskObserve(t *testing.T) {
	var risk session.SessionRisk

	risk.Observe(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   testGitHubCopilotDocs,
			Kind:  "http_response",
			Level: session.TaintAllowlistedReference,
		},
		MaxSources: 2,
	})

	if risk.Level != session.TaintAllowlistedReference {
		t.Fatalf("level = %v, want allowlisted", risk.Level)
	}
	if risk.Contaminated {
		t.Fatal("allowlisted reference should not contaminate the session")
	}
	if risk.LastExternalURL != testGitHubCopilotDocs {
		t.Fatalf("last external url = %q", risk.LastExternalURL)
	}

	risk.Observe(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://evil.example/issue/123",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
		PromptHit:  true,
		MediaSeen:  true,
		MaxSources: 2,
	})

	if risk.Level != session.TaintExternalHostile {
		t.Fatalf("level = %v, want hostile", risk.Level)
	}
	if !risk.Contaminated {
		t.Fatal("untrusted exposure should contaminate the session")
	}
	if !risk.PromptHit {
		t.Fatal("expected prompt hit to be sticky")
	}
	if !risk.MediaSeen {
		t.Fatal("expected media_seen to be sticky")
	}
	if got := len(risk.Sources); got != 2 {
		t.Fatalf("sources length = %d, want 2", got)
	}
	if risk.Sources[1].Level != session.TaintExternalHostile {
		t.Fatalf("latest source level = %v, want hostile", risk.Sources[1].Level)
	}
}

func TestSessionRiskSnapshotCopiesSources(t *testing.T) {
	risk := session.SessionRisk{
		Level: session.TaintExternalUntrusted,
		Sources: []session.TaintSourceRef{
			{URL: "https://example.com", Level: session.TaintExternalUntrusted, Timestamp: time.Now().UTC()},
		},
	}

	snap := risk.Snapshot()
	snap.Sources[0].URL = "https://mutated.example"

	if risk.Sources[0].URL != "https://example.com" {
		t.Fatal("snapshot should deep-copy sources")
	}
}

func TestSessionRiskTrustedSourceDoesNotEstablishOrigin(t *testing.T) {
	var risk session.SessionRisk
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		URL: "https://trusted.example/page", Kind: "http_response", Level: session.TaintTrusted,
	}})

	if risk.Level != session.TaintTrusted {
		t.Fatalf("level = %v, want trusted", risk.Level)
	}
	if got := risk.SecurityOriginURL(); got != "" {
		t.Fatalf("security origin URL = %q, want empty", got)
	}
}

func TestSessionRiskHigherCrossAgentLevelStaysUnnameable(t *testing.T) {
	var risk session.SessionRisk
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		Kind: session.TaintSourceKindCrossAgent, Level: session.TaintExternalHostile,
	}})
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		URL: testGitHubCopilotDocs, Kind: "http_response", Level: session.TaintAllowlistedReference,
	}})

	if !risk.TaintOriginAmbiguous {
		t.Fatal("higher cross-agent level must leave the origin unnameable")
	}
	if got := risk.SecurityOriginURL(); got != "" {
		t.Fatalf("security origin URL = %q, want empty after later benign source", got)
	}
}

func TestSessionRiskCrossAgentKeepsLatestURLForAmbiguousOrigin(t *testing.T) {
	risk := session.SessionRisk{
		Level:                session.TaintExternalUntrusted,
		Contaminated:         true,
		LastExternalURL:      testGitHubCopilotDocs,
		TaintOriginAmbiguous: true,
	}
	risk.Observe(session.ClassifyCrossAgentObservation(
		risk.Snapshot(), session.CrossAgentBoundaryA2ARequest,
	))

	if risk.LastExternalURL != testGitHubCopilotDocs {
		t.Fatalf("last external URL = %q, want latest audit context preserved", risk.LastExternalURL)
	}
	if got := risk.SecurityOriginURL(); got != "" {
		t.Fatalf("security origin URL = %q, want ambiguous origin to stay empty", got)
	}
}

func TestSessionRiskAmbiguityMarkerSurvivesJSONRoundTrip(t *testing.T) {
	risk := session.SessionRisk{
		Level:                session.TaintExternalUntrusted,
		Contaminated:         true,
		LastExternalURL:      testGitHubCopilotDocs,
		LastExternalKind:     "http_response",
		TaintOriginAmbiguous: true,
	}
	raw, err := json.Marshal(risk)
	if err != nil {
		t.Fatalf("marshal risk: %v", err)
	}
	var decoded session.SessionRisk
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal risk: %v", err)
	}
	if got := decoded.SecurityOriginURL(); got != "" {
		t.Fatalf("security origin URL after round trip = %q, want empty", got)
	}
}

func TestSessionRiskLegacyKindFallback(t *testing.T) {
	risk := session.SessionRisk{LastExternalKind: "legacy_response"}
	if got := risk.SecurityOriginKind(); got != "legacy_response" {
		t.Fatalf("security origin kind = %q, want legacy_response", got)
	}
}

func TestSessionRiskTaintOriginSurvivesLaterSources(t *testing.T) {
	var risk session.SessionRisk
	hostileAt := time.Date(2026, time.August, 23, 1, 0, 0, 0, time.UTC)
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		URL:       "https://evil.example/issue/123",
		Kind:      "http_response",
		Level:     session.TaintExternalUntrusted,
		Timestamp: hostileAt,
	}})
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		URL:       testGitHubCopilotDocs,
		Kind:      "http_response",
		Level:     session.TaintAllowlistedReference,
		Timestamp: hostileAt.Add(time.Minute),
	}})

	if risk.LastExternalURL != testGitHubCopilotDocs {
		t.Fatalf("last external URL = %q, want latest source", risk.LastExternalURL)
	}
	if got := risk.SecurityOriginURL(); got != "https://evil.example/issue/123" {
		t.Fatalf("security origin URL = %q, want hostile source", got)
	}
	if got := risk.SecurityOriginKind(); got != "http_response" {
		t.Fatalf("security origin kind = %q, want http_response", got)
	}
	if !risk.TaintOriginAt.Equal(hostileAt) {
		t.Fatalf("taint origin time = %v, want %v", risk.TaintOriginAt, hostileAt)
	}
}

func TestSessionRiskTaintOriginMigratesLegacySnapshot(t *testing.T) {
	legacyAt := time.Date(2026, time.August, 23, 1, 0, 0, 0, time.UTC)
	risk := session.SessionRisk{
		Level:            session.TaintExternalUntrusted,
		Contaminated:     true,
		LastExternalAt:   legacyAt,
		LastExternalURL:  "https://evil.example/legacy",
		LastExternalKind: "http_response",
	}
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		URL:       testGitHubCopilotDocs,
		Kind:      "http_response",
		Level:     session.TaintAllowlistedReference,
		Timestamp: legacyAt.Add(time.Minute),
	}})

	if got := risk.SecurityOriginURL(); got != "https://evil.example/legacy" {
		t.Fatalf("migrated security origin URL = %q, want legacy source", got)
	}
	if risk.LastExternalURL != testGitHubCopilotDocs {
		t.Fatalf("last external URL = %q, want latest source", risk.LastExternalURL)
	}
}

// The MCP ingest path records a Kind and no URL, so an origin with an empty URL
// is a resolved origin, not a missing one. Falling back to LastExternalURL here
// hands a source-scoped trust override the later benign URL to match.
func TestSessionRiskURLLessOriginDoesNotFallBackToLatest(t *testing.T) {
	var risk session.SessionRisk
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		Kind:  "mcp_response",
		Level: session.TaintExternalUntrusted,
	}})
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		URL:   testGitHubCopilotDocs,
		Kind:  "http_response",
		Level: session.TaintAllowlistedReference,
	}})

	if got := risk.SecurityOriginURL(); got != "" {
		t.Fatalf("security origin URL = %q, want empty for the URL-less MCP origin", got)
	}
	if got := risk.SecurityOriginKind(); got != "mcp_response" {
		t.Fatalf("security origin kind = %q, want mcp_response", got)
	}
	if risk.LastExternalURL != testGitHubCopilotDocs {
		t.Fatalf("last external URL = %q, want latest source", risk.LastExternalURL)
	}
}

// Two distinct sources at the session maximum make the origin ambiguous, so no
// single-source trust override may match. Naming a winner fails open in one
// ordering or the other: first-wins clears the action when the operator-trusted
// source arrives first, newest-wins clears it when the trusted source arrives
// last. Both orderings are asserted here.
func TestSessionRiskDistinctEqualLevelSourcesClearOriginIdentity(t *testing.T) {
	trustedURL := session.TaintSourceRef{
		URL:   "https://internal.corp.example/wiki",
		Kind:  "http_response",
		Level: session.TaintExternalUntrusted,
	}
	hostileURL := session.TaintSourceRef{
		URL:   "https://evil.example/inject",
		Kind:  "http_response",
		Level: session.TaintExternalUntrusted,
	}
	sameURLDifferentKind := trustedURL
	sameURLDifferentKind.Kind = "mcp_tool_result"

	for _, tc := range []struct {
		name  string
		first session.TaintSourceRef
		last  session.TaintSourceRef
	}{
		{"trusted source first", trustedURL, hostileURL},
		{"trusted source last", hostileURL, trustedURL},
		{"same URL different kind first", trustedURL, sameURLDifferentKind},
		{"same URL different kind last", sameURLDifferentKind, trustedURL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var risk session.SessionRisk
			risk.Observe(session.RiskObservation{Source: tc.first})
			risk.Observe(session.RiskObservation{Source: tc.last})

			if got := risk.SecurityOriginURL(); got != "" {
				t.Fatalf("security origin URL = %q, want empty once two sources share the maximum", got)
			}
			if got := risk.SecurityOriginKind(); got != "" {
				t.Fatalf("security origin kind = %q, want empty once two sources share the maximum", got)
			}
			if risk.Level != session.TaintExternalUntrusted {
				t.Fatalf("level = %v, want untrusted preserved", risk.Level)
			}
		})
	}
}

// Re-observing the same source at the maximum is not a second source and must
// leave the origin intact, or a chatty poll of one hostile page would erase its
// own attribution.
func TestSessionRiskRepeatedSameSourceKeepsOrigin(t *testing.T) {
	source := session.TaintSourceRef{
		URL:   "https://evil.example/inject",
		Kind:  "http_response",
		Level: session.TaintExternalUntrusted,
	}
	var risk session.SessionRisk
	risk.Observe(session.RiskObservation{Source: source})
	risk.Observe(session.RiskObservation{Source: source})

	if got := risk.SecurityOriginURL(); got != source.URL {
		t.Fatalf("security origin URL = %q, want %q", got, source.URL)
	}
}

// A cross-agent ref is synthesized from the current origin and re-asserts the
// existing level. Adopting it as the origin would overwrite the real origin's
// attribution with a self-reference.
func TestSessionRiskCrossAgentRefDoesNotReplaceOrigin(t *testing.T) {
	origin := "https://attacker.example/inject"
	var risk session.SessionRisk
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		URL:   origin,
		Kind:  "http_response",
		Level: session.TaintExternalUntrusted,
	}})
	risk.Observe(session.ClassifyCrossAgentObservation(risk.Snapshot(), session.CrossAgentBoundaryA2ARequest))

	if got := risk.SecurityOriginURL(); got != origin {
		t.Fatalf("security origin URL = %q, want %q", got, origin)
	}
	if got := risk.SecurityOriginKind(); got != "http_response" {
		t.Fatalf("security origin kind = %q, want the ingest kind, not cross_agent", got)
	}
}

// A legacy snapshot carrying a level but no recoverable LastExternal* must not
// let a later, lower-risk source become the origin on a subsequent observation.
func TestSessionRiskUnrecoverableLegacyOriginStaysEmpty(t *testing.T) {
	risk := session.SessionRisk{Level: session.TaintExternalUntrusted, Contaminated: true}
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		URL:   testGitHubCopilotDocs,
		Kind:  "http_response",
		Level: session.TaintAllowlistedReference,
	}})
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		URL:   "https://another.example/page",
		Kind:  "http_response",
		Level: session.TaintAllowlistedReference,
	}})

	if got := risk.SecurityOriginURL(); got != "" {
		t.Fatalf("security origin URL = %q, want empty for an unrecoverable legacy origin", got)
	}
}

// Relative severity must not decide the origin once a source has reached the
// escalation floor. All three orderings are asserted because each one fails
// open on its own if severity is allowed to pick a winner, and each reaches a
// different branch. The escalating source here is a page an operator would
// plausibly trust, escalated to hostile because its security prose trips the
// injection patterns - the documented false-positive class, not a contrivance.
func TestSessionRiskEscalatingOriginIsNeverRetiredByASecondSource(t *testing.T) {
	untrusted := session.TaintSourceRef{
		URL:   "https://evil.example/inject",
		Kind:  "http_response",
		Level: session.TaintExternalUntrusted,
	}
	docs := session.TaintSourceRef{
		URL:   testGitHubCopilotDocs,
		Kind:  "http_response",
		Level: session.TaintExternalUntrusted,
	}

	for _, tc := range []struct {
		name             string
		first, second    session.RiskObservation
		wantLevel        session.TaintLevel
		wantOriginBefore string
	}{
		{
			name:             "more severe source arrives second",
			first:            session.RiskObservation{Source: untrusted},
			second:           session.RiskObservation{Source: docs, PromptHit: true},
			wantLevel:        session.TaintExternalHostile,
			wantOriginBefore: untrusted.URL,
		},
		{
			name:             "less severe source arrives second",
			first:            session.RiskObservation{Source: docs, PromptHit: true},
			second:           session.RiskObservation{Source: untrusted},
			wantLevel:        session.TaintExternalHostile,
			wantOriginBefore: docs.URL,
		},
		{
			name:             "equally severe source arrives second",
			first:            session.RiskObservation{Source: untrusted},
			second:           session.RiskObservation{Source: docs},
			wantLevel:        session.TaintExternalUntrusted,
			wantOriginBefore: untrusted.URL,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var risk session.SessionRisk
			risk.Observe(tc.first)
			if got := risk.SecurityOriginURL(); got != tc.wantOriginBefore {
				t.Fatalf("setup: security origin URL = %q, want %q", got, tc.wantOriginBefore)
			}

			risk.Observe(tc.second)

			if risk.Level != tc.wantLevel {
				t.Fatalf("level = %v, want %v", risk.Level, tc.wantLevel)
			}
			if got := risk.SecurityOriginURL(); got != "" {
				t.Fatalf("security origin URL = %q, want empty once a second escalating source is present", got)
			}
			if got := risk.SecurityOriginKind(); got != "" {
				t.Fatalf("security origin kind = %q, want empty once a second escalating source is present", got)
			}
		})
	}
}

// The same source escalating itself is not a second source. Losing the origin
// here would be an availability bug: the single page an operator needs to
// exempt would stop being nameable the moment its own content tripped a
// pattern.
func TestSessionRiskSameSourceEscalatingKeepsOrigin(t *testing.T) {
	source := session.TaintSourceRef{
		URL:   "https://evil.example/inject",
		Kind:  "http_response",
		Level: session.TaintExternalUntrusted,
	}
	var risk session.SessionRisk
	risk.Observe(session.RiskObservation{Source: source})
	risk.Observe(session.RiskObservation{Source: source, PromptHit: true})

	if risk.Level != session.TaintExternalHostile {
		t.Fatalf("level = %v, want hostile", risk.Level)
	}
	if got := risk.SecurityOriginURL(); got != source.URL {
		t.Fatalf("security origin URL = %q, want %q", got, source.URL)
	}
	if got := risk.SecurityOriginKind(); got != source.Kind {
		t.Fatalf("security origin kind = %q, want %q", got, source.Kind)
	}
}

// Sources below the escalation floor cannot escalate anything by themselves, so
// they must not make the session permanently unnameable. Two distinct reference
// fetches followed by the first real untrusted source must still name that
// source, or ordinary browsing would disable source-scoped overrides for the
// rest of the session.
func TestSessionRiskSubEscalationSourcesDoNotBlockOriginNaming(t *testing.T) {
	var risk session.SessionRisk
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		URL: testGitHubCopilotDocs, Kind: "http_response", Level: session.TaintAllowlistedReference,
	}})
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		URL: "https://docs.vendor.example/guide", Kind: "http_response", Level: session.TaintAllowlistedReference,
	}})
	if risk.Level != session.TaintAllowlistedReference {
		t.Fatalf("setup: level = %v, want allowlisted reference", risk.Level)
	}
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		URL: "https://evil.example/inject", Kind: "http_response", Level: session.TaintExternalUntrusted,
	}})

	if got := risk.SecurityOriginURL(); got != "https://evil.example/inject" {
		t.Fatalf("security origin URL = %q, want the first escalating source", got)
	}
	if got := risk.SecurityOriginKind(); got != "http_response" {
		t.Fatalf("security origin kind = %q, want http_response", got)
	}
}

// An ambiguous origin must stay ambiguous. A legacy snapshot can carry a
// LastExternalURL with a zero LastExternalAt, so recovery resolves an origin
// whose only non-zero field is the URL. Clearing that URL for ambiguity leaves
// every other origin field zero, and if "was an origin resolved" is inferred
// from those fields alone it now reads as "no origin at all" - falling back to
// LastExternal*, which Observe has just overwritten with the newest source.
func TestSessionRiskAmbiguousOriginNeverFallsBackToLatestSource(t *testing.T) {
	risk := session.SessionRisk{
		Level:            session.TaintExternalUntrusted,
		Contaminated:     true,
		LastExternalURL:  "https://evil.example/legacy",
		LastExternalKind: "http_response",
	}
	risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{
		URL:   testGitHubCopilotDocs,
		Kind:  "http_response",
		Level: session.TaintExternalUntrusted,
	}})

	if got := risk.SecurityOriginURL(); got != "" {
		t.Fatalf("security origin URL = %q, want empty once the origin is ambiguous", got)
	}
	if got := risk.SecurityOriginKind(); got != "" {
		t.Fatalf("security origin kind = %q, want empty once the origin is ambiguous", got)
	}
	if risk.LastExternalURL != testGitHubCopilotDocs {
		t.Fatalf("last external URL = %q, want latest source", risk.LastExternalURL)
	}
}

func TestRiskWireLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"taint trusted", session.TaintTrusted.String(), "trusted"},
		{"taint internal", session.TaintInternalGenerated.String(), "internal_generated"},
		{"taint allowlisted", session.TaintAllowlistedReference.String(), "allowlisted_reference"},
		{"taint low risk", session.TaintExternalLowRisk.String(), "external_low_risk"},
		{"taint untrusted", session.TaintExternalUntrusted.String(), "external_untrusted"},
		{"taint hostile", session.TaintExternalHostile.String(), "external_hostile"},
		{"taint unknown", session.TaintLevel(255).String(), "unknown"},
		{"action read", session.ActionClassRead.String(), "read"},
		{"action browse", session.ActionClassBrowse.String(), "browse"},
		{"action summarize", session.ActionClassSummarize.String(), "summarize"},
		{"action write", session.ActionClassWrite.String(), "write"},
		{"action exec", session.ActionClassExec.String(), "exec"},
		{"action secret", session.ActionClassSecret.String(), "secret"},
		{"action publish", session.ActionClassPublish.String(), "publish"},
		{"action network", session.ActionClassNetwork.String(), "network"},
		{"action unknown", session.ActionClass(255).String(), "unknown"},
		{"sensitivity normal", session.SensitivityNormal.String(), "normal"},
		{"sensitivity elevated", session.SensitivityElevated.String(), "elevated"},
		{"sensitivity protected", session.SensitivityProtected.String(), "protected"},
		{"sensitivity unknown", session.ActionSensitivity(255).String(), "unknown"},
		{"authority unknown", session.AuthorityUnknown.String(), "unknown"},
		{"authority external", session.AuthorityExternal.String(), "external"},
		{"authority policy", session.AuthorityPolicy.String(), "policy"},
		{"authority user broad", session.AuthorityUserBroad.String(), "user_broad"},
		{"authority user exact", session.AuthorityUserExact.String(), "user_exact"},
		{"authority operator override", session.AuthorityOperatorOverride.String(), "operator_override"},
		{"authority invalid", session.AuthorityKind(255).String(), "unknown"},
		{"decision allow", session.PolicyAllow.String(), "allow"},
		{"decision warn", session.PolicyWarn.String(), "warn"},
		{"decision ask", session.PolicyAsk.String(), "ask"},
		{"decision block", session.PolicyBlock.String(), "block"},
		{"decision unknown", session.PolicyDecision(255).String(), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Fatalf("label = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestPolicyMatrixEvaluate(t *testing.T) {
	pm := session.PolicyMatrix{Profile: "balanced"}

	tests := []struct {
		name        string
		taint       session.TaintLevel
		action      session.ActionClass
		sensitivity session.ActionSensitivity
		authority   session.AuthorityKind
		want        session.PolicyDecision
		wantReason  string
	}{
		{
			name:       "read after hostile exposure still allowed",
			taint:      session.TaintExternalHostile,
			action:     session.ActionClassRead,
			authority:  session.AuthorityUnknown,
			want:       session.PolicyAllow,
			wantReason: "taint_safe_read_only_action",
		},
		{
			name:        "protected write after untrusted exposure asks",
			taint:       session.TaintExternalUntrusted,
			action:      session.ActionClassWrite,
			sensitivity: session.SensitivityProtected,
			authority:   session.AuthorityUserBroad,
			want:        session.PolicyAsk,
			wantReason:  "protected_write_after_untrusted_external_exposure",
		},
		{
			name:        "protected write with exact authority allowed",
			taint:       session.TaintExternalUntrusted,
			action:      session.ActionClassWrite,
			sensitivity: session.SensitivityProtected,
			authority:   session.AuthorityUserExact,
			want:        session.PolicyAllow,
			wantReason:  "no_taint_escalation_required",
		},
		{
			name:       "mutating exec after untrusted exposure asks",
			taint:      session.TaintExternalUntrusted,
			action:     session.ActionClassExec,
			authority:  session.AuthorityUserExact,
			want:       session.PolicyAsk,
			wantReason: "mutating_exec_after_untrusted_external_exposure",
		},
		{
			name:       "exec with operator override allowed",
			taint:      session.TaintExternalUntrusted,
			action:     session.ActionClassExec,
			authority:  session.AuthorityOperatorOverride,
			want:       session.PolicyAllow,
			wantReason: "no_taint_escalation_required",
		},
		{
			name:       "secret use after untrusted exposure asks",
			taint:      session.TaintExternalUntrusted,
			action:     session.ActionClassSecret,
			authority:  session.AuthorityUserBroad,
			want:       session.PolicyAsk,
			wantReason: "secret_use_after_untrusted_external_exposure",
		},
		{
			name:       "publish after untrusted exposure asks",
			taint:      session.TaintExternalUntrusted,
			action:     session.ActionClassPublish,
			authority:  session.AuthorityPolicy,
			want:       session.PolicyAsk,
			wantReason: "external_publish_after_untrusted_external_exposure",
		},
		{
			name:        "hostile sensitive action blocks",
			taint:       session.TaintExternalHostile,
			action:      session.ActionClassWrite,
			sensitivity: session.SensitivityProtected,
			authority:   session.AuthorityOperatorOverride,
			want:        session.PolicyBlock,
			wantReason:  "sensitive_action_after_hostile_external_exposure",
		},
		{
			name:        "trusted context does not escalate",
			taint:       session.TaintTrusted,
			action:      session.ActionClassWrite,
			sensitivity: session.SensitivityProtected,
			authority:   session.AuthorityUnknown,
			want:        session.PolicyAllow,
			wantReason:  "trusted_or_allowlisted_context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pm.Evaluate(tt.taint, tt.action, tt.sensitivity, tt.authority)
			if got.Decision != tt.want {
				t.Fatalf("decision = %v, want %v", got.Decision, tt.want)
			}
			if got.Reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", got.Reason, tt.wantReason)
			}
		})
	}
}

func TestPolicyMatrixEvaluate_PermissiveObserveOnly(t *testing.T) {
	pm := session.PolicyMatrix{Profile: "permissive"}

	tests := []struct {
		name        string
		taint       session.TaintLevel
		action      session.ActionClass
		sensitivity session.ActionSensitivity
		authority   session.AuthorityKind
		opts        session.PolicyEvaluateOptions
	}{
		{
			name:      "publish after untrusted exposure allows",
			taint:     session.TaintExternalUntrusted,
			action:    session.ActionClassPublish,
			authority: session.AuthorityPolicy,
		},
		{
			name:      "secret use after untrusted exposure allows",
			taint:     session.TaintExternalUntrusted,
			action:    session.ActionClassSecret,
			authority: session.AuthorityUserBroad,
		},
		{
			name:      "exec after untrusted exposure allows",
			taint:     session.TaintExternalUntrusted,
			action:    session.ActionClassExec,
			authority: session.AuthorityUserExact,
		},
		{
			name:        "hostile sensitive action allows",
			taint:       session.TaintExternalHostile,
			action:      session.ActionClassWrite,
			sensitivity: session.SensitivityProtected,
			authority:   session.AuthorityUnknown,
		},
		{
			name:        "fail safe low confidence read allows",
			taint:       session.TaintExternalHostile,
			action:      session.ActionClassRead,
			sensitivity: session.SensitivityProtected,
			authority:   session.AuthorityUserBroad,
			opts: session.PolicyEvaluateOptions{
				FailSafeClassification:  true,
				ClassificationConfident: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pm.EvaluateWithOptions(tt.taint, tt.action, tt.sensitivity, tt.authority, tt.opts)
			if got.Decision != session.PolicyAllow {
				t.Fatalf("decision = %s, want allow", got.Decision)
			}
			if got.Reason != "taint_permissive_observe_only" {
				t.Fatalf("reason = %q, want permissive observe-only", got.Reason)
			}
		})
	}
}

func TestPolicyMatrixEvaluateWithOptions_FailSafeLowConfidenceRead(t *testing.T) {
	t.Parallel()

	pm := session.PolicyMatrix{Profile: "balanced"}
	withoutFailSafe := pm.EvaluateWithOptions(
		session.TaintExternalHostile,
		session.ActionClassRead,
		session.SensitivityProtected,
		session.AuthorityUserBroad,
		session.PolicyEvaluateOptions{ClassificationConfident: false},
	)
	if withoutFailSafe.Decision != session.PolicyAllow {
		t.Fatalf("without fail-safe decision = %s, want allow", withoutFailSafe.Decision)
	}

	withFailSafe := pm.EvaluateWithOptions(
		session.TaintExternalHostile,
		session.ActionClassRead,
		session.SensitivityProtected,
		session.AuthorityUserBroad,
		session.PolicyEvaluateOptions{FailSafeClassification: true, ClassificationConfident: false},
	)
	if withFailSafe.Decision != session.PolicyBlock {
		t.Fatalf("with fail-safe decision = %s, want block", withFailSafe.Decision)
	}
}
