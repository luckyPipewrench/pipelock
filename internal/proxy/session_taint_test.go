// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestSessionStateObserveRisk(t *testing.T) {
	sess := &SessionState{}

	sess.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://evil.example/backdoor",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
		PromptHit: true,
	})

	snap := sess.RiskSnapshot()
	if !snap.Contaminated {
		t.Fatal("expected session to become contaminated")
	}
	if snap.Level != session.TaintExternalHostile {
		t.Fatalf("level = %v, want hostile", snap.Level)
	}

	sess.Reset()
	if !sess.RiskSnapshot().Contaminated {
		t.Fatal("reset should not clear sticky taint contamination")
	}
}

func TestSessionManagerSnapshotIncludesTaint(t *testing.T) {
	sm := NewSessionManager(&config.SessionProfiling{Enabled: true, MaxSessions: 10, SessionTTLMinutes: 30, CleanupIntervalSeconds: 60}, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("agent-a|127.0.0.1")
	sess.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://evil.example/readme",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
	})

	snaps := sm.Snapshot()
	if len(snaps) != 1 {
		t.Fatalf("snapshot length = %d, want 1", len(snaps))
	}
	if snaps[0].TaintLevel != session.TaintExternalUntrusted.String() {
		t.Fatalf("taint level = %q, want %q", snaps[0].TaintLevel, session.TaintExternalUntrusted.String())
	}
	if !snaps[0].Contaminated {
		t.Fatal("expected contaminated snapshot")
	}
}

func TestEvaluateHTTPTaint_ExternalPublishAfterUntrustedExposureAsks(t *testing.T) {
	cfg := config.Defaults()
	sess := &SessionState{}

	observeHTTPResponseTaint(sess, cfg, "https://evil.example/issue/123", "text/html", "fetch_response", false)

	targetURL, err := url.Parse("https://api.example.com/auth/update")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	decision := evaluateHTTPTaint(cfg, sess, http.MethodPost, targetURL)
	if decision.Result.Decision != session.PolicyAsk {
		t.Fatalf("decision = %v, want ask", decision.Result.Decision)
	}
	if decision.Result.Reason != "external_publish_after_untrusted_external_exposure" {
		t.Fatalf("reason = %q", decision.Result.Reason)
	}
}

func TestEvaluateHTTPTaint_TrustOverrideHonorsScope(t *testing.T) {
	cfg := config.Defaults()
	sess := &SessionState{}

	observeHTTPResponseTaint(sess, cfg, "https://evil.example/issue/123", "text/html", "fetch_response", false)

	targetURL, err := url.Parse("https://api.example.com/auth/update")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	cfg.Taint.TrustOverrides = []config.TaintTrustOverride{{
		Scope:       "source",
		SourceMatch: "https://evil.example/*",
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}}
	decision := evaluateHTTPTaint(cfg, sess, http.MethodPost, targetURL)
	if decision.Result.Decision != session.PolicyAllow {
		t.Fatalf("decision = %v, want allow", decision.Result.Decision)
	}

	cfg.Taint.TrustOverrides = []config.TaintTrustOverride{{
		Scope:       "source",
		ActionMatch: "publish:post:https://api.example.com/auth/update",
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}}
	decision = evaluateHTTPTaint(cfg, sess, http.MethodPost, targetURL)
	if decision.Result.Decision != session.PolicyAsk {
		t.Fatalf("decision = %v, want ask when scope=source has no source_match", decision.Result.Decision)
	}
}

func TestEvaluateHTTPTaint_TrustOverrideUsesActiveSourceOnly(t *testing.T) {
	cfg := config.Defaults()
	sess := &SessionState{}

	observeHTTPResponseTaint(sess, cfg, "https://docs.github.com/copilot", "text/html", "fetch_response", false)
	observeHTTPResponseTaint(sess, cfg, "https://evil.example/issue/123", "text/html", "fetch_response", false)

	targetURL, err := url.Parse("https://api.example.com/auth/update")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	cfg.Taint.TrustOverrides = []config.TaintTrustOverride{{
		Scope:       "source",
		SourceMatch: "https://docs.github.com/*",
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}}
	decision := evaluateHTTPTaint(cfg, sess, http.MethodPost, targetURL)
	if decision.Result.Decision != session.PolicyAsk {
		t.Fatalf("decision = %v, want ask when only a historical source matches", decision.Result.Decision)
	}
}
