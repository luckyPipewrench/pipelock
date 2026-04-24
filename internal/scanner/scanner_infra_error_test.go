// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestIsInfrastructureError covers the classifier for every defined
// ResultClass value.
func TestIsInfrastructureError(t *testing.T) {
	tests := []struct {
		name  string
		class ResultClass
		want  bool
	}{
		{"zero value is not infrastructure error", ClassThreat, false},
		{"ClassProtective is not infrastructure error", ClassProtective, false},
		{"ClassConfigMismatch is not infrastructure error", ClassConfigMismatch, false},
		{"ClassInfrastructureError is infrastructure error", ClassInfrastructureError, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Result{Class: tt.class}
			if got := r.IsInfrastructureError(); got != tt.want {
				t.Errorf("IsInfrastructureError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsAdaptiveNeutral covers the helper that unifies protective enforcement
// and infrastructure errors for adaptive-score exclusion. Config mismatch must
// NOT be neutral (it remains a bounded NearMiss signal).
func TestIsAdaptiveNeutral(t *testing.T) {
	tests := []struct {
		name  string
		class ResultClass
		want  bool
	}{
		{"ClassThreat is not adaptive neutral", ClassThreat, false},
		{"ClassProtective is adaptive neutral", ClassProtective, true},
		{"ClassConfigMismatch is not adaptive neutral", ClassConfigMismatch, false},
		{"ClassInfrastructureError is adaptive neutral", ClassInfrastructureError, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Result{Class: tt.class}
			if got := r.IsAdaptiveNeutral(); got != tt.want {
				t.Errorf("IsAdaptiveNeutral() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestScanURL_DNSFailure_ClassifiedAsInfrastructureError verifies that an
// SSRF check against a hostname the resolver cannot look up returns
// Result{Allowed: false, Class: ClassInfrastructureError}.
//
// The ".invalid" TLD is reserved by RFC 2606 and must never resolve, so the
// DNS-lookup branch at scanner.go is hit deterministically regardless of
// the host machine's DNS configuration.
//
// Rationale (see also internal/proxy/proxy.go recordSessionActivity): a
// burst of DNS failures previously accumulated SignalBlock points (+3.0
// each) and pushed the session into airlock lockdown. Classifying the
// block as an infrastructure error lets adaptive enforcement skip the
// signal while preserving fail-closed semantics.
func TestScanURL_DNSFailure_ClassifiedAsInfrastructureError(t *testing.T) {
	cfg := config.Defaults()
	// SSRF layer needs at least one internal CIDR configured to run the
	// DNS path at all. nil would disable the SSRF check entirely.
	cfg.Internal = []string{"127.0.0.0/8", "10.0.0.0/8"}

	s := New(cfg)
	defer s.Close()

	result := s.Scan(context.Background(), "https://nonexistent.invalid/")

	if result.Allowed {
		t.Fatal("DNS-unresolvable host must be blocked (fail-closed)")
	}
	if result.Scanner != ScannerSSRF {
		t.Errorf("expected SSRF scanner verdict, got %q (reason: %s)", result.Scanner, result.Reason)
	}
	if !result.IsInfrastructureError() {
		t.Errorf("DNS failure must be classified as ClassInfrastructureError; got class=%d reason=%q", result.Class, result.Reason)
	}
	if !result.IsAdaptiveNeutral() {
		t.Error("ClassInfrastructureError must return IsAdaptiveNeutral()=true")
	}
	if result.IsConfigMismatch() {
		t.Error("DNS failure is not a config mismatch")
	}
	if result.IsProtective() {
		t.Error("DNS failure is not protective enforcement (rate limit)")
	}
}

// TestScanURL_CancelledContext_RoutesThroughScannerContext pins the
// CodeRabbit follow-up on this PR: dnsCtx inherits the caller ctx, so
// a client abort or request deadline surfacing as context.Canceled /
// DeadlineExceeded from LookupHost must NOT be reclassified as
// ClassInfrastructureError (which would make it adaptive-neutral).
// CLAUDE.md is explicit: "context cancellation: all default to block"
// and the ScannerContext path is how every other cancellation reaches
// the fail-closed ceiling. An infrastructure classification here would
// let a cancelled adversarial probe skip session escalation.
func TestScanURL_CancelledContext_RoutesThroughScannerContext(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = []string{"127.0.0.0/8", "10.0.0.0/8"}

	s := New(cfg)
	defer s.Close()

	// Cancel the context before the Scan runs so the DNS layer sees
	// LookupHost return a ctx error, not a resolver NXDOMAIN.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := s.Scan(ctx, "https://nonexistent.invalid/")

	if result.Allowed {
		t.Fatal("cancelled context must be blocked (fail-closed)")
	}
	if result.Scanner != ScannerContext {
		t.Errorf("cancelled ctx must route through ScannerContext, got scanner=%q reason=%q class=%d",
			result.Scanner, result.Reason, result.Class)
	}
	if result.IsInfrastructureError() {
		t.Error("cancelled ctx must NOT be classified as ClassInfrastructureError (would skip adaptive signal)")
	}
	if result.IsAdaptiveNeutral() {
		t.Error("cancelled ctx must count as a fail-closed block for adaptive enforcement, not neutral")
	}
}

// TestScanURL_RealSSRF_StillThreat is the load-bearing regression guard:
// a real SSRF attempt (hostname resolving to an internal CIDR) must still
// be classified as ClassThreat so adaptive enforcement keeps scoring it as
// SignalBlock. If this test starts treating private-IP resolution as neutral,
// the infrastructure-error classifier has been miswired and adversarial
// SSRF probes will no longer escalate sessions.
func TestScanURL_RealSSRF_StillThreat(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = []string{"127.0.0.0/8"}

	s := New(cfg)
	defer s.Close()

	// Hostname decodes directly to 127.0.0.1 via the alternative-IP path,
	// so no DNS lookup is required — this keeps the test hermetic.
	result := s.Scan(context.Background(), "https://0x7f000001/")

	if result.Allowed {
		t.Fatal("SSRF against localhost must be blocked")
	}
	if result.Scanner != ScannerSSRF {
		t.Errorf("expected SSRF scanner verdict, got %q", result.Scanner)
	}
	if result.IsInfrastructureError() {
		t.Error("real SSRF (private IP) must NOT be classified as infrastructure error")
	}
	if result.IsAdaptiveNeutral() {
		t.Error("real SSRF must NOT be adaptive-neutral; it must score SignalBlock")
	}
	if result.Class != ClassThreat {
		t.Errorf("real SSRF must remain ClassThreat; got class=%d", result.Class)
	}
}
