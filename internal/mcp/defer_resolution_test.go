// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestEmitDeferredResolutionReceiptCarriesCascadePolicy(t *testing.T) {
	emitter, rec, dir := newTestReceiptEmitter(t)
	t.Cleanup(func() { _ = rec.Close() })
	wantPolicyHash := strings.TrimPrefix(mcpTestPolicyHash, "sha256:")

	opts := MCPProxyOpts{
		ReceiptEmitter:  emitter,
		PolicyHash:      mcpTestPolicyHash,
		RequireReceipts: true,
		Transport:       deferred.SurfaceMCPStdio,
	}
	var log bytes.Buffer
	err := EmitDeferredResolutionReceipt(opts, &log, deferred.Resolution{
		DeferID:          "child-defer",
		ParentActionID:   "child-action",
		FinalDecision:    config.ActionBlock,
		ResolutionSource: deferred.SourceCascade,
		Authority: deferred.AuthoritySnapshot{
			SessionID:         "session-a",
			SessionIDOriginal: "session-a",
		},
		ParentDeferID: "parent-defer",
		CascadeDepth:  2,
		Linkage:       deferred.LinkageSessionPendingAncestor,
		Policy: deferred.ResolutionPolicy{
			Timeout:              2 * time.Second,
			MaxPending:           64,
			MaxPendingPerSession: 8,
			MaxPendingBytes:      1024 * 1024,
			MaxCascadeDepth:      8,
		},
		Target: "neutral_tool",
		Method: "tools/call",
		Reason: "policy",
	})
	if err != nil {
		t.Fatalf("EmitDeferredResolutionReceipt: %v log=%q", err, log.String())
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder close: %v", err)
	}
	recorded := findActionReceiptHTTP(t, readReceiptEntriesHTTP(t, dir)).ActionRecord
	if recorded.ResolutionSource != deferred.SourceCascade {
		t.Fatalf("resolution_source = %q, want cascade", recorded.ResolutionSource)
	}
	if recorded.DecisionPhase != receipt.DecisionPhaseResolution {
		t.Fatalf("decision_phase = %q, want resolution", recorded.DecisionPhase)
	}
	var policy deferred.ReceiptPolicy
	if err := json.Unmarshal([]byte(recorded.ResolutionPolicy), &policy); err != nil {
		t.Fatalf("resolution_policy JSON: %v", err)
	}
	if policy.Cascade == nil {
		t.Fatal("resolution_policy.cascade missing")
	}
	if policy.Cascade.ParentDeferID != "parent-defer" ||
		policy.Cascade.CascadeDepth != 2 ||
		policy.Cascade.Linkage != deferred.LinkageSessionPendingAncestor ||
		policy.Bounds.MaxCascadeDepth != 8 {
		t.Fatalf("resolution_policy = %+v", policy)
	}
	if recorded.PolicyHash != wantPolicyHash {
		t.Fatalf("policy_hash = %q, want %q", recorded.PolicyHash, wantPolicyHash)
	}
}

func TestEmitDeferredResolutionReceiptNonCascadeCarriesBounds(t *testing.T) {
	emitter, rec, dir := newTestReceiptEmitter(t)
	t.Cleanup(func() { _ = rec.Close() })
	wantPolicyHash := strings.TrimPrefix(mcpTestPolicyHash, "sha256:")

	opts := MCPProxyOpts{
		ReceiptEmitter:  emitter,
		PolicyHash:      mcpTestPolicyHash,
		RequireReceipts: true,
		Transport:       deferred.SurfaceMCPStdio,
	}
	var log bytes.Buffer
	// Mirrors a plain capacity-exceeded Hold() failure: no cascade metadata.
	err := EmitDeferredResolutionReceipt(opts, &log, deferred.Resolution{
		DeferID:          "capacity-defer",
		ParentActionID:   "capacity-defer",
		FinalDecision:    config.ActionBlock,
		ResolutionSource: deferred.SourceCapacity,
		Authority: deferred.AuthoritySnapshot{
			SessionID:         "session-a",
			SessionIDOriginal: "session-a",
		},
		Policy: deferred.ResolutionPolicy{
			Timeout:              2 * time.Second,
			MaxPending:           64,
			MaxPendingPerSession: 8,
			MaxPendingBytes:      1024 * 1024,
			MaxCascadeDepth:      8,
		},
		Target: "neutral_tool",
		Method: "tools/call",
		Reason: "capacity",
	})
	if err != nil {
		t.Fatalf("EmitDeferredResolutionReceipt: %v log=%q", err, log.String())
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder close: %v", err)
	}
	recorded := findActionReceiptHTTP(t, readReceiptEntriesHTTP(t, dir)).ActionRecord
	if recorded.ResolutionSource != deferred.SourceCapacity {
		t.Fatalf("resolution_source = %q, want capacity", recorded.ResolutionSource)
	}
	if recorded.ResolutionPolicy == "" {
		t.Fatal("resolution_policy missing on non-cascade denial")
	}
	var policy deferred.ReceiptPolicy
	if err := json.Unmarshal([]byte(recorded.ResolutionPolicy), &policy); err != nil {
		t.Fatalf("resolution_policy JSON: %v", err)
	}
	if policy.Cascade != nil {
		t.Fatalf("resolution_policy.cascade = %+v, want nil", policy.Cascade)
	}
	if policy.Bounds.MaxCascadeDepth != 8 || policy.Bounds.MaxPending != 64 {
		t.Fatalf("resolution_policy bounds = %+v", policy.Bounds)
	}
	if recorded.PolicyHash != wantPolicyHash {
		t.Fatalf("policy_hash = %q, want %q", recorded.PolicyHash, wantPolicyHash)
	}
}

func TestEmitDeferredResolutionReceiptBlockFailureLogsAuditGap(t *testing.T) {
	emitter, rec, _ := newTestReceiptEmitter(t)
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder close: %v", err)
	}

	opts := MCPProxyOpts{
		ReceiptEmitter:  emitter,
		PolicyHash:      mcpTestPolicyHash,
		RequireReceipts: true,
		Transport:       deferred.SurfaceMCPStdio,
	}
	var log bytes.Buffer
	err := EmitDeferredResolutionReceipt(opts, &log, deferred.Resolution{
		DeferID:          "blocked-defer",
		ParentActionID:   "blocked-defer",
		FinalDecision:    config.ActionBlock,
		ResolutionSource: deferred.SourceTimeout,
		Target:           "neutral_tool",
		Method:           "tools/call",
		Reason:           "timeout",
	})
	if err == nil {
		t.Fatal("expected closed recorder to fail required resolution receipt")
	}
	if !strings.Contains(log.String(), "event=block_receipt_emit_failed") {
		t.Fatalf("missing block receipt audit-gap event in log: %s", log.String())
	}
	if !strings.Contains(log.String(), "audit_gap=true") {
		t.Fatalf("missing audit_gap marker in log: %s", log.String())
	}
}

func TestEmitHoldFailureResolutionSurfacesReceiptEmitError(t *testing.T) {
	emitter, rec, _ := newTestReceiptEmitter(t)
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder close: %v", err)
	}
	opts := MCPProxyOpts{
		ReceiptEmitter:  emitter,
		RequireReceipts: true,
		Transport:       deferred.SurfaceMCPStdio,
	}
	var log bytes.Buffer
	msg, err := emitHoldFailureResolution(opts, &log, deferred.ErrCapacity, holdFailureResolution{
		DeferID: "capacity-defer",
		Authority: deferred.AuthoritySnapshot{
			SessionID:         "session-a",
			SessionIDOriginal: "session-a",
		},
		Policy: deferred.ResolutionPolicy{
			Timeout:              2 * time.Second,
			MaxPending:           1,
			MaxPendingPerSession: 1,
			MaxPendingBytes:      8,
			MaxCascadeDepth:      2,
		},
		Target: "neutral_tool",
		Method: "tools/call",
		Reason: "capacity",
	})
	if msg != "pipelock: defer capacity exceeded" {
		t.Fatalf("message = %q, want capacity exceeded", msg)
	}
	if err == nil {
		t.Fatal("emitHoldFailureResolution error = nil, want receipt emission failure")
	}
	if !errors.Is(err, ErrReceiptRequired) {
		t.Fatalf("emitHoldFailureResolution error = %v, want ErrReceiptRequired", err)
	}
	if !strings.Contains(log.String(), "event=block_receipt_emit_failed") {
		t.Fatalf("log = %q, want block_receipt_emit_failed", log.String())
	}
}

func TestLogHoldFailureReceiptGap(t *testing.T) {
	var log bytes.Buffer
	logHoldFailureReceiptGap(&log, "defer-xyz", errors.New("emit boom"))
	got := log.String()
	for _, want := range []string{"audit_gap=true", "defer_id=defer-xyz", "emit boom"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log = %q, want %q", got, want)
		}
	}
	log.Reset()
	logHoldFailureReceiptGap(&log, "defer-xyz", nil)
	if log.String() != "" {
		t.Fatalf("expected no log on nil error, got %q", log.String())
	}
	logHoldFailureReceiptGap(nil, "defer-xyz", errors.New("x")) // must not panic on nil writer
}
