// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/reqpolicy"
)

func TestFinalizeRequestPolicyDecisionRoutes(t *testing.T) {
	t.Parallel()

	p := newTestProxyWithConfig(t, reqPolicyConfig(blockRule(http.MethodDelete)))
	in := requestPolicyInput{
		Host:   rpTestHost,
		Method: http.MethodDelete,
		Path:   "/v1/jobs/1",
	}

	if got := p.finalizeRequestPolicyDecision(in, reqpolicy.Decision{}); got.Block {
		t.Fatalf("unmatched = %+v, want allow", got)
	}

	warn := p.finalizeRequestPolicyDecision(in, reqpolicy.Decision{
		Action:   config.ActionWarn,
		RuleName: rpRuleName,
		Reason:   "would block",
	})
	if warn.Block {
		t.Fatalf("warn = %+v, want allow", warn)
	}

	blocked := p.finalizeRequestPolicyDecision(in, reqpolicy.Decision{
		Action:   config.ActionBlock,
		RuleName: rpRuleName,
	})
	if !blocked.Block {
		t.Fatal("enforced block was allowed")
	}
	if blocked.Reason != rpRuleName {
		t.Fatalf("empty reason fallback = %q, want rule name", blocked.Reason)
	}

	var emitCalls int
	in.Emit = func(receipt.EmitOpts) error {
		emitCalls++
		return errors.New("recorder unavailable")
	}
	failedEmit := p.finalizeRequestPolicyDecision(in, reqpolicy.Decision{
		Action:   config.ActionBlock,
		RuleName: rpRuleName,
		Reason:   "dangerous operation requires operator approval",
	})
	if !failedEmit.Block {
		t.Fatal("emit failure weakened the block")
	}
	if emitCalls != 1 {
		t.Fatalf("emit calls = %d, want 1", emitCalls)
	}
	if failedEmit.Info.Receipt != "" {
		t.Fatalf("failed emit still stamped a receipt: %+v", failedEmit.Info)
	}
	if failedEmit.Reason != "dangerous operation requires operator approval" {
		t.Fatalf("explicit reason = %q", failedEmit.Reason)
	}
}

func TestRequestPolicyBlockInfoDropsMalformedReceipt(t *testing.T) {
	t.Parallel()

	p := newTestProxyWithConfig(t, reqPolicyConfig(blockRule(http.MethodDelete)))
	info := p.requestPolicyBlockInfo("not-a-receipt")
	if info.Receipt != "" {
		t.Fatalf("malformed action id stamped a receipt: %+v", info)
	}
	if info.Reason != blockreason.RequestPolicyDeny {
		t.Fatalf("block reason = %q, want request-policy deny", info.Reason)
	}
}
