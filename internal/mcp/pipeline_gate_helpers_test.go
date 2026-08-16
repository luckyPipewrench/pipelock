// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/redact"
)

func TestFrameParseErrFailsClosed(t *testing.T) {
	t.Parallel()

	if frameParseErrFailsClosed(nil) {
		t.Fatal("nil parse error failed closed")
	}
	if frameParseErrFailsClosed(errors.New("unexpected EOF")) {
		t.Fatal("generic parse error failed closed")
	}
	if !frameParseErrFailsClosed(ErrInvalidMethodType) {
		t.Fatal("invalid method type did not fail closed")
	}
	if !frameParseErrFailsClosed(&redact.BlockError{Reason: redact.ReasonDuplicateKey}) {
		t.Fatal("duplicate key did not fail closed")
	}
}

func TestApplyDoWGateEmptyIdentityDoesNotRunCheck(t *testing.T) {
	t.Parallel()

	opts := MCPProxyOpts{
		DoWEnabledFn: func() bool { return true },
		DoWCheck: func(_, _, _ string) (bool, string, string, string) {
			t.Fatal("DoWCheck ran with an empty enforcement identity")
			return false, config.ActionBlock, "should not run", "test_budget"
		},
	}
	var eval MCPInputEvaluation
	if applyDoWGate(opts, &eval, "", MCPFrame{Method: methodToolsCall}, nil) {
		t.Fatal("empty identity blocked")
	}
	if eval.BlockingGate != "" || eval.DoWReason != "" {
		t.Fatalf("empty identity populated DoW fields: %+v", eval)
	}
}

func TestApplyDoWGateMissingTrustedSessionBlocks(t *testing.T) {
	t.Parallel()

	opts := MCPProxyOpts{
		DoWEnforceSubjectTrust: true,
		DoWEnabledFn:           func() bool { return true },
		DoWCheck: func(_, _, _ string) (bool, string, string, string) {
			t.Fatal("DoWCheck ran without a trusted subject")
			return true, config.ActionAllow, "", ""
		},
	}
	var eval MCPInputEvaluation
	if !applyDoWGate(opts, &eval, "read_file", MCPFrame{Method: methodToolsCall, ToolCallName: "read_file"}, nil) {
		t.Fatal("missing trusted session was allowed")
	}
	if eval.BlockingGate != blockingGateDoW {
		t.Fatalf("BlockingGate = %q, want %q", eval.BlockingGate, blockingGateDoW)
	}
	if eval.DoWAction != config.ActionBlock || eval.DoWAllowed {
		t.Fatalf("DoW verdict = allowed=%v action=%q", eval.DoWAllowed, eval.DoWAction)
	}
	if eval.DoWReason != dowMissingTrustedSessionReason {
		t.Fatalf("DoWReason = %q", eval.DoWReason)
	}
	if eval.DoWBudgetType != dowMissingTrustedSessionBudget {
		t.Fatalf("DoWBudgetType = %q", eval.DoWBudgetType)
	}
}

func TestEvaluateSessionBindingMissingToolNameDoesNotUseNoBaseline(t *testing.T) {
	t.Parallel()

	action, reason := evaluateSessionBinding(sessionBindingCheck{
		Method:           methodToolsCall,
		ToolName:         "",
		UnknownAction:    "",
		NoBaselineAction: config.ActionBlock,
	})
	if action != "" || reason != "" {
		t.Fatalf("missing tool name without unknown action = (%q,%q), want empty", action, reason)
	}

	action, reason = evaluateSessionBinding(sessionBindingCheck{
		Method:           methodToolsCall,
		ToolName:         "",
		UnknownAction:    config.ActionWarn,
		NoBaselineAction: config.ActionBlock,
	})
	if action != config.ActionWarn || reason != bindingReasonMissingToolName {
		t.Fatalf("missing tool name = (%q,%q)", action, reason)
	}
}

func TestMCPFrameParamsRejectsNullAndEmpty(t *testing.T) {
	t.Parallel()

	if got := mcpFrameParams(MCPFrame{Raw: []byte(`{"params":null}`)}); got != nil {
		t.Fatalf("null params = %s", got)
	}
	if got := mcpFrameParams(MCPFrame{Raw: []byte(`{"params":{}}`)}); len(got) == 0 {
		t.Fatal("empty object params dropped")
	}
}

func TestApplyMCPAirlockGateSkipsNonToolsCall(t *testing.T) {
	t.Parallel()

	eval := MCPInputEvaluation{}
	if applyMCPAirlockGate(MCPProxyOpts{Rec: &airlockTestRecorder{tier: config.AirlockTierHard}}, &eval, "tools/list") {
		t.Fatal("hard airlock contained a non-tools/call method")
	}
	if eval.BlockingGate != "" {
		t.Fatalf("non-tools/call gate = %q", eval.BlockingGate)
	}
}

func TestApplyMCPAirlockGateDisabledReleasesNilConfigKeepsHard(t *testing.T) {
	t.Parallel()

	rec := &airlockTestRecorder{tier: config.AirlockTierHard}
	disabled := config.Defaults().Airlock
	disabled.Enabled = false
	eval := MCPInputEvaluation{}
	if applyMCPAirlockGate(MCPProxyOpts{Rec: rec, AirlockCfg: &disabled}, &eval, methodToolsCall) {
		t.Fatal("explicitly disabled airlock still contained a hard session")
	}

	eval = MCPInputEvaluation{}
	if !applyMCPAirlockGate(MCPProxyOpts{Rec: rec}, &eval, methodToolsCall) {
		t.Fatal("nil airlock config released a hard session")
	}
	if eval.BlockingGate != blockingGateAirlockHard || eval.AirlockReason != mcpAirlockHardReason {
		t.Fatalf("nil-config hard session = gate=%q reason=%q", eval.BlockingGate, eval.AirlockReason)
	}
}

func TestMCPAirlockBlockMessageRoutes(t *testing.T) {
	t.Parallel()

	if got := mcpAirlockBlockMessage(MCPInputEvaluation{AirlockReason: mcpAirlockDrainReason}); !strings.Contains(got, "drain airlock") {
		t.Fatalf("drain message = %q", got)
	}
	if got := mcpAirlockBlockMessage(MCPInputEvaluation{
		BlockingGate: blockingGateAirlockMissing,
		AirlockTier:  mcpAirlockTierInvalid,
	}); !strings.Contains(got, "tier is invalid") {
		t.Fatalf("invalid-tier message = %q", got)
	}
	if got := mcpAirlockBlockMessage(MCPInputEvaluation{BlockingGate: blockingGateAirlockMissing}); !strings.Contains(got, "tier is unavailable") {
		t.Fatalf("unavailable message = %q", got)
	}
	if got := mcpAirlockBlockMessage(MCPInputEvaluation{AirlockReason: mcpAirlockHardReason}); !strings.Contains(got, "hard airlock") {
		t.Fatalf("hard message = %q", got)
	}
}

func TestEvaluateSessionBindingA2AEmptyActionDoesNotInheritUnknown(t *testing.T) {
	t.Parallel()

	mcpOnly := tools.NewToolBaseline()
	requireKnownTools(t, mcpOnly, []string{"search"})
	action, reason := evaluateSessionBinding(sessionBindingCheck{
		Baseline:            mcpOnly,
		Method:              "message/send",
		EnforcementIdentity: "a2a:message/send",
		UnknownAction:       config.ActionBlock,
		NoBaselineAction:    "",
	})
	if action != "" || reason != "" {
		t.Fatalf("empty A2A no-baseline action inherited unknown: (%q,%q)", action, reason)
	}
}

func TestEvaluateSessionBindingA2AUnknownEmptyActionDoesNotInheritNoBaseline(t *testing.T) {
	t.Parallel()

	baseline := tools.NewToolBaseline()
	baseline.SetKnownA2AMethods([]string{"SendMessage"})
	action, reason := evaluateSessionBinding(sessionBindingCheck{
		Baseline:            baseline,
		Method:              "message/send",
		EnforcementIdentity: "a2a:message/send",
		UnknownAction:       "",
		NoBaselineAction:    config.ActionBlock,
	})
	if action != "" || reason != "" {
		t.Fatalf("empty A2A unknown action inherited no-baseline: (%q,%q)", action, reason)
	}
}

func TestEvaluateSessionBindingUsesFrameMethodWhenMethodEmpty(t *testing.T) {
	t.Parallel()

	action, reason := evaluateSessionBinding(sessionBindingCheck{
		Baseline:         nil,
		Frame:            MCPFrame{Method: "message/send"},
		NoBaselineAction: config.ActionBlock,
	})
	if action != config.ActionBlock || reason != bindingReasonNoBaseline {
		t.Fatalf("empty Method did not use Frame.Method: (%q,%q)", action, reason)
	}
}

func TestApplyDoWGateUsesSessionKeyWhenSubjectEmpty(t *testing.T) {
	t.Parallel()

	var gotSubject string
	opts := MCPProxyOpts{
		DoWSessionKey: "sess-fallback",
		DoWEnabledFn:  func() bool { return true },
		DoWCheck: func(subject, _, _ string) (bool, string, string, string) {
			gotSubject = subject
			return true, config.ActionAllow, "", ""
		},
	}
	var eval MCPInputEvaluation
	if applyDoWGate(opts, &eval, "read_file", MCPFrame{Method: methodToolsCall}, nil) {
		t.Fatal("allowing DoW check blocked")
	}
	if gotSubject != "sess-fallback" {
		t.Fatalf("DoW subject = %q, want session-key fallback", gotSubject)
	}
}

func TestApplyDoWGateWarnDoesNotBlock(t *testing.T) {
	t.Parallel()

	opts := MCPProxyOpts{
		DoWSubjectKey: "agent-a",
		DoWEnabledFn:  func() bool { return true },
		DoWCheck: func(_, _, _ string) (bool, string, string, string) {
			return false, config.ActionWarn, "over budget", "token"
		},
	}
	var eval MCPInputEvaluation
	if applyDoWGate(opts, &eval, "read_file", MCPFrame{Method: methodToolsCall}, nil) {
		t.Fatal("warn DoW blocked")
	}
	if eval.BlockingGate != "" {
		t.Fatalf("warn DoW set BlockingGate = %q", eval.BlockingGate)
	}
	if eval.DoWAllowed || eval.DoWAction != config.ActionWarn || eval.DoWReason != "over budget" {
		t.Fatalf("warn DoW fields = %+v", eval)
	}
}

func TestApplyDoWGateDisabledSkipsCheck(t *testing.T) {
	t.Parallel()

	opts := MCPProxyOpts{
		DoWSubjectKey: "agent-a",
		DoWEnabledFn:  func() bool { return false },
		DoWCheck: func(_, _, _ string) (bool, string, string, string) {
			t.Fatal("DoWCheck ran while disabled")
			return false, config.ActionBlock, "should not run", "test_budget"
		},
	}
	var eval MCPInputEvaluation
	if applyDoWGate(opts, &eval, "read_file", MCPFrame{Method: methodToolsCall}, nil) {
		t.Fatal("disabled DoW blocked")
	}
}

func TestApplyMCPAirlockGateUnavailableAndInvalid(t *testing.T) {
	t.Parallel()

	enabled := config.Defaults().Airlock
	enabled.Enabled = true
	eval := MCPInputEvaluation{}
	if !applyMCPAirlockGate(MCPProxyOpts{AirlockCfg: &enabled}, &eval, methodToolsCall) {
		t.Fatal("enabled airlock with no recorder released")
	}
	if eval.BlockingGate != blockingGateAirlockMissing || eval.AirlockReason != mcpAirlockUnavailableReason {
		t.Fatalf("unavailable = gate=%q reason=%q", eval.BlockingGate, eval.AirlockReason)
	}

	eval = MCPInputEvaluation{}
	if !applyMCPAirlockGate(MCPProxyOpts{
		Rec:        &airlockTestRecorder{tier: "weird"},
		AirlockCfg: &enabled,
	}, &eval, methodToolsCall) {
		t.Fatal("invalid airlock tier was released")
	}
	if eval.BlockingGate != blockingGateAirlockMissing || eval.AirlockTier != mcpAirlockTierInvalid {
		t.Fatalf("invalid = gate=%q tier=%q", eval.BlockingGate, eval.AirlockTier)
	}
}
