// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// testOpts returns an MCPProxyOpts with only the scanner set.
// Most test callers need only the scanner; callers that need additional
// fields can copy the result and set them directly.
func testOpts(sc *scanner.Scanner) MCPProxyOpts {
	return MCPProxyOpts{Scanner: sc}
}

// testOptsFunc is a functional option for building MCPProxyOpts in tests.
type testOptsFunc func(*MCPProxyOpts)

// buildTestOpts constructs an MCPProxyOpts from a scanner and variadic options.
// This keeps test call sites short while allowing selective field overrides:
//
//	opts := buildTestOpts(sc, withRec(rec), withAdaptive(cfg))
func buildTestOpts(sc *scanner.Scanner, fns ...testOptsFunc) MCPProxyOpts {
	o := MCPProxyOpts{Scanner: sc}
	for _, fn := range fns {
		fn(&o)
	}
	return o
}

func withApprover(a *hitl.Approver) testOptsFunc {
	return func(o *MCPProxyOpts) { o.Approver = a }
}

func withToolCfg(tc *tools.ToolScanConfig) testOptsFunc {
	return func(o *MCPProxyOpts) { o.ToolCfg = tc }
}

func withKillSwitch(ks *killswitch.Controller) testOptsFunc {
	return func(o *MCPProxyOpts) { o.KillSwitch = ks }
}

func withRec(rec session.Recorder) testOptsFunc {
	return func(o *MCPProxyOpts) { o.Rec = rec }
}

func withAdaptive(cfg *config.AdaptiveEnforcement) testOptsFunc {
	return func(o *MCPProxyOpts) { o.AdaptiveCfg = cfg }
}

func withRedaction(m *redact.Matcher) testOptsFunc {
	return func(o *MCPProxyOpts) {
		o.RedactMatcher = m
		o.RedactLimits = redact.DefaultLimits().ToLimits()
		o.RedactProfile = "code"
	}
}

func TestMCPProxyOptsResolversPreferFunctions(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)
	staleCfg := config.Defaults()
	staleCfg.Internal = nil
	staleSc := scanner.New(staleCfg)
	t.Cleanup(staleSc.Close)

	inputCfg := &InputScanConfig{Enabled: true, Action: config.ActionBlock}
	requestBodyCfg := &config.RequestBodyScanning{Enabled: true, Action: config.ActionWarn}
	toolCfg := &tools.ToolScanConfig{Action: config.ActionWarn}
	policyCfg := &policy.Config{Action: config.ActionBlock}
	chainMatcher := chains.New(&cfg.ToolChainDetection)
	adaptiveCfg := &config.AdaptiveEnforcement{Enabled: true}
	taintCfg := &config.TaintConfig{Enabled: true}
	cee := &CEEDeps{Config: &cfg.CrossRequestDetection}
	redirectRT := &RedirectRuntime{FetchEndpoint: "http://127.0.0.1:8888/fetch"}
	provenanceCfg := &config.MCPToolProvenance{Enabled: true}
	a2aCfg := &config.A2AScanning{Enabled: true}
	mediaEnabled := true
	mediaPolicy := &config.MediaPolicy{Enabled: &mediaEnabled}
	redactionCfg := MCPRedactionConfig{Required: true, Profile: "strict"}
	staleMediaEnabled := false
	v2Emitter := &proxydecision.Emitter{}

	opts := MCPProxyOpts{
		Scanner:  staleSc,
		InputCfg: &InputScanConfig{Enabled: false},
		RequestBodyCfg: &config.RequestBodyScanning{
			Enabled: false,
			Action:  config.ActionBlock,
		},
		ToolCfg:          &tools.ToolScanConfig{Action: config.ActionBlock},
		PolicyCfg:        &policy.Config{Action: config.ActionWarn},
		ChainMatcher:     chains.New(&staleCfg.ToolChainDetection),
		AdaptiveCfg:      &config.AdaptiveEnforcement{Enabled: false},
		TaintCfg:         &config.TaintConfig{Enabled: false},
		CEE:              &CEEDeps{Config: &staleCfg.CrossRequestDetection},
		RedirectRT:       &RedirectRuntime{FetchEndpoint: "http://127.0.0.1:9999/fetch"},
		ProvenanceCfg:    &config.MCPToolProvenance{Enabled: false},
		A2ACfg:           &config.A2AScanning{Enabled: false},
		MediaPolicy:      &config.MediaPolicy{Enabled: &staleMediaEnabled},
		RedactProfile:    "stale",
		V2ReceiptEmitter: &proxydecision.Emitter{},
		PolicyHash:       "stale-policy-hash",

		ScannerFn:       func() *scanner.Scanner { return sc },
		InputCfgFn:      func() *InputScanConfig { return inputCfg },
		RequestBodyFn:   func() *config.RequestBodyScanning { return requestBodyCfg },
		ToolCfgFn:       func() *tools.ToolScanConfig { return toolCfg },
		PolicyCfgFn:     func() *policy.Config { return policyCfg },
		ChainMatcherFn:  func() *chains.Matcher { return chainMatcher },
		AdaptiveCfgFn:   func() *config.AdaptiveEnforcement { return adaptiveCfg },
		TaintCfgFn:      func() *config.TaintConfig { return taintCfg },
		CEEFn:           func() *CEEDeps { return cee },
		RedirectRTFn:    func() *RedirectRuntime { return redirectRT },
		ProvenanceCfgFn: func() *config.MCPToolProvenance { return provenanceCfg },
		A2ACfgFn:        func() *config.A2AScanning { return a2aCfg },
		MediaPolicyFn:   func() *config.MediaPolicy { return mediaPolicy },
		RedactionCfgFn:  func() MCPRedactionConfig { return redactionCfg },
		V2ReceiptEmitterFn: func() *proxydecision.Emitter {
			return v2Emitter
		},
		PolicyHashFn: func() string { return "live-policy-hash" },
	}

	if opts.scanner() != sc {
		t.Fatal("scanner resolver did not use ScannerFn")
	}
	if opts.inputCfg() != inputCfg {
		t.Fatal("input resolver did not use InputCfgFn")
	}
	if opts.requestBodyCfg() != requestBodyCfg {
		t.Fatal("request body resolver did not use RequestBodyFn")
	}
	if opts.toolCfg() != toolCfg {
		t.Fatal("tool resolver did not use ToolCfgFn")
	}
	if opts.policyCfg() != policyCfg {
		t.Fatal("policy resolver did not use PolicyCfgFn")
	}
	if opts.chainMatcher() != chainMatcher {
		t.Fatal("chain resolver did not use ChainMatcherFn")
	}
	if opts.adaptiveCfg() != adaptiveCfg {
		t.Fatal("adaptive resolver did not use AdaptiveCfgFn")
	}
	if opts.taintCfg() != taintCfg {
		t.Fatal("taint resolver did not use TaintCfgFn")
	}
	if opts.cee() != cee {
		t.Fatal("CEE resolver did not use CEEFn")
	}
	if opts.redirectRT() != redirectRT {
		t.Fatal("redirect resolver did not use RedirectRTFn")
	}
	if opts.provenanceCfg() != provenanceCfg {
		t.Fatal("provenance resolver did not use ProvenanceCfgFn")
	}
	if opts.a2aCfg() != a2aCfg {
		t.Fatal("A2A resolver did not use A2ACfgFn")
	}
	if opts.mediaPolicy() != mediaPolicy {
		t.Fatal("media resolver did not use MediaPolicyFn")
	}
	if got := opts.redactionConfig(); got != redactionCfg {
		t.Fatalf("redaction resolver = %+v, want %+v", got, redactionCfg)
	}
	if opts.v2ReceiptEmitter() != v2Emitter {
		t.Fatal("v2 receipt resolver did not use V2ReceiptEmitterFn")
	}
	if got := opts.receiptPolicyHash(); got != "live-policy-hash" {
		t.Fatalf("policy hash resolver = %q, want live-policy-hash", got)
	}
}

func TestMCPProxyOptsResolversFallbackToStaticValues(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	inputCfg := &InputScanConfig{Enabled: true}
	requestBodyCfg := &config.RequestBodyScanning{Enabled: true, Action: config.ActionBlock}
	toolCfg := &tools.ToolScanConfig{Action: config.ActionBlock}
	policyCfg := &policy.Config{Action: config.ActionBlock}
	chainMatcher := chains.New(&cfg.ToolChainDetection)
	adaptiveCfg := &config.AdaptiveEnforcement{Enabled: true}
	taintCfg := &config.TaintConfig{Enabled: true}
	cee := &CEEDeps{Config: &cfg.CrossRequestDetection}
	redirectRT := &RedirectRuntime{FetchEndpoint: "http://127.0.0.1:8888/fetch"}
	provenanceCfg := &config.MCPToolProvenance{Enabled: true}
	a2aCfg := &config.A2AScanning{Enabled: true}
	mediaEnabled := true
	mediaPolicy := &config.MediaPolicy{Enabled: &mediaEnabled}
	redactMatcher := redact.NewDefaultMatcher()
	redactLimits := redact.DefaultLimits().ToLimits()
	redactProfile := "strict"
	v2Emitter := &proxydecision.Emitter{}
	opts := MCPProxyOpts{
		Scanner:          sc,
		InputCfg:         inputCfg,
		RequestBodyCfg:   requestBodyCfg,
		ToolCfg:          toolCfg,
		PolicyCfg:        policyCfg,
		ChainMatcher:     chainMatcher,
		AdaptiveCfg:      adaptiveCfg,
		TaintCfg:         taintCfg,
		CEE:              cee,
		RedirectRT:       redirectRT,
		ProvenanceCfg:    provenanceCfg,
		A2ACfg:           a2aCfg,
		MediaPolicy:      mediaPolicy,
		RedactMatcher:    redactMatcher,
		RedactLimits:     redactLimits,
		RedactProfile:    redactProfile,
		V2ReceiptEmitter: v2Emitter,
		PolicyHash:       "static-policy-hash",
	}

	if opts.scanner() != sc || opts.inputCfg() != inputCfg || opts.toolCfg() != toolCfg ||
		opts.requestBodyCfg() != requestBodyCfg || opts.policyCfg() != policyCfg || opts.chainMatcher() != chainMatcher ||
		opts.adaptiveCfg() != adaptiveCfg || opts.taintCfg() != taintCfg ||
		opts.cee() != cee || opts.redirectRT() != redirectRT ||
		opts.provenanceCfg() != provenanceCfg || opts.a2aCfg() != a2aCfg ||
		opts.mediaPolicy() != mediaPolicy {
		t.Fatal("static resolver fallback returned unexpected value")
	}
	if got := opts.redactionConfig(); got.Matcher != redactMatcher || got.Limits != redactLimits || got.Profile != redactProfile {
		t.Fatalf("redaction fallback = %+v, want matcher=%p limits=%+v profile=%q",
			got, redactMatcher, redactLimits, redactProfile)
	}
	if opts.v2ReceiptEmitter() != v2Emitter {
		t.Fatal("v2 receipt fallback returned unexpected value")
	}
	if got := opts.receiptPolicyHash(); got != "static-policy-hash" {
		t.Fatalf("policy hash fallback = %q, want static-policy-hash", got)
	}
	stamped := opts.withReceiptPolicyHash(receipt.EmitOpts{Target: "tool"})
	if stamped.PolicyHash != "static-policy-hash" {
		t.Fatalf("withReceiptPolicyHash = %q, want static-policy-hash", stamped.PolicyHash)
	}
	preserved := opts.withReceiptPolicyHash(receipt.EmitOpts{PolicyHash: "pre-set"})
	if preserved.PolicyHash != "pre-set" {
		t.Fatalf("withReceiptPolicyHash overwrote existing hash: %q", preserved.PolicyHash)
	}
}
