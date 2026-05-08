// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestEvaluateGate_NilLoaderFallsThroughToScanner(t *testing.T) {
	out, err := EvaluateGate(ContractGateInput{
		URL:            "http://api.example.com/v1/chat",
		Method:         http.MethodPost,
		ScannerVerdict: config.ActionAllow,
		Transport:      TransportForward,
	})
	if err != nil {
		t.Fatalf("EvaluateGate: %v", err)
	}
	if out.Verdict != config.ActionAllow {
		t.Fatalf("verdict = %q, want allow", out.Verdict)
	}
	if out.WinningSource != contractruntime.WinningSourceScanner {
		t.Fatalf("winning_source = %q, want scanner", out.WinningSource)
	}
	if out.HasContractContext() {
		t.Fatalf("contract context = true, want false without active loader")
	}
	opts := withContractReceipt(out, receipt.EmitOpts{Verdict: config.ActionAllow})
	if opts.ContractWinningSource != "" || len(opts.ContractPolicySources) != 0 {
		t.Fatalf("receipt opts got contract fields without active contract: %+v", opts)
	}
}

func TestEvaluateGate_NoActiveManifestDoesNotEmitContractReceiptContext(t *testing.T) {
	loader := emptyContractLoader(t)
	out, err := EvaluateGate(ContractGateInput{
		Loader:         loader,
		Agent:          "agent-a",
		URL:            "http://api.example.com/v1/chat",
		Method:         http.MethodPost,
		ScannerVerdict: config.ActionAllow,
		Transport:      TransportForward,
	})
	if err != nil {
		t.Fatalf("EvaluateGate: %v", err)
	}
	if out.Verdict != config.ActionAllow {
		t.Fatalf("verdict = %q, want allow", out.Verdict)
	}
	if out.HasContractContext() {
		t.Fatalf("contract context = true, want false without active manifest")
	}
	opts := withContractReceipt(out, receipt.EmitOpts{Verdict: config.ActionAllow})
	if opts.ContractWinningSource != "" || opts.ActiveManifestHash != "" || opts.ContractHash != "" {
		t.Fatalf("receipt opts got contract fields without active manifest: %+v", opts)
	}
}

func TestEvaluateGate_LiveDefaultDeny(t *testing.T) {
	rule := contractruntimetest.HTTPEnforceRule("r-chat", "api.example.com", "/v1/chat", http.MethodPost)
	loader := testContractLoader(t, contractruntime.ModeLive, rule)

	out, err := EvaluateGate(ContractGateInput{
		Loader:         loader,
		Agent:          "agent-a",
		URL:            "http://evil.example.com/v1/chat",
		Method:         http.MethodPost,
		ScannerVerdict: config.ActionAllow,
		Transport:      TransportForward,
	})
	if err != nil {
		t.Fatalf("EvaluateGate: %v", err)
	}
	if out.Verdict != config.ActionBlock {
		t.Fatalf("verdict = %q, want block", out.Verdict)
	}
	if out.Reason != contractDefaultDenyReason {
		t.Fatalf("reason = %q, want %s", out.Reason, contractDefaultDenyReason)
	}
	if out.WinningSource != contractruntime.WinningSourceContract {
		t.Fatalf("winning_source = %q, want contract", out.WinningSource)
	}
	if !out.HasContractContext() {
		t.Fatalf("contract context = false, want true with resolved contract")
	}
}

func TestEvaluateGate_ScannerBlockWins(t *testing.T) {
	rule := contractruntimetest.HTTPEnforceRule("r-chat", "api.example.com", "/v1/chat", http.MethodPost)
	loader := testContractLoader(t, contractruntime.ModeLive, rule)

	out, err := EvaluateGate(ContractGateInput{
		Loader:         loader,
		Agent:          "agent-a",
		URL:            "http://api.example.com/v1/chat",
		Method:         http.MethodPost,
		ScannerVerdict: config.ActionBlock,
		ScannerMatched: true,
		Transport:      TransportForward,
	})
	if err != nil {
		t.Fatalf("EvaluateGate: %v", err)
	}
	if out.Verdict != config.ActionBlock {
		t.Fatalf("verdict = %q, want block", out.Verdict)
	}
	if out.WinningSource != contractruntime.WinningSourceScanner {
		t.Fatalf("winning_source = %q, want scanner", out.WinningSource)
	}
}

func TestEvaluateGate_ShadowSurfacesLiveVerdictWithoutBlocking(t *testing.T) {
	rule := contractruntimetest.HTTPEnforceRule("r-chat", "api.example.com", "/v1/chat", http.MethodPost)
	loader := testContractLoader(t, contractruntime.ModeShadow, rule)

	out, err := EvaluateGate(ContractGateInput{
		Loader:         loader,
		Agent:          "agent-a",
		URL:            "http://evil.example.com/v1/chat",
		Method:         http.MethodPost,
		ScannerVerdict: config.ActionAllow,
		Transport:      TransportForward,
	})
	if err != nil {
		t.Fatalf("EvaluateGate: %v", err)
	}
	if out.Verdict != config.ActionAllow {
		t.Fatalf("verdict = %q, want allow", out.Verdict)
	}
	if out.LiveVerdict != config.ActionBlock {
		t.Fatalf("live_verdict = %q, want block", out.LiveVerdict)
	}
	if out.Drift == nil {
		t.Fatal("drift = nil, want contract drift event")
	}
}

func TestBuildContractLoader_DisabledReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.LearnLock.Enabled = false
	loader, err := buildContractLoader(cfg)
	if err != nil {
		t.Fatalf("buildContractLoader: %v", err)
	}
	if loader != nil {
		t.Fatalf("loader = %v, want nil when learn-lock disabled", loader)
	}
}

func TestBuildContractLoader_NilConfigReturnsNil(t *testing.T) {
	loader, err := buildContractLoader(nil)
	if err != nil {
		t.Fatalf("buildContractLoader: %v", err)
	}
	if loader != nil {
		t.Fatalf("loader = %v, want nil for nil config", loader)
	}
}

func TestBuildContractLoader_EnabledHappyPathReturnsLoader(t *testing.T) {
	// Exercises the success arm of buildContractLoader so the
	// proxy-boot wiring is locked in alongside the disabled and
	// error paths. Uses contractruntimetest fixture so the roster
	// signing scaffolding stays in one place across packages.
	fixture := contractruntimetest.NewFixture(t)
	storeDir := t.TempDir()
	contractruntimetest.WriteSignedActiveStore(t, fixture, storeDir, contractruntimetest.ActiveStoreOptions{
		Generation:  1,
		PriorHash:   "sha256:genesis",
		Environment: contractruntimetest.Env(),
	})

	cfg := &config.Config{}
	cfg.LearnLock.Enabled = true
	cfg.LearnLock.StoreDir = storeDir
	cfg.LearnLock.RosterPath = fixture.RosterPath()
	cfg.LearnLock.PinnedRootFingerprint = fixture.RootFingerprint()
	cfg.LearnLock.Environment = "prod"
	cfg.LearnLock.MinimumSignatures = 1
	cfg.LearnLock.Mode = "live"

	loader, err := buildContractLoader(cfg)
	if err != nil {
		t.Fatalf("buildContractLoader: %v", err)
	}
	if loader == nil {
		t.Fatal("loader = nil, want loader for enabled config")
	}
	if loader.Mode() != contractruntime.ModeLive {
		t.Fatalf("loader.Mode() = %q, want live", loader.Mode())
	}
}

func TestBuildContractLoader_EnabledMissingFieldsErrors(t *testing.T) {
	// Defensive path. Enabled=true with no store_dir means NewLoader
	// fails fast at proxy init rather than panicking later when the
	// gate tries to call Current() on a half-built loader.
	cfg := &config.Config{}
	cfg.LearnLock.Enabled = true
	loader, err := buildContractLoader(cfg)
	if err == nil {
		t.Fatal("buildContractLoader err = nil, want error for missing fields")
	}
	if loader != nil {
		t.Fatalf("loader = %v, want nil on error", loader)
	}
	if !strings.Contains(err.Error(), "contract loader init") {
		t.Fatalf("err = %v, want wrapped \"contract loader init\"", err)
	}
}

func TestContractBlockInfo_RecognisesContractReasons(t *testing.T) {
	cases := []struct {
		reason string
		want   blockreason.Reason
	}{
		{contractDefaultDenyReason, blockreason.Reason("contract_default_deny")},
		{"contract_enforce_default", blockreason.Reason("contract_enforce_default")},
		{"contract_non_default_port", blockreason.Reason("contract_non_default_port")},
		{"contract_invalid_path", blockreason.Reason("contract_invalid_path")},
		{"contract_observed_only", blockreason.Reason("contract_observed_only")},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.reason, func(t *testing.T) {
			info, ok := contractBlockInfo(tc.reason)
			if !ok {
				t.Fatalf("ok=false, want true for %q", tc.reason)
			}
			if info.Reason != tc.want {
				t.Fatalf("info.Reason = %q, want %q", info.Reason, tc.want)
			}
			if info.Severity != blockreason.SeverityCritical {
				t.Fatalf("info.Severity = %q, want critical", info.Severity)
			}
			if info.Layer != "contract" {
				t.Fatalf("info.Layer = %q, want contract", info.Layer)
			}
		})
	}
}

func TestContractBlockInfo_UnknownReasonReturnsFalse(t *testing.T) {
	cases := []string{"", "made_up_reason", "kill_switch_active", "contract_"}
	for _, reason := range cases {
		reason := reason
		t.Run(reason, func(t *testing.T) {
			if _, ok := contractBlockInfo(reason); ok {
				t.Fatalf("ok=true, want false for non-contract reason %q", reason)
			}
		})
	}
}

func TestWriteGateBlockedError_RoutesByGateShape(t *testing.T) {
	// writeGateBlockedError is the proxy-side dispatcher that picks
	// the right block-reason header based on which path produced the
	// gate verdict. This pins the four arms (kill switch, scanner,
	// contract reason, fallback) so a future refactor can't silently
	// swap a kill-switch block to surface as parse_error.
	cases := []struct {
		name string
		gate ContractGateOutput
		want blockreason.Reason
	}{
		{
			name: "kill switch by reason",
			gate: ContractGateOutput{Reason: "kill_switch_active"},
			want: blockreason.KillSwitchActive,
		},
		{
			name: "kill switch by winning source",
			gate: ContractGateOutput{WinningSource: contractruntime.WinningSourceKillSwitch},
			want: blockreason.KillSwitchActive,
		},
		{
			name: "scanner winning source",
			gate: ContractGateOutput{WinningSource: contractruntime.WinningSourceScanner},
			want: blockreason.ParseError,
		},
		{
			name: "contract default deny reason",
			gate: ContractGateOutput{
				WinningSource: contractruntime.WinningSourceContract,
				Reason:        contractDefaultDenyReason,
			},
			want: blockreason.Reason("contract_default_deny"),
		},
		{
			name: "fallback for unknown reason",
			gate: ContractGateOutput{
				WinningSource: contractruntime.WinningSourceContract,
				Reason:        "made_up_reason",
			},
			want: blockreason.ParseError,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeGateBlockedError(rec, tc.gate, "blocked")
			if got := rec.Header().Get(blockreason.HeaderReason); got != string(tc.want) {
				t.Fatalf("header reason = %q, want %q", got, string(tc.want))
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
		})
	}
}

func TestScannerVerdictForGate(t *testing.T) {
	if got := scannerVerdictForGate(true); got != config.ActionWarn {
		t.Fatalf("hasFinding=true got %q, want warn", got)
	}
	if got := scannerVerdictForGate(false); got != config.ActionAllow {
		t.Fatalf("hasFinding=false got %q, want allow", got)
	}
}

func TestScannerVerdictForContinuingAction(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		enforce bool
		want    string
	}{
		{name: "empty", action: "", enforce: true, want: config.ActionAllow},
		{name: "allow", action: config.ActionAllow, enforce: true, want: config.ActionAllow},
		{name: "warn", action: config.ActionWarn, enforce: true, want: config.ActionWarn},
		{name: "block enforce", action: config.ActionBlock, enforce: true, want: config.ActionBlock},
		{name: "block audit", action: config.ActionBlock, enforce: false, want: config.ActionWarn},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scannerVerdictForContinuingAction(tc.action, tc.enforce); got != tc.want {
				t.Fatalf("scannerVerdictForContinuingAction(%q, %t) = %q, want %q", tc.action, tc.enforce, got, tc.want)
			}
		})
	}
}

func TestForwardKillSwitchReceiptOpts_BareForwardReceipt(t *testing.T) {
	got := forwardKillSwitchReceiptOpts("act-ks", "req-ks", http.MethodGet, "http://api.example.com/v1/chat")
	if got.ActionID != "act-ks" || got.RequestID != "req-ks" {
		t.Fatalf("identity fields lost: %+v", got)
	}
	if got.Verdict != config.ActionBlock {
		t.Fatalf("verdict = %q, want block", got.Verdict)
	}
	if got.Layer != "kill_switch" || got.Pattern != killSwitchActiveReason {
		t.Fatalf("layer/pattern = %q/%q", got.Layer, got.Pattern)
	}
	if got.Transport != TransportForward {
		t.Fatalf("transport = %q, want %q", got.Transport, TransportForward)
	}
	if got.Method != http.MethodGet || got.Target != "http://api.example.com/v1/chat" {
		t.Fatalf("method/target = %q/%q", got.Method, got.Target)
	}
	if got.Agent != "" || got.SessionTaintLevel != "" || got.AuthorityKind != "" {
		t.Fatalf("kill-switch receipt carried unresolved-agent context: %+v", got)
	}
}

func TestForwardBlockReceiptOpts_StampsForwardAndTaintContext(t *testing.T) {
	in := ForwardBlockReceiptInput{
		ActionID:  "act-1",
		RequestID: "req-1",
		Agent:     "agent-a",
		Method:    http.MethodPost,
		Target:    "http://api.example.com/v1/chat",
		Layer:     "contract",
		Pattern:   "contract_default_deny",
	}
	got := forwardBlockReceiptOpts(in)
	if got.ActionID != "act-1" || got.RequestID != "req-1" || got.Agent != "agent-a" {
		t.Fatalf("identity fields lost: %+v", got)
	}
	if got.Verdict != config.ActionBlock {
		t.Fatalf("verdict = %q, want block", got.Verdict)
	}
	if got.Layer != "contract" || got.Pattern != "contract_default_deny" {
		t.Fatalf("layer/pattern = %q/%q", got.Layer, got.Pattern)
	}
	if got.Transport != TransportForward {
		t.Fatalf("transport = %q, want %q", got.Transport, TransportForward)
	}
	if got.Method != http.MethodPost || got.Target != "http://api.example.com/v1/chat" {
		t.Fatalf("method/target = %q/%q", got.Method, got.Target)
	}
}

func TestForwardBlockReceiptOpts_StampsTaintFields(t *testing.T) {
	taint := taintDecision{
		TaskOverrideApplied: true,
	}
	taint.Risk.Level = session.TaintExternalUntrusted
	taint.Risk.Contaminated = true
	taint.Task.CurrentTaskID = "task-1"
	taint.Task.CurrentTaskLabel = "billing"
	taint.Authority = session.AuthorityUserExact
	taint.Result.Decision = session.PolicyBlock
	taint.Result.Reason = "task boundary violation"
	got := forwardBlockReceiptOpts(ForwardBlockReceiptInput{
		ActionID: "act-2",
		Agent:    "agent-a",
		Method:   http.MethodPost,
		Target:   "http://api.example.com/v1/chat",
		Layer:    blockLayerContract,
		Pattern:  contractDefaultDenyReason,
		Taint:    taint,
	})
	if got.SessionTaintLevel != session.TaintExternalUntrusted.String() {
		t.Fatalf("taint level = %q, want %q", got.SessionTaintLevel, session.TaintExternalUntrusted.String())
	}
	if !got.SessionContaminated {
		t.Fatal("SessionContaminated = false, want true")
	}
	if got.SessionTaskID != "task-1" || got.SessionTaskLabel != "billing" {
		t.Fatalf("task fields = %q/%q", got.SessionTaskID, got.SessionTaskLabel)
	}
	if got.AuthorityKind != session.AuthorityUserExact.String() {
		t.Fatalf("AuthorityKind = %q", got.AuthorityKind)
	}
	if got.TaintDecision != session.PolicyBlock.String() {
		t.Fatalf("TaintDecision = %q", got.TaintDecision)
	}
	if got.TaintDecisionReason != "task boundary violation" {
		t.Fatalf("TaintDecisionReason = %q", got.TaintDecisionReason)
	}
	if !got.TaskOverrideApplied {
		t.Fatal("TaskOverrideApplied = false, want true")
	}
}
