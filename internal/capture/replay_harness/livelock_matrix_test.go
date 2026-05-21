// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package replay_harness validates the runtime evaluator's live-lock decision
// precedence across the production gate shapes. End-to-end transport behavior
// is covered separately by the live-lock integration tests in internal/proxy
// and internal/mcp.
package replay_harness

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

var updateLiveLockGoldens = flag.Bool("update", false, "regenerate live-lock replay-harness golden files")

const (
	liveLockGoldenDir  = "testdata/livelock"
	liveLockGoldenFile = "transport_matrix.json"

	liveLockAgent       = "agent-a"
	liveLockHTTPHost    = "api.example.com"
	liveLockMCPServer   = "stripe"
	liveLockAllowedTool = "create_payment_intent"
	liveLockDeniedTool  = "refund_payment"

	gateProxyHTTP   = "proxy.EvaluateGate"
	gateRuntimeHTTP = "runtime.EvaluateHTTP"
	gateRuntimeMCP  = "runtime.EvaluateMCP"

	livelockJSONKeyValue  = "value"
	livelockConfidenceOne = "1.0"

	contractStateNone         = "none"
	contractStateAllow        = "allow"
	contractStateDefaultDeny  = "default_deny"
	contractStateScannerFloor = "scanner_floor"
	contractStateObserve      = "observe"
	contractStateKillSwitch   = "kill_switch"

	invariantNoActive     = "no_active_contract"
	invariantAllow        = "active_contract_allow"
	invariantDefaultDeny  = "active_contract_default_deny"
	invariantScannerFloor = "scanner_block_contract_allow"
	invariantShadow       = "mode_shadow_observes"
	invariantCapture      = "mode_capture_observes"
	invariantKillSwitch   = "kill_switch_override"
	connectNoPathRuleNote = "CONNECT uses host-only contract rules because tunnel setup has no path"
	mcpDefaultDenyReason  = "contract_mcp_default_deny"
	mcpSocketGateNote     = "MCP socket upstream addresses are normalized before evaluator input"
)

type transportKind string

const (
	transportKindHTTP    transportKind = "http"
	transportKindMCPURL  transportKind = "mcp_url"
	transportKindMCPTool transportKind = "mcp_tool"
)

type liveLockTransport struct {
	Name            string
	Kind            transportKind
	GateAPI         string
	Method          string
	EffectiveAction string
	AllowedURL      string
	DeniedURL       string
	Notes           []string
}

type liveLockCell struct {
	Transport      liveLockTransport
	Invariant      string
	Mode           contractruntime.Mode
	ScannerVerdict string
	ScannerMatched bool
	ContractState  string
	KillSwitch     bool
	AllowedTarget  bool
	Expected       liveLockExpectation
}

type liveLockExpectation struct {
	Verdict       string
	LiveVerdict   string
	WinningSource string
	RuleID        string
	Reason        string
	Resolved      bool
	DriftMode     string
}

type liveLockDecisionRecord struct {
	Transport       string   `json:"transport"`
	GateAPI         string   `json:"gate_api"`
	Invariant       string   `json:"invariant"`
	Mode            string   `json:"mode"`
	Method          string   `json:"method,omitempty"`
	Target          string   `json:"target,omitempty"`
	EffectiveAction string   `json:"effective_action,omitempty"`
	ScannerVerdict  string   `json:"scanner_verdict"`
	ScannerMatched  bool     `json:"scanner_matched"`
	ContractState   string   `json:"contract_state"`
	KillSwitch      bool     `json:"kill_switch"`
	Verdict         string   `json:"verdict"`
	LiveVerdict     string   `json:"live_verdict"`
	WinningSource   string   `json:"winning_source"`
	PolicySources   []string `json:"policy_sources,omitempty"`
	RuleID          string   `json:"rule_id,omitempty"`
	Reason          string   `json:"reason,omitempty"`
	Resolved        bool     `json:"resolved"`
	DriftMode       string   `json:"drift_mode,omitempty"`
	DriftKind       string   `json:"drift_kind,omitempty"`
	Notes           []string `json:"notes,omitempty"`
}

func liveLockTransports() []liveLockTransport {
	return []liveLockTransport{
		httpTransport("forward_absolute_uri", http.MethodPost, "forward",
			"https://api.example.com/v1/chat", "https://evil.example.com/v1/chat"),
		{
			Name:            "forward_connect",
			Kind:            transportKindHTTP,
			GateAPI:         gateProxyHTTP,
			Method:          http.MethodConnect,
			EffectiveAction: "connect",
			AllowedURL:      "https://api.example.com",
			DeniedURL:       "https://evil.example.com",
			Notes:           []string{connectNoPathRuleNote},
		},
		httpTransport("reverse_proxy", http.MethodPost, "reverse",
			"https://api.example.com/v1/chat", "https://evil.example.com/v1/chat"),
		httpTransport("redirect_refresh", http.MethodGet, "redirect_refresh",
			"https://api.example.com/v1/redirect-target", "https://evil.example.com/v1/redirect-target"),
		httpTransport("intercept_proxy", http.MethodPost, "intercept",
			"https://api.example.com/v1/chat", "https://evil.example.com/v1/chat"),
		httpTransport("fetch_handler", http.MethodGet, "fetch",
			"https://api.example.com/v1/chat", "https://evil.example.com/v1/chat"),
		httpTransport("websocket_handshake", http.MethodGet, "websocket",
			"https://api.example.com/v1/socket", "https://evil.example.com/v1/socket"),
		mcpURLTransport("mcp_http_listener_url", "mcp_listen",
			"https://api.example.com/mcp", "https://evil.example.com/mcp", nil),
		mcpURLTransport("mcp_stdio_http_bridge_url", "mcp_bridge",
			"https://api.example.com/mcp", "https://evil.example.com/mcp", nil),
		mcpURLTransport("mcp_ws_listener_url", "mcp_ws",
			"https://api.example.com/mcp/ws", "https://evil.example.com/mcp/ws", []string{mcpSocketGateNote}),
		{
			Name:            "mcp_tool_call",
			Kind:            transportKindMCPTool,
			GateAPI:         gateRuntimeMCP,
			Method:          "tools/call",
			EffectiveAction: "tool_call",
			AllowedURL:      liveLockAllowedTool,
			DeniedURL:       liveLockDeniedTool,
		},
	}
}

func httpTransport(name, method, action, allowedURL, deniedURL string) liveLockTransport {
	return liveLockTransport{
		Name:            name,
		Kind:            transportKindHTTP,
		GateAPI:         gateProxyHTTP,
		Method:          method,
		EffectiveAction: action,
		AllowedURL:      allowedURL,
		DeniedURL:       deniedURL,
	}
}

func mcpURLTransport(name, action, allowedURL, deniedURL string, notes []string) liveLockTransport {
	return liveLockTransport{
		Name:            name,
		Kind:            transportKindMCPURL,
		GateAPI:         gateRuntimeHTTP,
		Method:          http.MethodPost,
		EffectiveAction: action,
		AllowedURL:      allowedURL,
		DeniedURL:       deniedURL,
		Notes:           append([]string(nil), notes...),
	}
}

func liveLockCells() []liveLockCell {
	transports := liveLockTransports()
	cells := make([]liveLockCell, 0, len(transports)*7)
	for _, tr := range transports {
		allowRule := allowRuleID(tr)
		defaultDenyReason := string(blockreason.ContractDefaultDeny)
		if tr.Kind == transportKindMCPTool {
			defaultDenyReason = mcpDefaultDenyReason
		}
		cells = append(cells,
			liveLockCell{
				Transport:      tr,
				Invariant:      invariantNoActive,
				Mode:           contractruntime.ModeLive,
				ScannerVerdict: config.ActionAllow,
				ContractState:  contractStateNone,
				AllowedTarget:  true,
				Expected: liveLockExpectation{
					Verdict:       config.ActionAllow,
					LiveVerdict:   config.ActionAllow,
					WinningSource: contractruntime.WinningSourceScanner,
				},
			},
			liveLockCell{
				Transport:      tr,
				Invariant:      invariantAllow,
				Mode:           contractruntime.ModeLive,
				ScannerVerdict: config.ActionAllow,
				ContractState:  contractStateAllow,
				AllowedTarget:  true,
				Expected: liveLockExpectation{
					Verdict:       config.ActionAllow,
					LiveVerdict:   config.ActionAllow,
					WinningSource: contractruntime.WinningSourceContract,
					RuleID:        allowRule,
					Resolved:      true,
				},
			},
			liveLockCell{
				Transport:      tr,
				Invariant:      invariantDefaultDeny,
				Mode:           contractruntime.ModeLive,
				ScannerVerdict: config.ActionAllow,
				ContractState:  contractStateDefaultDeny,
				AllowedTarget:  false,
				Expected: liveLockExpectation{
					Verdict:       config.ActionBlock,
					LiveVerdict:   config.ActionBlock,
					WinningSource: contractruntime.WinningSourceContract,
					Reason:        defaultDenyReason,
					Resolved:      true,
					DriftMode:     string(contractruntime.ModeLive),
				},
			},
			liveLockCell{
				Transport:      tr,
				Invariant:      invariantScannerFloor,
				Mode:           contractruntime.ModeLive,
				ScannerVerdict: config.ActionBlock,
				ScannerMatched: true,
				ContractState:  contractStateScannerFloor,
				AllowedTarget:  true,
				Expected: liveLockExpectation{
					Verdict:       config.ActionBlock,
					LiveVerdict:   config.ActionBlock,
					WinningSource: contractruntime.WinningSourceScanner,
					Resolved:      true,
				},
			},
			liveLockCell{
				Transport:      tr,
				Invariant:      invariantShadow,
				Mode:           contractruntime.ModeShadow,
				ScannerVerdict: config.ActionAllow,
				ContractState:  contractStateObserve,
				AllowedTarget:  false,
				Expected: liveLockExpectation{
					Verdict:       config.ActionAllow,
					LiveVerdict:   config.ActionBlock,
					WinningSource: contractruntime.WinningSourceScanner,
					Reason:        string(blockreason.ContractObservedOnly),
					Resolved:      true,
					DriftMode:     string(contractruntime.ModeShadow),
				},
			},
			liveLockCell{
				Transport:      tr,
				Invariant:      invariantCapture,
				Mode:           contractruntime.ModeCapture,
				ScannerVerdict: config.ActionAllow,
				ContractState:  contractStateObserve,
				AllowedTarget:  false,
				Expected: liveLockExpectation{
					Verdict:       config.ActionAllow,
					LiveVerdict:   config.ActionBlock,
					WinningSource: contractruntime.WinningSourceScanner,
					Reason:        string(blockreason.ContractObservedOnly),
					Resolved:      true,
					DriftMode:     string(contractruntime.ModeCapture),
				},
			},
			liveLockCell{
				Transport:      tr,
				Invariant:      invariantKillSwitch,
				Mode:           contractruntime.ModeLive,
				ScannerVerdict: config.ActionAllow,
				ContractState:  contractStateKillSwitch,
				KillSwitch:     true,
				AllowedTarget:  true,
				Expected: liveLockExpectation{
					Verdict:       config.ActionBlock,
					LiveVerdict:   config.ActionBlock,
					WinningSource: contractruntime.WinningSourceKillSwitch,
					Reason:        string(blockreason.KillSwitchActive),
					Resolved:      true,
				},
			},
		)
	}
	return cells
}

func TestLiveLockReplayHarness_TransportMatrixMatchesGolden(t *testing.T) {
	records := runLiveLockMatrix(t)
	if got, want := len(records), 77; got != want {
		t.Fatalf("matrix records = %d, want %d", got, want)
	}
	got := marshalLiveLockRecords(t, records)
	assertLiveLockGolden(t, liveLockGoldenFile, got)
}

func TestLiveLockReplayHarness_EvaluatorEnforcesScannerFloor(t *testing.T) {
	// Production transports usually early-return on scanner blocks before
	// invoking the contract gate. This test exercises the evaluator's
	// defensive scanner-floor branch for non-early-return entry points and
	// future gate call sites.
	for _, cell := range liveLockCells() {
		cell := cell
		if cell.Invariant != invariantScannerFloor {
			continue
		}
		t.Run(cellName(cell), func(t *testing.T) {
			record := replayLiveLockCell(t, cell)
			if record.Verdict != config.ActionBlock {
				t.Fatalf("%s scanner floor verdict = %q, want block", record.Transport, record.Verdict)
			}
			if record.WinningSource != contractruntime.WinningSourceScanner {
				t.Fatalf("%s scanner floor winning_source = %q, want scanner", record.Transport, record.WinningSource)
			}
			if record.RuleID != "" {
				t.Fatalf("%s scanner floor rule_id = %q, want empty", record.Transport, record.RuleID)
			}
		})
	}
}

func TestLiveLockReplayHarness_KillSwitchOverridesEveryTransport(t *testing.T) {
	// OR-composition across config, API, signal, and sentinel sources lives in
	// internal/killswitch. The evaluator contract is the boolean floor: once a
	// caller reports KillSwitchActive=true, every gate must block.
	for _, cell := range liveLockCells() {
		cell := cell
		if cell.Invariant != invariantKillSwitch {
			continue
		}
		t.Run(cellName(cell), func(t *testing.T) {
			record := replayLiveLockCell(t, cell)
			if record.Verdict != config.ActionBlock {
				t.Fatalf("%s kill switch verdict = %q, want block", record.Transport, record.Verdict)
			}
			if record.WinningSource != contractruntime.WinningSourceKillSwitch {
				t.Fatalf("%s kill switch winning_source = %q, want kill_switch", record.Transport, record.WinningSource)
			}
			if record.Reason != string(blockreason.KillSwitchActive) {
				t.Fatalf("%s kill switch reason = %q, want %s", record.Transport, record.Reason, blockreason.KillSwitchActive)
			}
		})
	}
}

func runLiveLockMatrix(t *testing.T) []liveLockDecisionRecord {
	t.Helper()
	cells := liveLockCells()
	records := make([]liveLockDecisionRecord, 0, len(cells))
	for _, cell := range cells {
		cell := cell
		t.Run(cellName(cell), func(t *testing.T) {
			records = append(records, replayLiveLockCell(t, cell))
		})
	}
	return records
}

func cellName(cell liveLockCell) string {
	return cell.Transport.Name + "/" + cell.Invariant
}

func replayLiveLockCell(t *testing.T, cell liveLockCell) liveLockDecisionRecord {
	t.Helper()
	record, err := evaluateLiveLockCell(t, cell)
	if err != nil {
		t.Fatalf("%s/%s: %v", cell.Transport.Name, cell.Invariant, err)
	}
	assertLiveLockExpectation(t, cell, record)
	return record
}

func evaluateLiveLockCell(t *testing.T, cell liveLockCell) (liveLockDecisionRecord, error) {
	t.Helper()
	switch cell.Transport.Kind {
	case transportKindHTTP:
		return evaluateProxyHTTPCell(t, cell)
	case transportKindMCPURL:
		return evaluateRuntimeHTTPCell(t, cell)
	case transportKindMCPTool:
		return evaluateRuntimeMCPCell(t, cell)
	default:
		t.Fatalf("unknown transport kind %q", cell.Transport.Kind)
		return liveLockDecisionRecord{}, nil
	}
}

func evaluateProxyHTTPCell(t *testing.T, cell liveLockCell) (liveLockDecisionRecord, error) {
	t.Helper()
	var loader *contractruntime.Loader
	if cell.ContractState != contractStateNone {
		loader = liveLockLoader(t, cell.Mode, liveLockHTTPRule(cell.Transport))
	}
	target := cellTarget(cell)
	gate, err := proxy.EvaluateGate(proxy.ContractGateInput{
		Loader:           loader,
		Agent:            liveLockAgent,
		URL:              target,
		Method:           cell.Transport.Method,
		EffectiveAction:  cell.Transport.EffectiveAction,
		ScannerVerdict:   cell.ScannerVerdict,
		ScannerMatched:   cell.ScannerMatched,
		KillSwitchActive: cell.KillSwitch,
		Transport:        cell.Transport.Name,
	})
	if err != nil {
		return liveLockDecisionRecord{}, err
	}
	return recordFromGate(cell, target, gate), nil
}

func evaluateRuntimeHTTPCell(t *testing.T, cell liveLockCell) (liveLockDecisionRecord, error) {
	t.Helper()
	resolved := resolvedForCell(t, cell, liveLockHTTPRule(cell.Transport))
	target := cellTarget(cell)
	decision, err := contractruntime.EvaluateHTTP(contractruntime.EvaluateOptions{
		Resolved: resolved,
		Request: contractruntime.HTTPRequest{
			URL:             target,
			Method:          cell.Transport.Method,
			EffectiveAction: cell.Transport.EffectiveAction,
		},
		Mode:             cell.Mode,
		KillSwitchActive: cell.KillSwitch,
		ScannerVerdict:   cell.ScannerVerdict,
		ScannerMatched:   cell.ScannerMatched,
	})
	if err != nil {
		return liveLockDecisionRecord{}, err
	}
	return recordFromDecision(cell, target, decision, resolved != nil), nil
}

func evaluateRuntimeMCPCell(t *testing.T, cell liveLockCell) (liveLockDecisionRecord, error) {
	t.Helper()
	resolved := resolvedForCell(t, cell, liveLockMCPRule(allowRuleID(cell.Transport)))
	decision, err := contractruntime.EvaluateMCP(contractruntime.EvaluateMCPOptions{
		Resolved: resolved,
		Request: contractruntime.MCPRequest{
			Server:   liveLockMCPServer,
			ToolName: cellTarget(cell),
			ToolArgs: map[string]any{},
		},
		Mode:             cell.Mode,
		KillSwitchActive: cell.KillSwitch,
		ScannerVerdict:   cell.ScannerVerdict,
		ScannerMatched:   cell.ScannerMatched,
	})
	if err != nil {
		return liveLockDecisionRecord{}, err
	}
	return recordFromDecision(cell, cellTarget(cell), decision, resolved != nil), nil
}

func recordFromGate(cell liveLockCell, target string, gate proxy.ContractGateOutput) liveLockDecisionRecord {
	record := baseRecord(cell, target)
	record.Verdict = gate.Verdict
	record.LiveVerdict = gate.LiveVerdict
	record.PolicySources = gate.PolicySources
	record.WinningSource = gate.WinningSource
	record.RuleID = gate.RuleID
	record.Reason = gate.Reason
	record.Resolved = gate.Resolved != nil
	if gate.Drift != nil {
		record.DriftMode = string(gate.Drift.Mode)
		record.DriftKind = gate.Drift.Kind
	}
	return record
}

func recordFromDecision(cell liveLockCell, target string, decision contractruntime.Decision, resolved bool) liveLockDecisionRecord {
	record := baseRecord(cell, target)
	record.Verdict = decision.Verdict
	record.LiveVerdict = decision.LiveVerdict
	record.PolicySources = decision.PolicySources
	record.WinningSource = decision.WinningSource
	record.RuleID = decision.RuleID
	record.Reason = decision.Reason
	record.Resolved = resolved
	if decision.Drift != nil {
		record.DriftMode = string(decision.Drift.Mode)
		record.DriftKind = decision.Drift.Kind
	}
	return record
}

func baseRecord(cell liveLockCell, target string) liveLockDecisionRecord {
	return liveLockDecisionRecord{
		Transport:       cell.Transport.Name,
		GateAPI:         cell.Transport.GateAPI,
		Invariant:       cell.Invariant,
		Mode:            string(cell.Mode),
		Method:          cell.Transport.Method,
		Target:          target,
		EffectiveAction: cell.Transport.EffectiveAction,
		ScannerVerdict:  cell.ScannerVerdict,
		ScannerMatched:  cell.ScannerMatched,
		ContractState:   cell.ContractState,
		KillSwitch:      cell.KillSwitch,
		Notes:           append([]string(nil), cell.Transport.Notes...),
	}
}

func assertLiveLockExpectation(t *testing.T, cell liveLockCell, record liveLockDecisionRecord) {
	t.Helper()
	expect := cell.Expected
	if record.Verdict != expect.Verdict {
		t.Fatalf("%s/%s verdict = %q, want %q", cell.Transport.Name, cell.Invariant, record.Verdict, expect.Verdict)
	}
	if record.LiveVerdict != expect.LiveVerdict {
		t.Fatalf("%s/%s live_verdict = %q, want %q", cell.Transport.Name, cell.Invariant, record.LiveVerdict, expect.LiveVerdict)
	}
	if record.WinningSource != expect.WinningSource {
		t.Fatalf("%s/%s winning_source = %q, want %q", cell.Transport.Name, cell.Invariant, record.WinningSource, expect.WinningSource)
	}
	if record.RuleID != expect.RuleID {
		t.Fatalf("%s/%s rule_id = %q, want %q", cell.Transport.Name, cell.Invariant, record.RuleID, expect.RuleID)
	}
	if record.Reason != expect.Reason {
		t.Fatalf("%s/%s reason = %q, want %q", cell.Transport.Name, cell.Invariant, record.Reason, expect.Reason)
	}
	if record.Resolved != expect.Resolved {
		t.Fatalf("%s/%s resolved = %v, want %v", cell.Transport.Name, cell.Invariant, record.Resolved, expect.Resolved)
	}
	if record.DriftMode != expect.DriftMode {
		t.Fatalf("%s/%s drift_mode = %q, want %q", cell.Transport.Name, cell.Invariant, record.DriftMode, expect.DriftMode)
	}
}

func resolvedForCell(t *testing.T, cell liveLockCell, rule contract.Rule) *contractruntime.ResolvedContract {
	t.Helper()
	if cell.ContractState == contractStateNone {
		return nil
	}
	loader := liveLockLoader(t, cell.Mode, rule)
	active := loader.Current()
	if active == nil {
		t.Fatal("active contract missing")
	}
	resolved, ok := active.Resolve(liveLockAgent)
	if !ok {
		t.Fatal("contract did not resolve for live-lock agent")
	}
	return resolved
}

func liveLockLoader(t *testing.T, mode contractruntime.Mode, rules ...contract.Rule) *contractruntime.Loader {
	t.Helper()
	fixture := contractruntimetest.NewFixture(t)
	storeDir := t.TempDir()
	env := contractruntimetest.Env()
	contractruntimetest.WriteSignedActiveStore(t, fixture, storeDir, contractruntimetest.ActiveStoreOptions{
		Agent:       liveLockAgent,
		Rules:       rules,
		Generation:  1,
		PriorHash:   "sha256:genesis",
		Environment: env,
	})
	loader, err := contractruntime.NewLoader(contractruntime.LoaderOptions{
		StoreDir:              storeDir,
		RosterPath:            fixture.RosterPath(),
		PinnedRootFingerprint: fixture.RootFingerprint(),
		Environment:           env,
		MinSignatures:         1,
		Mode:                  mode,
	}, nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	return loader
}

func liveLockHTTPRule(tr liveLockTransport) contract.Rule {
	ruleID := allowRuleID(tr)
	selector := map[string]any{
		"host":    map[string]any{livelockJSONKeyValue: liveLockHTTPHost},
		"methods": []any{tr.Method},
	}
	if tr.Method != http.MethodConnect {
		selector["paths"] = []any{map[string]any{livelockJSONKeyValue: pathForRule(tr.AllowedURL)}}
	}
	if tr.EffectiveAction != "" {
		selector["effective_action"] = tr.EffectiveAction
	}
	return contract.Rule{
		RuleID:               ruleID,
		DisplayName:          ruleID,
		RuleKind:             contract.RuleKindHTTPDestination,
		LifecycleState:       contract.LifecycleEnforce,
		RequiredCaptureGrade: contract.CaptureGradeFull,
		ObservedCaptureGrade: contract.CaptureGradeFull,
		Confidence:           livelockConfidenceOne,
		WilsonLower:          livelockConfidenceOne,
		Observation:          map[string]any{},
		Selector:             selector,
		Rationale:            map[string]any{},
		RecurringSupport:     map[string]any{},
		OpportunityHealth:    map[string]any{},
	}
}

func liveLockMCPRule(ruleID string) contract.Rule {
	return contract.Rule{
		RuleID:               ruleID,
		DisplayName:          ruleID,
		RuleKind:             contract.RuleKindMCPToolCall,
		LifecycleState:       contract.LifecycleEnforce,
		RequiredCaptureGrade: contract.CaptureGradeFull,
		ObservedCaptureGrade: contract.CaptureGradeFull,
		Confidence:           livelockConfidenceOne,
		WilsonLower:          livelockConfidenceOne,
		Observation:          map[string]any{},
		Selector: map[string]any{
			"server": map[string]any{livelockJSONKeyValue: liveLockMCPServer},
			"tool":   map[string]any{livelockJSONKeyValue: liveLockAllowedTool},
		},
		Rationale:         map[string]any{},
		RecurringSupport:  map[string]any{},
		OpportunityHealth: map[string]any{},
	}
}

func allowRuleID(tr liveLockTransport) string {
	return "r-" + tr.Name + "-allow"
}

func cellTarget(cell liveLockCell) string {
	if cell.AllowedTarget {
		return cell.Transport.AllowedURL
	}
	return cell.Transport.DeniedURL
}

func pathForRule(rawURL string) string {
	switch rawURL {
	case "https://api.example.com/v1/redirect-target":
		return "/v1/redirect-target"
	case "https://api.example.com/v1/socket":
		return "/v1/socket"
	case "https://api.example.com/mcp":
		return "/mcp"
	case "https://api.example.com/mcp/ws":
		return "/mcp/ws"
	default:
		return "/v1/chat"
	}
}

func marshalLiveLockRecords(t *testing.T, records []liveLockDecisionRecord) []byte {
	t.Helper()
	out, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		t.Fatalf("marshal records: %v", err)
	}
	return append(out, '\n')
}

func assertLiveLockGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join(liveLockGoldenDir, name)
	if *updateLiveLockGoldens {
		if err := os.MkdirAll(liveLockGoldenDir, 0o750); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("write golden %s: %v", name, err)
		}
		return
	}
	want, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to create)", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("golden %s drifted; rerun with -update after reviewing the diff.\n--- want\n%s\n--- got\n%s",
			name, previewGolden(want), previewGolden(got))
	}
}

func previewGolden(data []byte) string {
	const limit = 1200
	if len(data) <= limit {
		return string(data)
	}
	return string(data[:limit]) + "..."
}
