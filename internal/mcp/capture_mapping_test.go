// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCaptureSessionIDHashesUnsafeTransport(t *testing.T) {
	t.Parallel()

	if got := captureSessionID(""); got != "mcp" {
		t.Fatalf("empty transport session id = %q, want mcp", got)
	}
	if got := captureSessionID("stdio"); got != "mcp-stdio" {
		t.Fatalf("safe transport session id = %q", got)
	}
	if got := captureSessionIDOriginal("stdio"); got != "" {
		t.Fatalf("safe transport leaked original = %q", got)
	}

	unsafe := `stdio/../evil`
	safe := captureSessionID(unsafe)
	if !strings.HasPrefix(safe, "mcp-") || strings.Contains(safe, "..") || strings.ContainsAny(safe, `/\`) {
		t.Fatalf("unsafe transport was not hashed: %q", safe)
	}
	if got := captureSessionIDOriginal(unsafe); got != "mcp-"+unsafe {
		t.Fatalf("original key = %q, want mcp-%s", got, unsafe)
	}
}

func TestCaptureFindingsConvertersEmptyAndMapped(t *testing.T) {
	t.Parallel()

	if got := dlpMatchesToFindings(nil); got != nil {
		t.Fatalf("empty DLP findings = %+v", got)
	}
	dlp := dlpMatchesToFindingsWithAction([]scanner.TextDLPMatch{{
		PatternName: "AWS Access ID",
		Severity:    "high",
		Encoded:     "base64",
	}}, config.ActionStrip)
	if len(dlp) != 1 || dlp[0].Kind != capture.KindDLP || dlp[0].Action != config.ActionStrip || dlp[0].Encoded != "base64" {
		t.Fatalf("DLP findings = %+v", dlp)
	}

	if got := responseMatchesToFindings(nil, config.ActionBlock); got != nil {
		t.Fatalf("empty injection findings = %+v", got)
	}
	inj := responseMatchesToFindings([]scanner.ResponseMatch{{
		PatternName: "Prompt Injection",
		MatchText:   "ignore previous",
	}}, config.ActionWarn)
	if len(inj) != 1 || inj[0].Kind != capture.KindInjection || inj[0].Action != config.ActionWarn {
		t.Fatalf("injection findings = %+v", inj)
	}

	if got := urlFindingsToCapture(nil); got != nil {
		t.Fatalf("empty URL findings = %+v", got)
	}
	urls := urlFindingsToCapture([]scanner.Result{{Scanner: scanner.ScannerSSRF, Reason: "private ip"}})
	if len(urls) != 1 || urls[0].Kind != capture.KindURL || urls[0].Action != config.ActionBlock {
		t.Fatalf("URL findings = %+v", urls)
	}

	if got := addressFindingsToCapture(nil); got != nil {
		t.Fatalf("empty address findings = %+v", got)
	}
	addrs := addressFindingsToCapture([]addressprotect.Finding{{
		Explanation: "wallet",
		Action:      config.ActionBlock,
	}})
	if len(addrs) != 1 || addrs[0].Kind != capture.KindAddressProtection || addrs[0].AddrVerdict != "wallet" {
		t.Fatalf("address findings = %+v", addrs)
	}
}

func TestToolScanMatchesToFindingsKinds(t *testing.T) {
	t.Parallel()

	if got := toolScanMatchesToFindings(nil); got != nil {
		t.Fatalf("empty tool findings = %+v", got)
	}
	got := toolScanMatchesToFindings([]tools.ToolScanMatch{{
		ToolName:      "fetch",
		ToolPoison:    []string{"hidden"},
		Injection:     []scanner.ResponseMatch{{PatternName: "Prompt Injection", MatchText: "ignore"}},
		DriftDetected: true,
		DriftDetail:   "schema",
	}})
	if len(got) != 3 {
		t.Fatalf("tool findings = %+v, want 3", got)
	}
	if got[0].Kind != capture.KindToolPoison || got[1].Kind != capture.KindInjection || got[2].Kind != capture.KindToolDrift {
		t.Fatalf("kinds = %+v", got)
	}
}

func TestMCPCaptureOutcomeAndRedirectAttribution(t *testing.T) {
	t.Parallel()

	if got := captureOutcome(config.ActionBlock, true); got != capture.OutcomeClean {
		t.Fatalf("clean outcome = %q", got)
	}
	if got := captureOutcome("not-an-action", false); got != capture.OutcomeBlocked {
		t.Fatalf("unknown outcome = %q, want blocked", got)
	}

	pat, sev := redirectResponseAttribution(jsonrpc.ScanVerdict{
		Matches: []scanner.ResponseMatch{{PatternName: "Prompt Injection"}},
	})
	if pat != "Prompt Injection" || sev != config.SeverityHigh {
		t.Fatalf("inject attribution = %q %q", pat, sev)
	}
	pat, sev = redirectResponseAttribution(jsonrpc.ScanVerdict{
		DLPMatches: []scanner.TextDLPMatch{{PatternName: "AWS Access ID", Severity: "critical"}},
	})
	if pat != "AWS Access ID" || sev != "critical" {
		t.Fatalf("dlp attribution = %q %q", pat, sev)
	}
	pat, sev = redirectResponseAttribution(jsonrpc.ScanVerdict{})
	if pat != "" || sev != "" {
		t.Fatalf("empty attribution = %q %q", pat, sev)
	}
}

func TestHasNonIdentityEncoding(t *testing.T) {
	t.Parallel()

	if hasNonIdentityEncoding("") || hasNonIdentityEncoding("identity") || hasNonIdentityEncoding("identity, identity") {
		t.Fatal("identity-only encoding treated as compressed")
	}
	if !hasNonIdentityEncoding("gzip") || !hasNonIdentityEncoding("identity, gzip") {
		t.Fatal("gzip encoding not treated as non-identity")
	}
}
