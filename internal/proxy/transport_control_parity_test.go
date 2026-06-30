// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	parityCovered       = "covered"
	parityNotApplicable = "not_applicable"
)

type transportControlCoverage struct {
	Control   string
	Transport string
	State     string
	File      string
	Test      string
	Exception string
}

// transportControlParityMatrix is an executable index of sibling coverage for
// controls that repeatedly drift across transports. Each covered cell points at
// the runtime regression test that proves it. Exceptions must state why the
// control has no equivalent surface on that transport.
var transportControlParityMatrix = []transportControlCoverage{
	{
		Control:   "response_suppression_exact_match",
		Transport: TransportFetch,
		State:     parityCovered,
		File:      "internal/proxy/response_suppress_cascade_test.go",
		Test:      "TestFetchSuppressedMetricCountsHiddenAndVisibleFindings",
	},
	{
		Control:   "response_suppression_exact_match",
		Transport: TransportForward,
		State:     parityCovered,
		File:      "internal/proxy/forward_test.go",
		Test:      "TestForwardHTTPResponseInjection_SuppressedPassesThrough",
	},
	{
		Control:   "response_suppression_exact_match",
		Transport: TransportConnect,
		State:     parityCovered,
		File:      "internal/proxy/intercept_test.go",
		Test:      "TestInterceptTunnel_SuppressedInjectionPassesThrough",
	},
	{
		Control:   "response_suppression_exact_match",
		Transport: TransportReverse,
		State:     parityCovered,
		File:      "internal/proxy/reverse_test.go",
		Test:      "TestReverseProxy_SuppressedInjectionPassesThrough",
	},
	{
		Control:   "response_suppression_exact_match",
		Transport: TransportWS,
		State:     parityCovered,
		File:      "internal/proxy/response_suppress_cascade_test.go",
		Test:      "TestWebSocketResponseSuppressionPassesMatchingFinding",
	},
	{
		Control:   "response_suppression_exact_match",
		Transport: "mcp_stdio",
		State:     parityCovered,
		File:      "internal/mcp/scan_suppress_test.go",
		Test:      "TestScanResponseOpts_PerServerSuppression",
	},
	{
		Control:   "response_suppression_exact_match",
		Transport: "mcp_sse",
		State:     parityCovered,
		File:      "internal/mcp/sse_generic_test.go",
		Test:      "TestScanGenericSSEStream_SuppressRuleSkipsFinding",
	},
	{
		Control:   "response_suppression_decoded_cascade",
		Transport: TransportFetch,
		State:     parityCovered,
		File:      "internal/proxy/response_suppress_cascade_test.go",
		Test:      "TestFetchResponseSuppressionDoesNotMaskEncodedFinding",
	},
	{
		Control:   "response_suppression_decoded_cascade",
		Transport: TransportForward,
		State:     parityCovered,
		File:      "internal/proxy/response_suppress_cascade_test.go",
		Test:      "TestForwardResponseSuppressionDoesNotMaskEncodedFinding",
	},
	{
		Control:   "response_suppression_decoded_cascade",
		Transport: TransportConnect,
		State:     parityCovered,
		File:      "internal/proxy/response_suppress_cascade_test.go",
		Test:      "TestInterceptResponseSuppressionDoesNotMaskEncodedFinding",
	},
	{
		Control:   "response_suppression_decoded_cascade",
		Transport: TransportReverse,
		State:     parityCovered,
		File:      "internal/proxy/response_suppress_cascade_test.go",
		Test:      "TestReverseResponseSuppressionDoesNotMaskEncodedFinding",
	},
	{
		Control:   "response_suppression_decoded_cascade",
		Transport: TransportWS,
		State:     parityCovered,
		File:      "internal/proxy/response_suppress_cascade_test.go",
		Test:      "TestWebSocketResponseSuppressionDoesNotMaskEncodedFinding",
	},
	{
		Control:   "response_suppression_decoded_cascade",
		Transport: "mcp_stdio",
		State:     parityCovered,
		File:      "internal/mcp/scan_suppress_test.go",
		Test:      "TestScanResponseOpts_SuppressedFirstPassDoesNotMaskDecodedPattern",
	},
	{
		Control:   "response_suppression_decoded_cascade",
		Transport: "mcp_sse",
		State:     parityCovered,
		File:      "internal/mcp/sse_generic_test.go",
		Test:      "TestScanGenericSSEStream_SuppressionDoesNotMaskEncodedFinding",
	},
	{
		Control:   "size_exempt_in_cap_response_scan",
		Transport: TransportForward,
		State:     parityCovered,
		File:      "internal/proxy/forward_test.go",
		Test:      "TestForwardHTTPResponseInjection_SizeExemptDomainStillScanned",
	},
	{
		Control:   "size_exempt_in_cap_response_scan",
		Transport: TransportConnect,
		State:     parityCovered,
		File:      "internal/proxy/intercept_test.go",
		Test:      "TestInterceptTunnel_ResponseInjectionSizeExemptDomainStillScanned",
	},
	{
		Control:   "size_exempt_in_cap_response_scan",
		Transport: TransportFetch,
		State:     parityNotApplicable,
		Exception: "fetch has no response_scanning.size_exempt_domains branch",
	},
	{
		Control:   "size_exempt_in_cap_response_scan",
		Transport: TransportReverse,
		State:     parityNotApplicable,
		Exception: "reverse proxy does not consume response_scanning.size_exempt_domains",
	},
	{
		Control:   "size_exempt_in_cap_response_scan",
		Transport: TransportWS,
		State:     parityNotApplicable,
		Exception: "WebSocket frames are bounded by websocket_proxy.max_message_bytes, not response size exemptions",
	},
	{
		Control:   "request_split_dlp",
		Transport: "http_body_scanner",
		State:     parityCovered,
		File:      "internal/proxy/bodyscan_test.go",
		Test:      "TestScanRequestBody_SplitSecretAcrossFields",
	},
	{
		Control:   "request_split_dlp",
		Transport: TransportForward,
		State:     parityCovered,
		File:      "internal/proxy/bodyscan_test.go",
		Test:      "TestForwardProxy_SplitSecretHeaders_Blocked",
	},
	{
		Control:   "request_split_dlp",
		Transport: TransportWS,
		State:     parityCovered,
		File:      "internal/proxy/websocket_test.go",
		Test:      "TestWSProxy_CrossMessageDLP_SplitKey",
	},
	{
		Control:   "request_split_dlp",
		Transport: "mcp_stdio",
		State:     parityCovered,
		File:      "internal/mcp/input_test.go",
		Test:      "TestScanRequest_SplitSecretDeterministic",
	},
	{
		Control:   "request_split_dlp",
		Transport: "mcp_http_listener",
		State:     parityCovered,
		File:      "internal/mcp/pipeline_parity_test.go",
		Test:      "TestHTTPListener_ParitySplitSecret",
	},
	{
		Control:   "request_split_dlp",
		Transport: "a2a",
		State:     parityCovered,
		File:      "internal/mcp/a2a_scan_test.go",
		Test:      "TestScanA2ARequestBody_SplitSecretFallback",
	},
	{
		Control:   "cross_transport_fragment_dlp",
		Transport: "fetch_forward_shared_buffer",
		State:     parityCovered,
		File:      "internal/proxy/cee_bypass_test.go",
		Test:      "TestCEEBypass_CrossTransportSharesBuffer",
	},
	{
		Control:   "cross_transport_fragment_dlp",
		Transport: "mcp",
		State:     parityCovered,
		File:      "internal/mcp/cee_test.go",
		Test:      "TestCeeRecordMCP_FragmentDLPBlock",
	},
}

func TestTransportControlParityMatrix(t *testing.T) {
	root := parityRepoRoot(t)
	seen := make(map[string]struct{}, len(transportControlParityMatrix))
	coveredByControl := make(map[string]int)

	for _, row := range transportControlParityMatrix {
		name := row.Control + "/" + row.Transport
		if _, ok := seen[name]; ok {
			t.Fatalf("duplicate parity matrix row: %s", name)
		}
		seen[name] = struct{}{}

		switch row.State {
		case parityCovered:
			coveredByControl[row.Control]++
			assertParityEvidenceExists(t, root, row)
		case parityNotApplicable:
			if strings.TrimSpace(row.Exception) == "" {
				t.Fatalf("%s: not-applicable row must explain why the control has no sibling surface", name)
			}
			if row.File != "" || row.Test != "" {
				t.Fatalf("%s: not-applicable row must not point at executable evidence", name)
			}
		default:
			t.Fatalf("%s: unknown matrix state %q", name, row.State)
		}
	}

	for control, count := range coveredByControl {
		if count < 2 {
			t.Fatalf("%s: parity control has only %d covered transport(s)", control, count)
		}
	}
}

func assertParityEvidenceExists(t *testing.T, root string, row transportControlCoverage) {
	t.Helper()
	if row.File == "" || row.Test == "" {
		t.Fatalf("%s/%s: covered row must name file and test", row.Control, row.Transport)
	}
	evidencePath := filepath.Clean(filepath.Join(root, row.File))
	rel, err := filepath.Rel(root, evidencePath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		t.Fatalf("%s/%s: evidence file %s escapes repo root", row.Control, row.Transport, row.File)
	}
	// evidencePath is filepath.Clean'd and confirmed (via filepath.Rel) to stay
	// inside the repo root above, so this read is not a file-inclusion vector.
	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("%s/%s: read evidence file %s: %v", row.Control, row.Transport, row.File, err)
	}
	needle := "func " + row.Test + "("
	if !strings.Contains(string(data), needle) {
		t.Fatalf("%s/%s: evidence file %s does not define %s", row.Control, row.Transport, row.File, row.Test)
	}
}

func parityRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
