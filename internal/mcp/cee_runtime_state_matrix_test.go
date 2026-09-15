// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

const (
	ceeMatrixAWSFirst  = "AKI" + "A"
	ceeMatrixAWSSecond = testMCPAWSKeySuffix
	ceeMatrixGHPFirst  = "gh" + "p_"
	ceeMatrixGHPSecond = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
)

func newCEERuntimeMatrixDeps(t *testing.T) *CEEDeps {
	t.Helper()
	cee := NewCEEDeps(config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionBlock,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled: true, MaxBufferBytes: 4096, WindowMinutes: 5,
		},
	}, metrics.New())
	t.Cleanup(cee.Close)
	return cee
}

// TestMCPCEERuntimeStateMatrix proves stateful CEE enforcement through both
// request runtimes. Each sequence carries a benign request and an allowed
// fragment before the denial, so a stopped input loop cannot satisfy the test.
func TestMCPCEERuntimeStateMatrix(t *testing.T) {
	first := mcpChunkedCEERequest(2, ceeMatrixAWSFirst)
	second := mcpChunkedCEERequest(3, ceeMatrixAWSSecond)
	laterFirst := mcpSingletonCEERequest(4, "payload", "later_integrity_checker", ceeMatrixGHPFirst)
	laterSecond := mcpSingletonCEERequest(5, "payload", "later_integrity_checker", ceeMatrixGHPSecond)
	benign := mcpSingletonCEERequest(1, "note", "status_checker", "routine-check")

	t.Run("stdio forwards useful history and blocks each completed stream", func(t *testing.T) {
		cee := newCEERuntimeMatrixDeps(t)
		var forwarded, log bytes.Buffer
		blockedCh := make(chan BlockedRequest, 5)
		opts := MCPProxyOpts{Scanner: testMCPScanner(), CEE: cee, Transport: transportMCPStdio}
		t.Cleanup(opts.Scanner.Close)

		ForwardScannedInput(
			transport.NewStdioReader(strings.NewReader(strings.Join([]string{
				string(benign), string(first), string(second), string(laterFirst), string(laterSecond),
			}, "\n")+"\n")),
			transport.NewStdioWriter(&forwarded), &log, config.ActionBlock, config.ActionBlock,
			blockedCh, nil, nil, opts,
		)

		var blocks []BlockedRequest
		for block := range blockedCh {
			blocks = append(blocks, block)
		}
		if !strings.Contains(forwarded.String(), `"id":1`) || !strings.Contains(forwarded.String(), `"id":2`) || !strings.Contains(forwarded.String(), `"id":4`) {
			t.Fatalf("forwarded requests = %q, want benign and both allowed first fragments", forwarded.String())
		}
		if strings.Contains(forwarded.String(), `"id":3`) || strings.Contains(forwarded.String(), `"id":5`) {
			t.Fatalf("blocked CEE requests reached upstream: %q", forwarded.String())
		}
		if len(blocks) != 2 {
			t.Fatalf("CEE blocks = %d, want both completed cross-request streams blocked", len(blocks))
		}
		for _, block := range blocks {
			if block.ErrorCode != mcpCEEBlockErrorCode {
				t.Fatalf("block = %+v, want CEE error code %d", block, mcpCEEBlockErrorCode)
			}
		}
	})

	t.Run("HTTP forwards useful history and blocks each completed stream", func(t *testing.T) {
		cee := newCEERuntimeMatrixDeps(t)
		opts := MCPProxyOpts{Scanner: testMCPScanner(), CEE: cee, Transport: transportMCPHTTP}
		t.Cleanup(opts.Scanner.Close)
		for _, request := range []struct {
			msg       []byte
			wantBlock bool
		}{
			{benign, false}, {first, false}, {second, true}, {laterFirst, false}, {laterSecond, true},
		} {
			decision := scanHTTPInputDecision(request.msg, io.Discard, "matrix-session", "matrix-audit", opts)
			if (decision.Blocked != nil) != request.wantBlock {
				t.Fatalf("HTTP request %s blocked = %v, want %v", request.msg, decision.Blocked != nil, request.wantBlock)
			}
			if request.wantBlock {
				if decision.Blocked.ErrorCode != mcpCEEBlockErrorCode {
					t.Fatalf("HTTP CEE block = %+v, want error code %d", decision.Blocked, mcpCEEBlockErrorCode)
				}
				continue
			}
			if !bytes.Equal(decision.ForwardMessage, request.msg) {
				t.Fatalf("HTTP allowed request was not forwarded intact: got %q, want %q", decision.ForwardMessage, request.msg)
			}
		}
	})

	t.Run("HTTP session identities remain isolated", func(t *testing.T) {
		cee := newCEERuntimeMatrixDeps(t)
		opts := MCPProxyOpts{Scanner: testMCPScanner(), CEE: cee, Transport: transportMCPHTTP}
		t.Cleanup(opts.Scanner.Close)
		if got := scanHTTPInputDecision(first, io.Discard, "identity-a", "audit", opts); got.Blocked != nil {
			t.Fatalf("first identity fragment blocked: %+v", got.Blocked)
		}
		if got := scanHTTPInputDecision(second, io.Discard, "identity-b", "audit", opts); got.Blocked != nil {
			t.Fatalf("different identity inherited CEE state: %+v", got.Blocked)
		}
		if got := scanHTTPInputDecision(second, io.Discard, "identity-a", "audit", opts); got.Blocked == nil || got.Blocked.ErrorCode != mcpCEEBlockErrorCode {
			t.Fatalf("origin identity completion = %+v, want CEE block", got.Blocked)
		}
	})
}

func TestMCPCEERuntimeStateMatrix_ReconfigurePreservesInFlightHistory(t *testing.T) {
	cee := newCEERuntimeMatrixDeps(t)
	opts := MCPProxyOpts{Scanner: testMCPScanner(), CEE: cee, Transport: transportMCPHTTP}
	t.Cleanup(opts.Scanner.Close)
	if got := scanHTTPInputDecision(mcpChunkedCEERequest(1, ceeMatrixAWSFirst), io.Discard, "reload-session", "audit", opts); got.Blocked != nil {
		t.Fatalf("first fragment blocked: %+v", got.Blocked)
	}

	// Reconfigure is the supported MCP runtime reload path. Keeping the same
	// policy makes the post-reload denial depend on retained request history.
	cee.Reconfigure(config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionBlock,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled: true, MaxBufferBytes: 4096, WindowMinutes: 5,
		},
	}, metrics.New())

	got := scanHTTPInputDecision(mcpChunkedCEERequest(2, ceeMatrixAWSSecond), io.Discard, "reload-session", "audit", opts)
	if got.Blocked == nil || got.Blocked.ErrorCode != mcpCEEBlockErrorCode {
		t.Fatalf("post-reload completion = %+v, want CEE block from preserved history", got.Blocked)
	}
}

func TestMCPCEERuntimeStateMatrix_ConcurrentRequestsRemainInspectable(t *testing.T) {
	cee := newCEERuntimeMatrixDeps(t)
	opts := MCPProxyOpts{Scanner: testMCPScanner(), CEE: cee, Transport: transportMCPHTTP}
	t.Cleanup(opts.Scanner.Close)

	start := make(chan struct{})
	results := make(chan httpInputDecision, 2)
	for _, session := range []string{"concurrent-session-a", "concurrent-session-b"} {
		seeded := scanHTTPInputDecision(mcpChunkedCEERequest(1, ceeMatrixAWSFirst), io.Discard, session, "audit", opts)
		if seeded.Blocked != nil {
			t.Fatalf("seed for %s blocked: %+v", session, seeded.Blocked)
		}
	}

	var wg sync.WaitGroup
	for _, session := range []string{"concurrent-session-a", "concurrent-session-b"} {
		wg.Add(1)
		go func(session string) {
			defer wg.Done()
			<-start
			results <- scanHTTPInputDecision(mcpChunkedCEERequest(2, ceeMatrixAWSSecond), io.Discard, session, "audit", opts)
		}(session)
	}
	close(start)
	wg.Wait()
	close(results)

	blocked := 0
	for result := range results {
		if result.Blocked == nil {
			t.Fatal("concurrent completion forwarded, want CEE block")
		}
		if result.Blocked.ErrorCode != mcpCEEBlockErrorCode {
			t.Fatalf("concurrent block = %+v, want CEE error code %d", result.Blocked, mcpCEEBlockErrorCode)
		}
		blocked++
	}
	if blocked != 2 {
		t.Fatalf("concurrent CEE blocks = %d, want 2", blocked)
	}
}
