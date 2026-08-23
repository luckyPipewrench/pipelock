// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	gobwasutil "github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/authority"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

type authorityVerifierFunc func(context.Context, authority.Request) authority.Result

func (f authorityVerifierFunc) Verify(ctx context.Context, request authority.Request) authority.Result {
	return f(ctx, request)
}

func allowAuthorityVerifier(captured *authority.Request) authority.Verifier {
	return authorityVerifierFunc(func(_ context.Context, request authority.Request) authority.Result {
		if captured != nil {
			*captured = request
		}
		return authority.Result{Decision: authority.DecisionAllow, Reason: authority.ReasonMatched, Issuer: "issuer", Reference: "ref-1"}
	})
}

func TestExtractInboundMCPAuthorityStripsOnlyOwnedMembers(t *testing.T) {
	t.Parallel()
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"com.pipelock/authority":"grant","com.pipelock/mediation":{"spoof":true},"vendor.example/keep":{"n":9007199254740993}}}}`)
	out, ref, err := extractInboundMCPAuthority(msg)
	if err != nil {
		t.Fatalf("extractInboundMCPAuthority: %v", err)
	}
	if ref != "grant" {
		t.Fatalf("reference = %q, want grant", ref)
	}
	if bytes.Contains(out, []byte("com.pipelock/authority")) || bytes.Contains(out, []byte("com.pipelock/mediation")) {
		t.Fatalf("owned metadata survived: %s", out)
	}
	if !bytes.Contains(out, []byte(`"vendor.example/keep":{"n":9007199254740993}`)) {
		t.Fatalf("sibling metadata changed or disappeared: %s", out)
	}
}

func TestExtractInboundMCPAuthorityPreservesOpaqueReference(t *testing.T) {
	t.Parallel()
	msg := []byte(`{"params":{"_meta":{"com.pipelock/authority":" grant "}}}`)
	_, ref, err := extractInboundMCPAuthority(msg)
	if err != nil {
		t.Fatalf("extractInboundMCPAuthority: %v", err)
	}
	if ref != " grant " {
		t.Fatalf("reference = %q, want exact opaque value", ref)
	}
}

func TestExtractInboundMCPAuthorityRejectsDuplicateAndMalformed(t *testing.T) {
	t.Parallel()
	duplicate := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"com.pipelock/authority":"one","com.pipelock/authority":"two"}}}`)
	if _, _, err := extractInboundMCPAuthority(duplicate); err == nil {
		t.Fatal("duplicate authority key did not fail closed")
	}
	malformed := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"com.pipelock/authority":42,"keep":true}}}`)
	out, _, err := extractInboundMCPAuthority(malformed)
	if err == nil {
		t.Fatal("non-string authority did not fail closed")
	}
	if bytes.Contains(out, []byte("com.pipelock/authority")) || !bytes.Contains(out, []byte(`"keep":true`)) {
		t.Fatalf("malformed authority was not consumed safely: %s", out)
	}
}

func TestExtractInboundMCPAuthorityRejectsMalformedShapes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		msg  string
	}{
		{name: "invalid JSON", msg: `{`},
		{name: "missing params", msg: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`},
		{name: "null params", msg: `{"params":null}`},
		{name: "scalar params", msg: `{"params":42}`},
		{name: "missing meta", msg: `{"params":{}}`},
		{name: "null meta", msg: `{"params":{"_meta":null}}`},
		{name: "scalar meta", msg: `{"params":{"_meta":42}}`},
		{name: "unowned meta", msg: `{"params":{"_meta":{"keep":true}}}`},
		{name: "mediation only", msg: `{"params":{"_meta":{"com.pipelock/mediation":{"spoof":true}}}}`},
		{name: "empty authority", msg: `{"params":{"_meta":{"com.pipelock/authority":" "}}}`},
		{name: "oversize authority", msg: `{"params":{"_meta":{"com.pipelock/authority":"` + strings.Repeat("x", authority.MaxReferenceBytes+1) + `"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := extractInboundMCPAuthority([]byte(tc.msg)); err == nil {
				t.Fatal("malformed carrier did not fail closed")
			}
		})
	}
}

func TestAuthorityOptionResolution(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		opts MCPProxyOpts
		want string
	}{
		{name: "explicit actor", opts: MCPProxyOpts{AuthorityActor: " actor "}, want: "actor"},
		{name: "address protection actor", opts: MCPProxyOpts{AddressProtectionAgent: " address "}, want: "address"},
		{name: "contract actor", opts: MCPProxyOpts{ContractAgent: " contract "}, want: "contract"},
		{name: "profile actor", opts: MCPProxyOpts{Profile: " profile "}, want: "profile"},
		{name: "empty actor", opts: MCPProxyOpts{}, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.opts.authorityActor(); got != tc.want {
				t.Fatalf("authorityActor = %q, want %q", got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		opts MCPProxyOpts
		want string
	}{
		{name: "explicit destination", opts: MCPProxyOpts{AuthorityDestination: " upstream "}, want: "upstream"},
		{name: "contract server", opts: MCPProxyOpts{ContractServer: " contract "}, want: "contract"},
		{name: "server name", opts: MCPProxyOpts{ServerName: " server "}, want: "server"},
		{name: "empty destination", opts: MCPProxyOpts{}, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.opts.authorityDestination(); got != tc.want {
				t.Fatalf("authorityDestination = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuthorizeMCPAuditAndNilVerifierPaths(t *testing.T) {
	t.Parallel()
	if err := authorizeMCP(t.Context(), "", authority.ErrMissingReference, MCPFrame{}, MCPProxyOpts{}); err != nil {
		t.Fatalf("nil verifier changed behavior: %v", err)
	}
	var auditBuf bytes.Buffer
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, &auditBuf)
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}
	t.Cleanup(logger.Close)
	opts := MCPProxyOpts{
		AuthorityVerifier: authorityVerifierFunc(func(context.Context, authority.Request) authority.Result {
			return authority.Result{Decision: authority.DecisionDeny, Reason: authority.ReasonActionMismatch}
		}),
		AuthorityActor:       "agent-a",
		AuthorityDestination: "server-a",
		AuditLogger:          logger,
		Transport:            transportMCPHTTP,
	}
	for _, tc := range []struct {
		frame    MCPFrame
		resource string
	}{
		{frame: MCPFrame{Method: "tools/call", ToolCallName: "echo"}, resource: "echo"},
		{frame: MCPFrame{Method: "tools/list"}, resource: "tools/list"},
		{frame: MCPFrame{}, resource: "mcp-request"},
	} {
		if err := authorizeMCP(t.Context(), "grant", nil, tc.frame, opts); err == nil {
			t.Fatalf("denying verifier allowed frame %+v", tc.frame)
		}
		var entry map[string]any
		line, _, _ := bytes.Cut(auditBuf.Bytes(), []byte("\n"))
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("decode authority audit: %v", err)
		}
		auditBuf.Next(len(line) + 1)
		for key, want := range map[string]string{
			"transport": transportMCPHTTP,
			"decision":  "deny",
			"reason":    string(authority.ReasonActionMismatch),
			"resource":  tc.resource,
		} {
			if got := entry[key]; got != want {
				t.Errorf("%s = %v, want %q for frame %+v", key, got, want, tc.frame)
			}
		}
	}

	opts.AuthorityVerifier = allowAuthorityVerifier(nil)
	if err := authorizeMCP(t.Context(), "grant", nil, MCPFrame{Method: "tools/list"}, opts); err != nil {
		t.Fatalf("allowing verifier blocked: %v", err)
	}
	var allowed map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(auditBuf.Bytes()), &allowed); err != nil {
		t.Fatalf("decode allowed authority audit: %v", err)
	}
	if allowed["decision"] != "allow" || allowed["issuer"] != "issuer" || allowed["reference"] != "ref-1" {
		t.Fatalf("allowed authority audit = %+v", allowed)
	}
}

func TestScanHTTPInputDecisionAuthorityGate(t *testing.T) {
	t.Parallel()
	emitter, rec, dir, _ := newReceiptTestHarness(t)
	var captured authority.Request
	opts := MCPProxyOpts{
		Scanner:              testScannerForHTTP(t),
		Transport:            transportMCPHTTP,
		ReceiptEmitter:       emitter,
		AuthorityVerifier:    allowAuthorityVerifier(&captured),
		AuthorityActor:       "principal:alice",
		AuthorityDestination: "https://mcp.example/rpc",
	}
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"com.pipelock/authority":"grant","keep":true}}}`)
	decision := scanHTTPInputDecision(msg, &bytes.Buffer{}, "session", "audit", opts)
	if decision.Blocked != nil {
		t.Fatalf("allowed grant blocked: %+v", decision.Blocked)
	}
	if bytes.Contains(decision.ForwardMessage, []byte(authority.MCPMetaKey)) || !bytes.Contains(decision.ForwardMessage, []byte(`"keep":true`)) {
		t.Fatalf("forwarded metadata = %s", decision.ForwardMessage)
	}
	if captured.Actor != "principal:alice" || captured.Action != "read" || captured.Destination != "https://mcp.example/rpc" || captured.AuthorityRef != "grant" {
		t.Fatalf("verification request = %+v", captured)
	}

	missing := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if got := scanHTTPInputDecision(missing, &bytes.Buffer{}, "session", "audit", opts); got.Blocked == nil {
		t.Fatal("missing grant forwarded with verifier enabled")
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	assertSingleAuthorityBlockReceipt(t, readActionReceipts(t, dir))
}

func TestForwardScannedInputAuthorityDenialMakesNoWrite(t *testing.T) {
	t.Parallel()
	emitter, rec, dir, _ := newReceiptTestHarness(t)
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"com.pipelock/authority":"grant"}}}` + "\n"
	var upstream, log bytes.Buffer
	blocked := make(chan BlockedRequest, 1)
	opts := MCPProxyOpts{
		Scanner:        testInputScanner(t),
		Transport:      transportMCPStdio,
		ReceiptEmitter: emitter,
		AuthorityVerifier: authorityVerifierFunc(func(context.Context, authority.Request) authority.Result {
			return authority.Result{Decision: authority.DecisionDeny, Reason: authority.ReasonActionMismatch}
		}),
		AuthorityActor:       "agent-a",
		AuthorityDestination: "server-a",
	}
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(msg)),
		transport.NewStdioWriter(&upstream),
		&log,
		config.ActionBlock,
		config.ActionBlock,
		blocked,
		nil,
		NewRequestTracker(),
		opts,
	)
	if upstream.Len() != 0 {
		t.Fatalf("denied request reached upstream: %s", upstream.Bytes())
	}
	got, ok := <-blocked
	if !ok || got.ErrorCode != -32008 {
		t.Fatalf("blocked request = %+v, ok=%v", got, ok)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	assertSingleAuthorityBlockReceipt(t, readActionReceipts(t, dir))
}

func TestForwardScannedInputWarnAuthorityDenialMakesNoWrite(t *testing.T) {
	t.Parallel()
	emitter, rec, dir, _ := newReceiptTestHarness(t)
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_tool","arguments":{"token":%q},"_meta":{"com.pipelock/authority":"grant"}}}`+"\n", secret)
	var upstream, log bytes.Buffer
	blocked := make(chan BlockedRequest, 1)
	opts := MCPProxyOpts{
		Scanner:        testInputScanner(t),
		Transport:      transportMCPStdio,
		ReceiptEmitter: emitter,
		InputCfg:       &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock},
		AuthorityVerifier: authorityVerifierFunc(func(context.Context, authority.Request) authority.Result {
			return authority.Result{Decision: authority.DecisionDeny, Reason: authority.ReasonActionMismatch}
		}),
		AuthorityActor:       "agent-a",
		AuthorityDestination: "server-a",
	}
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(msg)),
		transport.NewStdioWriter(&upstream),
		&log,
		config.ActionWarn,
		config.ActionBlock,
		blocked,
		nil,
		NewRequestTracker(),
		opts,
	)
	if upstream.Len() != 0 {
		t.Fatalf("denied request reached upstream: %s", upstream.Bytes())
	}
	got, ok := <-blocked
	if !ok || got.ErrorCode != -32008 {
		t.Fatalf("blocked request = %+v, ok=%v", got, ok)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	assertSingleAuthorityBlockReceipt(t, readActionReceipts(t, dir))
}

func assertSingleAuthorityBlockReceipt(t *testing.T, receipts []receipt.Receipt) {
	t.Helper()
	if len(receipts) != 1 {
		t.Fatalf("receipt count = %d, want exactly one authority denial", len(receipts))
	}
	assertAuthorityBlockReceiptRecord(t, receipts[0].ActionRecord)
}

func assertAuthorityBlockReceiptRecord(t *testing.T, record receipt.ActionRecord) {
	t.Helper()
	if record.Verdict != config.ActionBlock || record.Layer != mcpReceiptLayerAuthority {
		t.Fatalf("receipt verdict/layer = %q/%q, want %q/%s", record.Verdict, record.Layer, config.ActionBlock, mcpReceiptLayerAuthority)
	}
	if record.Pattern != mcpReceiptPatternAuthority {
		t.Fatalf("receipt pattern = %q, want %q", record.Pattern, mcpReceiptPatternAuthority)
	}
	if record.Severity != config.SeverityHigh {
		t.Fatalf("receipt severity = %q, want %q", record.Severity, config.SeverityHigh)
	}
}

func TestMCPAuthorityCarrierIsNeverForwardedWithoutVerifier(t *testing.T) {
	t.Parallel()
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"com.pipelock/authority":"grant","keep":{"x":1}}}}`)
	decision := scanHTTPInputDecision(msg, &bytes.Buffer{}, "session", "audit", MCPProxyOpts{Scanner: testScannerForHTTP(t)})
	if decision.Blocked != nil {
		data, _ := json.Marshal(decision.Blocked)
		t.Fatalf("nil verifier changed behavior: %s", data)
	}
	if bytes.Contains(decision.ForwardMessage, []byte(authority.MCPMetaKey)) {
		t.Fatalf("authority leaked upstream: %s", decision.ForwardMessage)
	}
}

func TestStdioAuthorityCarrierConsumedOnAllow(t *testing.T) {
	t.Parallel()
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"com.pipelock/authority":"grant","keep":{"x":1}}}}` + "\n"
	var upstream, log bytes.Buffer
	blocked := make(chan BlockedRequest, 1)
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(msg)),
		transport.NewStdioWriter(&upstream),
		&log,
		config.ActionBlock,
		config.ActionBlock,
		blocked,
		nil,
		NewRequestTracker(),
		MCPProxyOpts{
			Scanner:              testInputScanner(t),
			Transport:            transportMCPStdio,
			AuthorityVerifier:    allowAuthorityVerifier(nil),
			AuthorityActor:       "agent-a",
			AuthorityDestination: "server-a",
		},
	)
	if bytes.Contains(upstream.Bytes(), []byte(authority.MCPMetaKey)) || !bytes.Contains(upstream.Bytes(), []byte(`"keep":{"x":1}`)) {
		t.Fatalf("forwarded stdio message = %s", upstream.Bytes())
	}
	if got, ok := <-blocked; ok {
		t.Fatalf("allowed stdio message blocked: %+v", got)
	}
}

func TestHTTPAuthorityCarrierConsumedBeforeUpstream(t *testing.T) {
	t.Parallel()
	upstreamBody := make(chan []byte, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
			return
		}
		upstreamBody <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"com.pipelock/authority":"grant","keep":true}}}` + "\n"
	var stdout, stderr bytes.Buffer
	err := RunHTTPProxy(t.Context(), strings.NewReader(msg), &stdout, &stderr, upstream.URL, nil, MCPProxyOpts{
		Scanner:              testScannerForHTTP(t),
		AuthorityVerifier:    allowAuthorityVerifier(nil),
		AuthorityActor:       "agent-a",
		AuthorityDestination: upstream.URL,
	})
	if err != nil {
		t.Fatalf("RunHTTPProxy: %v", err)
	}
	got := <-upstreamBody
	if bytes.Contains(got, []byte(authority.MCPMetaKey)) || !bytes.Contains(got, []byte(`"keep":true`)) {
		t.Fatalf("upstream HTTP body = %s", got)
	}
}

func TestWebSocketAuthorityCarrierConsumedBeforeUpstream(t *testing.T) {
	t.Parallel()
	upstreamMessage := make(chan []byte, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			t.Errorf("upgrade upstream: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		message, _, err := gobwasutil.ReadClientData(conn)
		if err != nil {
			t.Errorf("read upstream message: %v", err)
			return
		}
		upstreamMessage <- message
		_ = gobwasutil.WriteServerMessage(conn, ws.OpText, []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()

	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"com.pipelock/authority":"grant","keep":true}}}` + "\n"
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := RunWSProxy(ctx, strings.NewReader(msg), &stdout, &stderr, wsURL(upstream), MCPProxyOpts{
		Scanner:              testScannerForWS(t),
		AuthorityVerifier:    allowAuthorityVerifier(nil),
		AuthorityActor:       "agent-a",
		AuthorityDestination: wsURL(upstream),
	})
	if err != nil {
		t.Fatalf("RunWSProxy: %v", err)
	}
	got := <-upstreamMessage
	if bytes.Contains(got, []byte(authority.MCPMetaKey)) || !bytes.Contains(got, []byte(`"keep":true`)) {
		t.Fatalf("upstream WebSocket message = %s", got)
	}
}

func TestWebSocketAuthorityDenialMakesNoUpstreamDial(t *testing.T) {
	t.Parallel()
	var dialCalls atomic.Int32
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"com.pipelock/authority":"grant"}}}` + "\n"
	var stdout, stderr bytes.Buffer
	err := RunWSProxy(t.Context(), strings.NewReader(msg), &stdout, &stderr, "ws://mcp.invalid/rpc", MCPProxyOpts{
		Scanner: testScannerForWS(t),
		AuthorityVerifier: authorityVerifierFunc(func(context.Context, authority.Request) authority.Result {
			return authority.Result{Decision: authority.DecisionDeny, Reason: authority.ReasonActionMismatch}
		}),
		AuthorityActor:       "agent-a",
		AuthorityDestination: "ws://mcp.invalid/rpc",
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("unexpected dial")
		},
	})
	if err != nil {
		t.Fatalf("RunWSProxy: %v", err)
	}
	if dialCalls.Load() != 0 {
		t.Fatalf("authority-denied WebSocket dialed upstream %d times", dialCalls.Load())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"code":-32008`)) {
		t.Fatalf("stdout = %s, want authority block response", stdout.Bytes())
	}
}

func TestHTTPListenerAuthorityDenialsMakeNoUpstreamRequest(t *testing.T) {
	t.Parallel()
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()
	opts := MCPProxyOpts{
		Scanner:              testScannerForHTTP(t),
		AuthorityVerifier:    allowAuthorityVerifier(nil),
		AuthorityActor:       "agent-a",
		AuthorityDestination: upstream.URL,
	}
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)

	for _, tc := range []struct {
		name     string
		body     string
		header   bool
		wantCode int
	}{
		{name: "missing", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, wantCode: -32008},
		{name: "HTTP header is not an MCP carrier", body: `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, header: true, wantCode: -32008},
		// Duplicate JSON keys are rejected by the existing parser before the
		// authority gate; preserve that ordering and assert its exact code.
		{name: "duplicate metadata key", body: `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"_meta":{"com.pipelock/authority":"one","com.pipelock/authority":"two"}}}`, wantCode: -32600},
		{name: "malformed metadata member", body: `{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"_meta":{"com.pipelock/authority":42}}}`, wantCode: -32008},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/", strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			if tc.header {
				req.Header.Set(authority.HTTPHeader, "grant")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				t.Fatalf("read response: %v", readErr)
			}
			wantCode := fmt.Sprintf(`"code":%d`, tc.wantCode)
			if !bytes.Contains(body, []byte(wantCode)) {
				t.Fatalf("response = %s, want code %d", body, tc.wantCode)
			}
		})
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("authority-denied listener requests reached upstream %d times", upstreamCalls.Load())
	}
}
