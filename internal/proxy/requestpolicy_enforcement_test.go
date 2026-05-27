// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	rpTestHost = "api.example.com"
	rpRuleName = "block-dangerous"
)

// reqPolicyConfig returns a Defaults config with SSRF disabled (no DNS in unit
// tests) and request_policy enabled with the given rules.
func reqPolicyConfig(rules ...config.RequestPolicyRule) *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	// Forward proxy gates the absolute-URI and CONNECT dispatch in buildHandler.
	cfg.ForwardProxy.Enabled = true
	cfg.RequestPolicy.Enabled = true
	cfg.RequestPolicy.Rules = rules
	return cfg
}

// blockRule blocks the given method(s) to rpTestHost.
func blockRule(methods ...string) config.RequestPolicyRule {
	return config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{rpTestHost}, Methods: methods},
		Reason: "dangerous operation requires operator approval",
	}
}

func graphqlBlockRule() config.RequestPolicyRule {
	return config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{
			Hosts:        []string{rpTestHost},
			Methods:      []string{http.MethodPost},
			ContentTypes: []string{"application/json"},
		},
		GraphQL: &config.RequestPolicyGraphQL{
			OperationTypes:    []string{"mutation"},
			RootFieldPatterns: []string{`^deleteRecord$`},
		},
		Reason: "dangerous operation requires operator approval",
	}
}

func deleteRecordGraphQLBody() string {
	return `{"query":` + strconv.Quote(`mutation { deleteRecord { id } }`) + `}`
}

// --- Shared helper: method-override double-evaluation -----------------------

func TestEvaluateRequestPolicy_MethodOverrideCannotDowngrade(t *testing.T) {
	t.Parallel()
	// Rule blocks DELETE. An attacker sends POST but tunnels the real verb via
	// X-HTTP-Method-Override: DELETE. The double-evaluation must still block.
	p := newTestProxyWithConfig(t, reqPolicyConfig(blockRule(http.MethodDelete)))

	h := http.Header{}
	h.Set("X-HTTP-Method-Override", http.MethodDelete)
	d := p.evaluateRequestPolicy(rpTestHost, http.MethodPost, h, "/v1/jobs/1", "", nil)
	if d.Action != config.ActionBlock {
		t.Fatalf("override DELETE via POST should block, got action=%q", d.Action)
	}

	// And the inverse: a bare POST with no override is not caught by a
	// DELETE-only rule.
	if d2 := p.evaluateRequestPolicy(rpTestHost, http.MethodPost, http.Header{}, "/v1/jobs/1", "", nil); d2.Matched() {
		t.Fatalf("bare POST should not match a DELETE-only rule, got %+v", d2)
	}
}

// --- Shared helper: block / warn / shadow + metric + receipt ----------------

func TestApplyRequestPolicy_Outcomes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		rule      config.RequestPolicyRule
		wantBlock bool
	}{
		{
			name:      "block enforces",
			rule:      blockRule(http.MethodDelete),
			wantBlock: true,
		},
		{
			name: "warn forwards",
			rule: config.RequestPolicyRule{
				Name: rpRuleName, Action: config.ActionWarn,
				Route: config.RequestPolicyRoute{Hosts: []string{rpTestHost}, Methods: []string{http.MethodDelete}},
			},
			wantBlock: false,
		},
		{
			name: "shadow block forwards",
			rule: config.RequestPolicyRule{
				Name: rpRuleName, Action: config.ActionBlock, Shadow: true,
				Route: config.RequestPolicyRoute{Hosts: []string{rpTestHost}, Methods: []string{http.MethodDelete}},
			},
			wantBlock: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProxyWithConfig(t, reqPolicyConfig(tc.rule))
			res := p.applyRequestPolicy(requestPolicyInput{
				Host:      rpTestHost,
				Method:    http.MethodDelete,
				Path:      "/v1/jobs/1",
				Transport: TransportForward,
				Target:    "http://" + rpTestHost + "/v1/jobs/1",
				AuditCtx:  audit.LogContext{},
			})
			if res.Block != tc.wantBlock {
				t.Fatalf("Block = %v, want %v", res.Block, tc.wantBlock)
			}
			if tc.wantBlock {
				if res.Info.Reason != "request_policy_deny" {
					t.Errorf("block Info.Reason = %q, want request_policy_deny", res.Info.Reason)
				}
				if res.Reason == "" {
					t.Error("block result should carry a non-empty operator reason")
				}
			}
		})
	}
}

func TestApplyRequestPolicy_NoMatchForwards(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(blockRule(http.MethodDelete)))
	res := p.applyRequestPolicy(requestPolicyInput{
		Host: rpTestHost, Method: http.MethodGet, Path: "/v1/jobs/1",
		Transport: TransportForward, AuditCtx: audit.LogContext{},
	})
	if res.Block {
		t.Fatal("GET should not match a DELETE rule")
	}
}

func TestApplyRequestPolicy_GraphQLPredicateBlocks(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(graphqlBlockRule()))
	res := p.applyRequestPolicy(requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/graphql",
		ContentType: "application/json",
		Body:        []byte(deleteRecordGraphQLBody()),
		BodyRead:    true,
		Transport:   TransportForward,
		AuditCtx:    audit.LogContext{},
	})
	if !res.Block {
		t.Fatal("GraphQL deleteRecord mutation should block")
	}
}

func TestApplyRequestPolicy_GraphQLParseErrorFailsClosed(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(graphqlBlockRule()))
	res := p.applyRequestPolicy(requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/graphql",
		ContentType: "application/json",
		Body:        []byte(`{"query":"mutation { deleteRecord "`),
		BodyRead:    true,
		Transport:   TransportForward,
		AuditCtx:    audit.LogContext{},
	})
	if !res.Block {
		t.Fatal("unparseable route-matched GraphQL body should fail closed")
	}
}

func TestApplyRequestPolicy_GraphQLOpaqueFailsClosed(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(graphqlBlockRule()))
	res := p.applyRequestPolicy(requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/graphql",
		ContentType: "application/json",
		BodyRead:    false,
		Transport:   TransportForward,
		AuditCtx:    audit.LogContext{},
	})
	if !res.Block {
		t.Fatal("route-matched GraphQL request with unavailable body should fail closed")
	}
}

func TestApplyRequestPolicy_GraphQLOpaqueWarnForwards(t *testing.T) {
	t.Parallel()
	cfg := reqPolicyConfig(graphqlBlockRule())
	cfg.RequestPolicy.OnOpaqueOperation = config.ActionWarn
	p := newTestProxyWithConfig(t, cfg)
	res := p.applyRequestPolicy(requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/graphql",
		ContentType: "application/json",
		BodyRead:    false,
		Transport:   TransportForward,
		AuditCtx:    audit.LogContext{},
	})
	if res.Block {
		t.Fatal("on_opaque_operation=warn should log and forward")
	}
}

func TestPrepareRequestPolicyBody_OversizeBlocks(t *testing.T) {
	t.Parallel()
	cfg := reqPolicyConfig(graphqlBlockRule())
	cfg.RequestBodyScanning.MaxBodyBytes = 8
	p := newTestProxyWithConfig(t, cfg)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql",
		strings.NewReader(deleteRecordGraphQLBody()))
	req.Header.Set("Content-Type", "application/json")
	in := requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/graphql",
		ContentType: "application/json",
		Headers:     req.Header,
		Transport:   TransportForward,
		AuditCtx:    audit.LogContext{},
	}
	res := p.prepareRequestPolicyBody(req, &in)
	if !res.Block {
		t.Fatal("oversize request_policy operation body should block fail-closed")
	}
	// The client-facing reason is the matched rule's reason (the max_body_bytes
	// detail is recorded in the audit log); the block honors on_parse_error,
	// which defaults to block.
	if res.Reason == "" {
		t.Fatal("oversize block should carry the rule's operator-facing reason")
	}
}

func TestPrepareRequestPolicyBody_OversizeAlwaysBlocks(t *testing.T) {
	t.Parallel()
	// An oversize body is destroyed by the bounded read and cannot be forwarded
	// intact, so it must block even when on_parse_error is warn/allow. The
	// configured on_parse_error downgrade applies only to a fully-read body
	// that fails to parse, not to an unreadable/oversize one.
	cfg := reqPolicyConfig(graphqlBlockRule())
	cfg.RequestPolicy.OnParseError = config.ActionWarn
	cfg.RequestBodyScanning.MaxBodyBytes = 8
	p := newTestProxyWithConfig(t, cfg)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql",
		strings.NewReader(deleteRecordGraphQLBody()))
	req.Header.Set("Content-Type", "application/json")
	in := requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/graphql",
		ContentType: "application/json",
		Headers:     req.Header,
		Transport:   TransportForward,
		AuditCtx:    audit.LogContext{},
	}
	if res := p.prepareRequestPolicyBody(req, &in); !res.Block {
		t.Fatal("an oversize operation body must block even with on_parse_error=warn (it cannot be forwarded intact)")
	}
}

func TestRequestPolicy_FetchIgnoresInboundControlPlaneHeaders(t *testing.T) {
	t.Parallel()
	// A rule that would match a POST/application/json request must NOT fire on
	// a /fetch call merely because the agent set those headers on the inbound
	// control-plane request — the outbound fetch is always a plain GET.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}
	rule := config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{
			Hosts:        []string{upstreamURL.Hostname()},
			Methods:      []string{http.MethodPost},
			ContentTypes: []string{"application/json"},
		},
		Reason: "dangerous operation requires operator approval",
	}
	p := newTestProxyWithConfig(t, reqPolicyConfig(rule))
	handler := p.buildHandler(p.buildMux())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL), nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HTTP-Method-Override", http.MethodPost)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got := w.Header().Get("X-Pipelock-Block-Reason"); got == "request_policy_deny" {
		t.Fatal("inbound /fetch control-plane headers must not drive request_policy matching")
	}
}

func TestPrepareRequestPolicyBody_ReadsAndRewrapsOnlyWhenNeeded(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(graphqlBlockRule()))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql",
		strings.NewReader(deleteRecordGraphQLBody()))
	req.Header.Set("Content-Type", "application/json")
	in := requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/graphql",
		ContentType: "application/json",
		Headers:     req.Header,
	}
	if res := p.prepareRequestPolicyBody(req, &in); res.Block {
		t.Fatalf("prepare blocked valid body: %+v", res)
	}
	if !in.BodyRead || len(in.Body) == 0 {
		t.Fatalf("body not buffered: BodyRead=%v len=%d", in.BodyRead, len(in.Body))
	}
	rewrapped, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read rewrapped body: %v", err)
	}
	if string(rewrapped) != string(in.Body) {
		t.Fatalf("rewrapped body mismatch")
	}

	routeOnly := newTestProxyWithConfig(t, reqPolicyConfig(blockRule(http.MethodPost)))
	req2 := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql",
		strings.NewReader("not read"))
	in2 := requestPolicyInput{Host: rpTestHost, Method: http.MethodPost, Path: "/graphql", Headers: req2.Header}
	if res := routeOnly.prepareRequestPolicyBody(req2, &in2); res.Block || in2.BodyRead {
		t.Fatalf("route-only rule should not force body read, res=%+v BodyRead=%v", res, in2.BodyRead)
	}
}

func TestRequestPolicyBodyLimit_DefaultFallback(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(graphqlBlockRule()))
	p.cfgPtr.Store(&config.Config{})
	if got := p.requestPolicyBodyLimit(); got != defaultRequestPolicyMaxBodyBytes {
		t.Fatalf("default limit = %d, want %d", got, defaultRequestPolicyMaxBodyBytes)
	}
}

// rpErrBody is a request body that errors on read, to exercise the
// fail-closed branch of prepareRequestPolicyBody.
type rpErrBody struct{}

func (rpErrBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (rpErrBody) Close() error             { return nil }

func TestPrepareRequestPolicyBody_ReadErrorFailsClosed(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(graphqlBlockRule()))
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql", nil)
	r.Header.Set(headerContentType, "application/json")
	r.Body = rpErrBody{}
	in := requestPolicyInput{
		Host: rpTestHost, Method: http.MethodPost, Path: "/graphql",
		ContentType: "application/json", Headers: r.Header, AuditCtx: audit.LogContext{},
	}
	if rp := p.prepareRequestPolicyBody(r, &in); !rp.Block {
		t.Fatal("a body read error on a route-matched GraphQL request must fail closed")
	}
}

func TestPrepareRequestPolicyBody_NilBodyMarksRead(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(graphqlBlockRule()))
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql", nil)
	r.Header.Set(headerContentType, "application/json")
	r.Body = nil
	in := requestPolicyInput{
		Host: rpTestHost, Method: http.MethodPost, Path: "/graphql",
		ContentType: "application/json", Headers: r.Header, AuditCtx: audit.LogContext{},
	}
	rp := p.prepareRequestPolicyBody(r, &in)
	if rp.Block {
		t.Fatal("prepare should not itself block on a nil body; apply handles opaque")
	}
	if !in.BodyRead {
		t.Fatal("a nil body must mark BodyRead so apply treats the operation as opaque")
	}
}

func TestApplyRequestPolicy_OpaqueWithMethodOverrideFailsClosed(t *testing.T) {
	t.Parallel()
	// Base GET, override POST: the override makes the GraphQL (POST) rule's
	// route match, and the unread body is opaque, so it must fail closed. This
	// exercises the base-vs-override path of the uninspectable evaluator.
	p := newTestProxyWithConfig(t, reqPolicyConfig(graphqlBlockRule()))
	h := http.Header{}
	h.Set(headerContentType, "application/json")
	h.Set("X-HTTP-Method-Override", http.MethodPost)
	res := p.applyRequestPolicy(requestPolicyInput{
		Host: rpTestHost, Method: http.MethodGet, Path: "/graphql",
		ContentType: "application/json", Headers: h, BodyRead: false,
		Transport: TransportForward, AuditCtx: audit.LogContext{},
	})
	if !res.Block {
		t.Fatal("opaque GraphQL reached via method override must fail closed")
	}
}

func TestApplyRequestPolicy_BlockCarriesReceiptWhenEmitterConfigured(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(blockRule(http.MethodDelete)))
	// A configured receipt emitter makes the block stamp the real action_id
	// into the receipt header and emit a correlated receipt. The gating only
	// reads the pointer for non-nil presence, so a zero-value emitter suffices.
	p.receiptEmitterPtr.Store(&receipt.Emitter{})

	emitted := 0
	res := p.applyRequestPolicy(requestPolicyInput{
		Host: rpTestHost, Method: http.MethodDelete, Path: "/v1/jobs/1",
		Transport: TransportForward, AuditCtx: audit.LogContext{},
		Emit: func(receipt.EmitOpts) { emitted++ },
	})
	if !res.Block {
		t.Fatal("expected block")
	}
	if emitted != 1 {
		t.Fatalf("expected exactly one receipt emission, got %d", emitted)
	}
	if res.Info.Receipt == "" {
		t.Error("receipt header should be populated when an emitter is configured")
	}
}

func TestSetupRequestPolicy_InvalidPatternFailsStartup(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.RequestPolicy.Enabled = true
	cfg.RequestPolicy.Rules = []config.RequestPolicyRule{{
		Name:   "bad",
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{rpTestHost}, PathPatterns: []string{"("}},
	}}
	sc := scanner.New(cfg)
	logger, _ := audit.New("json", "stdout", "", false, false)
	if _, err := New(cfg, logger, sc, metrics.New()); err == nil {
		t.Fatal("New must fail closed when a request_policy path_pattern does not compile")
	}
}

func TestApplyRequestPolicy_DisabledForwards(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.RequestPolicy.Enabled = false
	cfg.RequestPolicy.Rules = []config.RequestPolicyRule{blockRule(http.MethodDelete)}
	p := newTestProxyWithConfig(t, cfg)
	res := p.applyRequestPolicy(requestPolicyInput{
		Host: rpTestHost, Method: http.MethodDelete, Path: "/v1/jobs/1",
		Transport: TransportForward, AuditCtx: audit.LogContext{},
	})
	if res.Block {
		t.Fatal("disabled request_policy must not block")
	}
}

// --- Transport parity: HTTP-surface block emission --------------------------

// assertRequestPolicyBlock checks a recorded response is a request_policy 403.
func assertRequestPolicyBlock(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if got := w.Header().Get("X-Pipelock-Block-Reason"); got != "request_policy_deny" {
		t.Fatalf("X-Pipelock-Block-Reason = %q, want request_policy_deny", got)
	}
	if got := w.Header().Get("X-Pipelock-Block-Reason-Retry"); got != "policy" {
		t.Errorf("retry hint = %q, want policy", got)
	}
}

func TestRequestPolicy_ForwardAbsoluteURI_Blocks(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(blockRule(http.MethodDelete)))
	handler := p.buildHandler(p.buildMux())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete,
		"http://"+rpTestHost+"/v1/jobs/123", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assertRequestPolicyBlock(t, w)
}

func TestRequestPolicy_ForwardGraphQL_BlocksWithBodyScanningDisabled(t *testing.T) {
	t.Parallel()
	cfg := reqPolicyConfig(graphqlBlockRule())
	cfg.RequestBodyScanning.Enabled = false
	p := newTestProxyWithConfig(t, cfg)
	handler := p.buildHandler(p.buildMux())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://"+rpTestHost+"/graphql", strings.NewReader(deleteRecordGraphQLBody()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assertRequestPolicyBlock(t, w)
}

func TestRequestPolicy_Fetch_Blocks(t *testing.T) {
	t.Parallel()
	// Fetch is GET-only; block GET to the host.
	p := newTestProxyWithConfig(t, reqPolicyConfig(blockRule(http.MethodGet)))
	handler := p.buildHandler(p.buildMux())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/fetch?url=http://"+rpTestHost+"/v1/secret", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assertRequestPolicyBlock(t, w)
}

func TestRequestPolicy_Connect_HostRuleBlocks(t *testing.T) {
	t.Parallel()
	// CONNECT setup sees host + method CONNECT only. A host-scoped rule (no
	// path) blocks the tunnel before it opens.
	rule := config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{rpTestHost}},
		Reason: "host blocked for agent runtime",
	}
	p := newTestProxyWithConfig(t, reqPolicyConfig(rule))
	handler := p.buildHandler(p.buildMux())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "//"+rpTestHost+":443", nil)
	req.Host = rpTestHost + ":443"
	req.RequestURI = rpTestHost + ":443"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assertRequestPolicyBlock(t, w)
}

func TestRequestPolicy_WebSocketHandshake_Blocks(t *testing.T) {
	t.Parallel()
	// WebSocket handshake is a GET upgrade; a host+GET rule blocks it before
	// the upgrade completes.
	cfg := reqPolicyConfig(blockRule(http.MethodGet))
	cfg.WebSocketProxy.Enabled = true
	p := newTestProxyWithConfig(t, cfg)
	handler := p.buildHandler(p.buildMux())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/ws?url=ws://"+rpTestHost+"/socket", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if got := w.Header().Get("X-Pipelock-Block-Reason"); got != "request_policy_deny" {
		t.Fatalf("X-Pipelock-Block-Reason = %q, want request_policy_deny", got)
	}
}

func TestRequestPolicy_Reverse_Blocks(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}
	// The reverse proxy forwards to a fixed upstream, so request_policy matches
	// the upstream (egress) host, not the inbound Host header.
	rule := config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{upstreamURL.Hostname()}, Methods: []string{http.MethodDelete}},
		Reason: "dangerous operation requires operator approval",
	}
	p := newTestProxyWithConfig(t, reqPolicyConfig(rule))
	rpHandler := NewReverseProxy(upstreamURL, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
	// Production wires this in server_lifecycle; a reverse handler without it
	// would silently skip request_policy, so the test mirrors production.
	rpHandler.SetRequestPolicyFn(p.ApplyRequestPolicy)
	rpHandler.SetRequestPolicyPrepareFn(p.PrepareRequestPolicyBody)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "http://"+rpTestHost+"/v1/jobs/1", nil)
	req.Host = rpTestHost
	w := httptest.NewRecorder()
	rpHandler.ServeHTTP(w, req)

	assertRequestPolicyBlock(t, w)
}

func TestRequestPolicy_ReverseGraphQL_BlocksWithBodyScanningDisabled(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}
	// Rule scoped to the upstream (egress) host, mirroring real reverse traffic
	// where the inbound URL carries no host.
	rule := config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{
			Hosts:        []string{upstreamURL.Hostname()},
			Methods:      []string{http.MethodPost},
			ContentTypes: []string{"application/json"},
		},
		GraphQL: &config.RequestPolicyGraphQL{
			OperationTypes:    []string{"mutation"},
			RootFieldPatterns: []string{`^deleteRecord$`},
		},
		Reason: "dangerous operation requires operator approval",
	}
	cfg := reqPolicyConfig(rule)
	cfg.RequestBodyScanning.Enabled = false
	p := newTestProxyWithConfig(t, cfg)
	rpHandler := NewReverseProxy(upstreamURL, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
	rpHandler.SetRequestPolicyFn(p.ApplyRequestPolicy)
	rpHandler.SetRequestPolicyPrepareFn(p.PrepareRequestPolicyBody)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql",
		strings.NewReader(deleteRecordGraphQLBody()))
	req.Host = rpTestHost
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	rpHandler.ServeHTTP(w, req)

	assertRequestPolicyBlock(t, w)
}

func TestRequestPolicy_RedirectHopReportsRequestPolicyReason(t *testing.T) {
	t.Parallel()
	// An origin redirects to a host that request_policy blocks for GET. The
	// redirect-hop block must surface request_policy_deny (with policy retry),
	// not the generic redirect_scan_denied.
	p := newTestProxyWithConfig(t, reqPolicyConfig(blockRule(http.MethodGet)))

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+rpTestHost+"/v1/secret", http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	handler := p.buildHandler(p.buildMux())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/fetch?url="+url.QueryEscape(origin.URL), nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got := w.Header().Get("X-Pipelock-Block-Reason"); got != "request_policy_deny" {
		t.Fatalf("redirect-hop block reason = %q, want request_policy_deny", got)
	}
	if got := w.Header().Get("X-Pipelock-Block-Reason-Retry"); got != "policy" {
		t.Errorf("retry hint = %q, want policy", got)
	}
}

func TestRequestPolicy_RedirectHopGraphQLOverGETBenignForwards(t *testing.T) {
	t.Parallel()
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(final.Close)
	finalURL, err := url.Parse(final.URL)
	if err != nil {
		t.Fatalf("parse final URL: %v", err)
	}

	cfg := reqPolicyConfig(config.RequestPolicyRule{
		Name:   "block-delete",
		Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{
			Hosts:        []string{finalURL.Hostname()},
			Methods:      []string{http.MethodGet},
			PathPatterns: []string{`/graphql$`},
		},
		GraphQL: &config.RequestPolicyGraphQL{
			OperationTypes:    []string{"mutation"},
			RootFieldPatterns: []string{`^deleteRecord$`},
		},
	})
	p := newTestProxyWithConfig(t, cfg)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := final.URL + "/graphql?query=" + url.QueryEscape(`query { viewer { id } }`)
		http.Redirect(w, r, target, http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	handler := p.buildHandler(p.buildMux())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/fetch?url="+url.QueryEscape(origin.URL), nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("benign GraphQL-over-GET redirect hop: status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Pipelock-Block-Reason"); got != "" {
		t.Fatalf("benign GraphQL-over-GET redirect hop must not be blocked; got reason %q", got)
	}
}

// --- Before-gate ordering: request_policy blocks with no contract -----------

func TestRequestPolicy_EnforcesWithoutContract(t *testing.T) {
	t.Parallel()
	// No learn_lock contract is configured, so EvaluateGate would allow. The
	// request_policy block must still fire — proving it runs independently and
	// before the contract gate, not gated behind it.
	p := newTestProxyWithConfig(t, reqPolicyConfig(blockRule(http.MethodDelete)))
	if p.currentContractLoader() != nil {
		t.Fatal("test precondition: no contract loader expected")
	}
	handler := p.buildHandler(p.buildMux())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete,
		"http://"+rpTestHost+"/v1/jobs/123", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assertRequestPolicyBlock(t, w)
}

// --- Hot reload: rule changes take effect -----------------------------------

func TestRequestPolicy_HotReloadAppliesRuleChange(t *testing.T) {
	t.Parallel()
	// Start with request_policy disabled: a DELETE forwards (no block).
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	p := newTestProxyWithConfig(t, cfg)

	if got := p.evaluateRequestPolicy(rpTestHost, http.MethodDelete, http.Header{}, "/v1/jobs/1", "", nil); got.Matched() {
		t.Fatal("no rule configured: DELETE should not match")
	}

	// Reload with a blocking rule.
	newCfg := reqPolicyConfig(blockRule(http.MethodDelete))
	if !p.Reload(newCfg, scanner.New(newCfg)) {
		t.Fatal("Reload returned false")
	}
	if got := p.evaluateRequestPolicy(rpTestHost, http.MethodDelete, http.Header{}, "/v1/jobs/1", "", nil); got.Action != config.ActionBlock {
		t.Fatalf("after reload, DELETE should block, got action=%q", got.Action)
	}

	// Reload again removing the rule: enforcement clears.
	cfgOff := reqPolicyConfig()
	if !p.Reload(cfgOff, scanner.New(cfgOff)) {
		t.Fatal("second Reload returned false")
	}
	if got := p.evaluateRequestPolicy(rpTestHost, http.MethodDelete, http.Header{}, "/v1/jobs/1", "", nil); got.Matched() {
		t.Fatal("after rule removal, DELETE should not match")
	}
}
