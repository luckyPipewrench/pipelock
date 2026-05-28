// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// wsDiscriminatorRule blocks a WebSocket text frame whose top-level JSON
// "action" field is a string matching ^delete. It is host-scoped (no method)
// so it applies to the GET-upgraded WebSocket route and its frames.
func wsDiscriminatorRule(host string) config.RequestPolicyRule {
	return config.RequestPolicyRule{
		Name:   "ws-destructive-op",
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{host}},
		Discriminator: &config.RequestPolicyDiscriminator{
			Field:         "action",
			ValuePatterns: []string{`^delete`},
		},
		Reason: "destructive websocket operation",
	}
}

func wsDiscriminatorJSONRule(host string) config.RequestPolicyRule {
	r := wsDiscriminatorRule(host)
	r.Route.ContentTypes = []string{"application/json"}
	return r
}

func wsReqPolicyConfig(cfg *config.Config) {
	cfg.RequestPolicy.Enabled = true
	cfg.RequestPolicy.OnParseError = config.ActionBlock
	cfg.RequestPolicy.OnOpaqueOperation = config.ActionBlock
	cfg.RequestPolicy.Rules = []config.RequestPolicyRule{wsDiscriminatorRule("127.0.0.1")}
}

// A benign frame on a route with a discriminator rule must still be relayed:
// the handshake gates route-only, and a non-matching operation forwards.
func TestWSProxyRequestPolicy_BenignFrameForwards(t *testing.T) {
	backendAddr, backendCleanup := wsEchoServer(t)
	defer backendCleanup()
	proxyAddr, proxyCleanup := setupWSProxy(t, wsReqPolicyConfig)
	defer proxyCleanup()

	conn := dialWS(t, proxyAddr, backendAddr)
	defer func() { _ = conn.Close() }()

	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(`{"action":"list"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply, op, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatalf("benign frame should be relayed and echoed, got error: %v", err)
	}
	if op != ws.OpText || string(reply) != `{"action":"list"}` {
		t.Fatalf("expected echoed benign frame, got op=%v reply=%q", op, reply)
	}
}

// A frame whose discriminator value matches a block rule must close the
// connection (per-frame operation policy).
func TestWSProxyRequestPolicy_MatchingFrameBlocks(t *testing.T) {
	backendAddr, backendCleanup := wsEchoServer(t)
	defer backendCleanup()
	proxyAddr, proxyCleanup := setupWSProxy(t, wsReqPolicyConfig)
	defer proxyCleanup()

	conn := dialWS(t, proxyAddr, backendAddr)
	defer func() { _ = conn.Close() }()

	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(`{"action":"deleteAll"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := wsutil.ReadServerData(conn); err == nil {
		t.Fatal("matching discriminator frame should close the connection")
	}
}

func TestWSProxyRequestPolicy_JSONContentTypeScopedFrameBlocks(t *testing.T) {
	backendAddr, backendCleanup := wsEchoServer(t)
	defer backendCleanup()
	proxyAddr, proxyCleanup := setupWSProxy(t, func(cfg *config.Config) {
		wsReqPolicyConfig(cfg)
		cfg.RequestPolicy.Rules = []config.RequestPolicyRule{wsDiscriminatorJSONRule("127.0.0.1")}
	})
	defer proxyCleanup()

	conn := dialWS(t, proxyAddr, backendAddr)
	defer func() { _ = conn.Close() }()

	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(`{"action":"deleteAll"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := wsutil.ReadServerData(conn); err == nil {
		t.Fatal("content_type-scoped discriminator frame should close the connection")
	}
}

// A present-but-non-string discriminator value in a frame is opaque and must
// fail closed (close) under the default on_opaque_operation=block.
func TestWSProxyRequestPolicy_OpaqueFrameBlocks(t *testing.T) {
	backendAddr, backendCleanup := wsEchoServer(t)
	defer backendCleanup()
	proxyAddr, proxyCleanup := setupWSProxy(t, wsReqPolicyConfig)
	defer proxyCleanup()

	conn := dialWS(t, proxyAddr, backendAddr)
	defer func() { _ = conn.Close() }()

	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(`{"action":["delete"]}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := wsutil.ReadServerData(conn); err == nil {
		t.Fatal("opaque (non-string) discriminator frame should close the connection")
	}
}

// A non-JSON text frame on a route with a body-predicate rule cannot be
// classified, so it fails closed under the default on_parse_error=block. This
// is the documented fragment/parse boundary: operators scope body-predicate
// rules to JSON-operation routes (or relax on_parse_error).
func TestWSProxyRequestPolicy_NonJSONFrameFailsClosed(t *testing.T) {
	backendAddr, backendCleanup := wsEchoServer(t)
	defer backendCleanup()
	proxyAddr, proxyCleanup := setupWSProxy(t, wsReqPolicyConfig)
	defer proxyCleanup()

	conn := dialWS(t, proxyAddr, backendAddr)
	defer func() { _ = conn.Close() }()

	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte("not json")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := wsutil.ReadServerData(conn); err == nil {
		t.Fatal("non-JSON frame on a body-predicate route should fail closed")
	}
}

// on_parse_error=warn relaxes the parse-error fail-closed: a non-JSON frame is
// logged but forwarded. This also proves the handshake itself is not blocked by
// a body-predicate rule on the route — the upgrade succeeds and the relay runs.
func TestWSProxyRequestPolicy_NonJSONFrameForwardsWhenParseErrorWarn(t *testing.T) {
	backendAddr, backendCleanup := wsEchoServer(t)
	defer backendCleanup()
	proxyAddr, proxyCleanup := setupWSProxy(t, func(cfg *config.Config) {
		wsReqPolicyConfig(cfg)
		cfg.RequestPolicy.OnParseError = config.ActionWarn
	})
	defer proxyCleanup()

	conn := dialWS(t, proxyAddr, backendAddr)
	defer func() { _ = conn.Close() }()

	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte("not json")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatalf("on_parse_error=warn should forward a non-JSON frame; got %v", err)
	}
	if string(reply) != "not json" {
		t.Fatalf("expected echo, got %q", reply)
	}
}
