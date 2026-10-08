// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type identityReviewConn struct {
	discardConn
	input  *bytes.Reader
	output bytes.Buffer
}

func (c *identityReviewConn) Read(b []byte) (int, error)  { return c.input.Read(b) }
func (c *identityReviewConn) Write(b []byte) (int, error) { return c.output.Write(b) }

func TestDefaultIdentityReviewRelayDirections(t *testing.T) {
	for _, client := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.DefaultAgentIdentity = defaultBucketName
		p := newTestProxyWithConfig(t, cfg)
		updated := cfg.Clone()
		updated.DefaultAgentIdentity = "new-default"
		p.cfgPtr.Store(updated)
		var input bytes.Buffer
		if client {
			_ = wsutil.WriteClientMessage(&input, ws.OpText, []byte("payload"))
		} else {
			_ = wsutil.WriteServerMessage(&input, ws.OpText, []byte("payload"))
		}
		reader := &identityReviewConn{input: bytes.NewReader(input.Bytes())}
		writer := &identityReviewConn{input: bytes.NewReader(nil)}
		r := &wsRelay{proxy: p, cfg: cfg, actorAuth: envelope.ActorAuthSelfDeclared, agent: "declared", clientIP: defaultBucketPeer, targetURL: "ws://api.vendor.example/", maxMsg: 128, clientConn: writer, upstreamConn: reader}
		ctx, cancel := context.WithCancel(t.Context())
		var n int64
		var blocked bool
		if client {
			r.clientConn, r.upstreamConn = reader, writer
			n, _, _, blocked = r.clientToUpstream(ctx, cancel, time.Second)
		} else {
			n, _, _, blocked = r.upstreamToClient(ctx, cancel, time.Second)
		}
		cancel()
		if !blocked || n != 0 {
			t.Errorf("client=%v: blocked=%v bytes=%d", client, blocked, n)
		}
	}
}

func TestDefaultIdentityReviewReloadStates(t *testing.T) {
	for _, tc := range []struct {
		oldName, newName       string
		oldBind, newBind, want bool
	}{
		{"", "", false, false, true},
		{"", defaultBucketName, false, false, false},
		{defaultBucketName, "", false, false, false},
		{defaultBucketName, defaultBucketName, false, false, true},
		{defaultBucketName, defaultBucketName, false, true, false},
		{defaultBucketName, defaultBucketName, true, false, false},
	} {
		cfg := config.Defaults()
		cfg.DefaultAgentIdentity, cfg.BindDefaultAgentIdentity = tc.oldName, tc.oldBind
		live := cfg.Clone()
		live.DefaultAgentIdentity, live.BindDefaultAgentIdentity = tc.newName, tc.newBind
		p := &Proxy{}
		p.cfgPtr.Store(live)
		if got := p.stateIdentityConfigCurrent(cfg, envelope.ActorAuthSelfDeclared); got != tc.want {
			t.Fatalf("%+v: got %v", tc, got)
		}
		if !p.stateIdentityConfigCurrent(cfg, envelope.ActorAuthBound) {
			t.Fatal("bound identity must survive default changes")
		}
	}
}

func TestDefaultIdentityReviewInterceptReload(t *testing.T) {
	for _, auth := range []envelope.ActorAuth{envelope.ActorAuthSelfDeclared, envelope.ActorAuthConfigDefault, envelope.ActorAuthBound} {
		t.Run(string(auth), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DefaultAgentIdentity = defaultBucketName
			cfg.CrossRequestDetection.Enabled = false
			cfg.ResponseScanning.Enabled = false
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p := newTestProxyWithConfig(t, cfg)
			hits := 0
			handler := newInterceptHandler(&InterceptContext{
				TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc,
				Logger: audit.NewNop(), Metrics: p.metrics, ClientIP: defaultBucketPeer,
				Agent: defaultBucketName, ActorAuth: auth, Proxy: p,
			}, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				hits++
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
			}))
			do := func() int {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example/", nil))
				return w.Code
			}
			if got := do(); got != http.StatusOK {
				t.Fatalf("before reload = %d", got)
			}
			updated := cfg.Clone()
			updated.DefaultAgentIdentity = "new-default"
			p.cfgPtr.Store(updated)
			want, wantHits := http.StatusForbidden, 1
			if auth == envelope.ActorAuthBound {
				want, wantHits = http.StatusOK, 2
			}
			if got := do(); got != want || hits != wantHits {
				t.Fatalf("after reload status=%d hits=%d, want %d/%d", got, hits, want, wantHits)
			}
		})
	}
}

func TestDefaultIdentityReviewWebSocketReload(t *testing.T) {
	backend, closeBackend := wsEchoServer(t)
	t.Cleanup(closeBackend)
	addr, p, cleanup := setupWSProxyDefaultWithProxy(t, func(cfg *config.Config) {
		cfg.DefaultAgentIdentity = defaultBucketName
	})
	t.Cleanup(cleanup)
	conn := dialWS(t, addr, backend)
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte("before")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := wsutil.ReadServerData(conn); err != nil {
		t.Fatal(err)
	}
	updated := p.ConfigPtr().Load().Clone()
	updated.DefaultAgentIdentity = "new-default"
	if !p.Reload(updated, scanner.MustNew(updated)) {
		t.Fatal("reload did not publish the new identity")
	}
	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte("after")); err != nil {
		t.Fatal(err)
	}
	if msg, _, err := wsutil.ReadServerData(conn); err == nil {
		t.Fatalf("old identity connection forwarded after reload: %q", msg)
	}
}

func TestDefaultIdentityReviewIssuerPeerIsolation(t *testing.T) {
	cfg := config.Defaults()
	cfg.DefaultAgentIdentity = defaultBucketName
	issuer, err := url.Parse("https://api.vendor.example/login")
	if err != nil {
		t.Fatal(err)
	}
	value := issuerJWTShapedValue()
	cookies := newIssuerBoundCookieStore()
	queries := newIssuerQueryStore()
	now := time.Now()
	owner := sessionKeyFor(cfg, "declared-one", defaultBucketPeer, envelope.ActorAuthSelfDeclared)
	cookies.observeResponse(owner, issuer, http.Header{"Set-Cookie": {"session=" + value + "; Path=/; Secure"}}, true, now)
	queries.remember(owner, issuer, "next", value, now)
	for _, tc := range []struct {
		name, peer string
		auth       envelope.ActorAuth
		want       bool
	}{
		{"declared-two", defaultBucketPeer, envelope.ActorAuthMatched, true},
		{"declared-two", "192.0.2.2", envelope.ActorAuthSelfDeclared, false},
		{"bound-other", defaultBucketPeer, envelope.ActorAuthBound, false},
		{defaultBucketName, defaultBucketPeer, envelope.ActorAuthBound, true},
	} {
		key := sessionKeyFor(cfg, tc.name, tc.peer, tc.auth)
		if got := cookies.allows(key, issuer, "session", value, now); got != tc.want {
			t.Fatalf("cookie %s/%s/%s=%v", tc.name, tc.peer, tc.auth, got)
		}
		if got := queries.allows(key, issuer, "next", value); got != tc.want {
			t.Fatalf("query %s/%s/%s=%v", tc.name, tc.peer, tc.auth, got)
		}
	}
}
