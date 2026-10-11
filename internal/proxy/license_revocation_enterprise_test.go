//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func revocationConnectionConfig(cfg *config.Config) {
	cfg.LicenseKey = "same-license"
	cfg.Agents = map[string]config.AgentProfile{"client": {SourceCIDRs: []string{"127.0.0.0/8"}}}
	cfg.ForwardProxy.IdleTimeoutSeconds = 60
	cfg.WebSocketProxy.IdleTimeoutSeconds = 60
}

func revokeAfterReload(t *testing.T, p *Proxy) {
	t.Helper()
	old := p.CurrentConfig()
	next := old.Clone()
	next.Logging.IncludeAllowed = !old.Logging.IncludeAllowed
	if !p.Reload(next, scanner.MustNew(next)) {
		t.Fatal("unrelated reload failed")
	}
	if !p.SetLicenseRevoked(old, true) {
		t.Fatal("same-license revocation dropped after reload")
	}
	if _, ok := p.Edition().LookupProfile("client"); ok {
		t.Fatal("revoked profile remained selectable")
	}
}

func requireRevocationClose(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := conn.Read(b[:]); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("revocation did not close connection: %v", err)
	}
}

func TestLicenseRevocationClosesMainListenerConnect(t *testing.T) {
	t.Parallel()
	target, live := airlockProbeHoldListener(t)
	addr, p, cleanup := setupForwardProxyWithInstance(t, revocationConnectionConfig)
	defer cleanup()
	conn := dialProxy(t, addr)
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.Addr(), target.Addr()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("positive control: CONNECT status %d", resp.StatusCode)
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-live:
	case <-time.After(3 * time.Second):
		t.Fatal("positive control: CONNECT probe not delivered")
	}
	revokeAfterReload(t, p)
	requireRevocationClose(t, conn)
}

func TestLicenseRevocationClosesMainListenerWebSocket(t *testing.T) {
	t.Parallel()
	backend, stop := wsEchoServer(t)
	defer stop()
	addr, p, cleanup := setupWSProxyDefaultWithProxy(t, revocationConnectionConfig)
	defer cleanup()
	conn := dialWS(t, addr, backend)
	defer func() { _ = conn.Close() }()
	if err := wsutil.WriteClientText(conn, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := wsutil.ReadServerData(conn); err != nil {
		t.Fatalf("positive control: echo failed: %v", err)
	}
	if ra, ok := p.Edition().LookupProfile("client"); !ok || ra.Name == edition.ProfileDefault {
		t.Fatal("positive control: paid profile not selectable")
	}
	revokeAfterReload(t, p)
	requireRevocationClose(t, conn)
}

func TestLicenseRevocationClosesConnectBeforeClientHello(t *testing.T) {
	t.Parallel()
	target, _ := airlockProbeHoldListener(t)
	addr, p, cleanup := setupForwardProxyWithInstance(t, revocationConnectionConfig)
	defer cleanup()
	conn := dialProxy(t, addr)
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.Addr(), target.Addr()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !p.CurrentConfig().ForwardProxy.SNIVerificationEnabled() {
		t.Fatal("positive control: CONNECT not admitted with SNI verification")
	}
	if !p.SetLicenseRevoked(p.CurrentConfig(), true) {
		t.Fatal("revocation not published")
	}
	requireRevocationClose(t, conn)
}
