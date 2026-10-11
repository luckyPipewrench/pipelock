//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package proxy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func revocationConnectionConfig(cfg *config.Config) {
	cfg.LicenseKey = "same-license"
	cfg.Agents = map[string]config.AgentProfile{"client": {SourceCIDRs: []string{"127.0.0.0/8"}}}
	cfg.ForwardProxy.IdleTimeoutSeconds = 60
	cfg.WebSocketProxy.IdleTimeoutSeconds = 60
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
	addr, p, cleanup := setupForwardProxyWithInstance(t, revocationReceiptConnectionConfig)
	defer cleanup()
	rph := newReceiptProxyHelper(t)
	p.receiptEmitterPtr.Store(rph.emitter)
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
	if !p.SetLicenseRevoked(p.CurrentConfig(), true) {
		t.Fatal("revocation not published")
	}
	requireRevocationClose(t, conn)
	requireLicenseRevocationOutcome(t, rph)
}

func TestLicenseRevocationClosesMainListenerWebSocket(t *testing.T) {
	t.Parallel()
	backend, stop := wsEchoServer(t)
	defer stop()
	addr, p, cleanup := setupWSProxyDefaultWithProxy(t, revocationReceiptConnectionConfig)
	defer cleanup()
	rph := newReceiptProxyHelper(t)
	p.receiptEmitterPtr.Store(rph.emitter)
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
	if !p.SetLicenseRevoked(p.CurrentConfig(), true) {
		t.Fatal("revocation not published")
	}
	requireRevocationClose(t, conn)
	requireLicenseRevocationOutcome(t, rph)
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

func requireLicenseRevocationOutcome(t *testing.T, rph *receiptProxyHelper) {
	t.Helper()
	testwait.For(t, 3*time.Second, func() bool {
		entries, err := os.ReadDir(rph.dir)
		if err != nil {
			return false
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".jsonl") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(rph.dir, entry.Name()))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				if json.Valid([]byte(line)) && strings.Contains(line, "reason=license_revoked") {
					return true
				}
			}
		}
		return false
	}, "signed revocation outcome")
	r := rph.requireReceipt(t, receiptOutcomeLayer)
	if err := receipt.VerifyWithKey(r, rph.pubHex); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.ActionRecord.Pattern, "reason=license_revoked") {
		t.Fatalf("revocation reason: %s", r.ActionRecord.Pattern)
	}
}

func revocationReceiptConnectionConfig(cfg *config.Config) {
	revocationConnectionConfig(cfg)
	cfg.FlightRecorder.RequireReceipts = true
}

// Frames arriving while revocation wakes a blocked read must not become DLP findings.
func TestWSReceiptsAfterRevocation(t *testing.T) {
	for _, op := range []ws.OpCode{ws.OpText, ws.OpPing} {
		t.Run(opCodeLabel(op), func(t *testing.T) {
			backend, stop := wsEchoServer(t)
			defer stop()
			addr, p, cleanup := setupWSProxyDefaultWithProxy(t, revocationReceiptConnectionConfig)
			defer cleanup()
			rph := newReceiptProxyHelper(t)
			p.receiptEmitterPtr.Store(rph.emitter)
			conn := dialWS(t, addr, backend)
			defer func() { _ = conn.Close() }()
			if err := wsutil.WriteClientText(conn, []byte("hello")); err != nil {
				t.Fatal(err)
			}
			if _, _, err := wsutil.ReadServerData(conn); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			if !p.SetLicenseRevoked(p.CurrentConfig(), true) {
				t.Fatal("revocation not published")
			}
			if err := wsutil.WriteClientMessage(conn, op, []byte("plain2")); err != nil {
				t.Fatal(err)
			}
			if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			_, _, readErr := wsutil.ReadServerData(conn)
			if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, net.ErrClosed) {
				t.Errorf("revocation must close without a policy frame: %v", readErr)
			}
			testwait.For(t, 3*time.Second, func() bool {
				entries, err := os.ReadDir(rph.dir)
				if err != nil {
					return false
				}
				for _, entry := range entries {
					if !strings.HasSuffix(entry.Name(), ".jsonl") {
						continue
					}
					data, err := os.ReadFile(filepath.Join(rph.dir, entry.Name()))
					if err != nil {
						continue
					}
					for _, line := range strings.Split(string(data), "\n") {
						if json.Valid([]byte(line)) && strings.Contains(line, "session_close") && strings.Contains(line, "license_revoked") {
							return true
						}
					}
				}
				return false
			}, "signed revocation session close")
			outcome := false
			for _, rcpt := range rph.findReceipts(t) {
				if err := receipt.VerifyWithKey(rcpt, rph.pubHex); err != nil {
					t.Fatal(err)
				}
				if rcpt.ActionRecord.Layer == receiptOutcomeLayer && strings.Contains(rcpt.ActionRecord.Pattern, "reason=license_revoked") {
					outcome = true
				}
				if rcpt.ActionRecord.Layer == "dlp" || strings.Contains(rcpt.ActionRecord.Pattern, "dlp_match") {
					t.Errorf("revocation misclassified as DLP: %+v", rcpt.ActionRecord)
				}
			}
			if !outcome {
				t.Fatal("signed license_revoked outcome missing")
			}
		})
	}
}
