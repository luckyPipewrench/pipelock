//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package proxy

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func requireLicensedWebSocketTeardown(t *testing.T, mutate func(cfg *config.Config), act func(t *testing.T, p *Proxy)) {
	t.Helper()
	backend, stop := wsEchoServer(t)
	defer stop()
	addr, p, cleanup := setupWSProxyDefaultWithProxy(t, mutate)
	defer cleanup()
	conn := dialWS(t, addr, backend)
	defer func() { _ = conn.Close() }()
	if err := wsutil.WriteClientText(conn, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := wsutil.ReadServerData(conn); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	if ra, ok := p.Edition().LookupProfile("client"); !ok || ra.LicenseRevoked == nil {
		t.Fatal("positive control: paid profile not active")
	}
	act(t, p)
	if _, ok := p.Edition().LookupProfile("client"); ok {
		t.Fatal("precondition: paid profile still selectable for new requests")
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := wsutil.WriteClientText(conn, []byte("after")); err != nil {
		t.Logf("closed on write: %v", err)
		return
	}
	if msg, _, err := wsutil.ReadServerData(conn); err == nil {
		t.Fatalf("paid-profile WebSocket kept relaying after entitlement loss: %q", msg)
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatalf("connection stayed open: %v", err)
		}
		t.Logf("closed on read: %v", err)
	}
}

// A committed replacement ends the previous entitlement generation.
func TestLicenseReplacementClosesPreviousGeneration(t *testing.T) {
	requireLicensedWebSocketTeardown(t, revocationConnectionConfig, func(t *testing.T, p *Proxy) {
		next := p.CurrentConfig().Clone()
		next.LicenseKey = "replacement-revoked"
		next.Agents = nil
		if !p.Reload(next, scanner.MustNew(next)) {
			t.Fatal("reload failed")
		}
	})
}

// Expiry closes a paid request even without a CRL refresh.
func TestLicenseExpiryClosesPreviousGeneration(t *testing.T) {
	requireLicensedWebSocketTeardown(t, func(cfg *config.Config) {
		revocationConnectionConfig(cfg)
		cfg.LicenseExpiresAt = time.Now().Add(2 * time.Second).Unix()
	}, func(t *testing.T, p *Proxy) {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok := p.Edition().LookupProfile("client"); !ok {
				return
			}
			select {
			case <-time.After(100 * time.Millisecond):
			case <-t.Context().Done():
				t.Fatal("test canceled")
			}
		}
	})
}

// Runtime revocation closes an established connection.
func TestLicenseRevocationClosesPreviousGeneration(t *testing.T) {
	requireLicensedWebSocketTeardown(t, revocationConnectionConfig, func(t *testing.T, p *Proxy) {
		if !p.SetLicenseRevoked(p.CurrentConfig(), true) {
			t.Fatal("revoke")
		}
	})
}

func TestLicenseGenerationSurvivesAbortedReload(t *testing.T) {
	_, p, cleanup := setupForwardProxyWithInstance(t, revocationConnectionConfig)
	defer cleanup()
	ra, ok := p.Edition().LookupProfile("client")
	if !ok || ra.LicenseRevoked == nil {
		t.Fatal("positive control: paid generation missing")
	}
	for _, replacement := range []bool{false, true} {
		next := p.CurrentConfig().Clone()
		if replacement {
			next.LicenseKey = "replacement"
			next.Agents = nil
		}
		next.MediationEnvelope.VerifyInbound.Enabled = true
		next.MediationEnvelope.VerifyInbound.TrustList = nil
		if p.Reload(next, scanner.MustNew(next)) {
			t.Fatal("invalid reload committed")
		}
		select {
		case <-ra.LicenseRevoked:
			t.Fatal("aborted reload ended live entitlement")
		default:
		}
		if _, ok := p.Edition().LookupProfile("client"); !ok {
			t.Fatal("aborted reload removed paid profile")
		}
	}
}
