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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Forward streams retain their entitlement lifetime after admission.
func TestForwardSSELicenseRevocation(t *testing.T) { exerciseLicensedSSE(t, true) }
func TestForwardSSELicenseControl(t *testing.T)    { exerciseLicensedSSE(t, false) }

func exerciseLicensedSSE(t *testing.T, revoke bool) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: one\n\n")
		fl.Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "data: two\n\n")
		fl.Flush()
		<-r.Context().Done()
	}))
	defer up.Close()
	addr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		revocationConnectionConfig(cfg)
		cfg.FlightRecorder.RequireReceipts = true
	})
	defer cleanup()
	if ra, ok := p.Edition().LookupProfile("client"); !ok || ra.LicenseRevoked == nil {
		t.Fatal("positive control: paid profile not selectable")
	}
	rph := newReceiptProxyHelper(t)
	p.receiptEmitterPtr.Store(rph.emitter)
	defer func() { _ = rph.rec.Close() }()
	conn := dialProxy(t, addr)
	defer func() { _ = conn.Close() }()
	host := strings.TrimPrefix(up.URL, "http://")
	if _, err := fmt.Fprintf(conn, "GET %s/stream HTTP/1.1\r\nHost: %s\r\n\r\n", up.URL, host); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = conn.Close()
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("positive control status %d", resp.StatusCode)
	}
	body := bufio.NewReader(resp.Body)
	readEvent := func() (string, error) {
		var sb strings.Builder
		for {
			line, err := body.ReadString('\n')
			sb.WriteString(line)
			if err != nil {
				return sb.String(), err
			}
			if line == "\n" || line == "\r\n" {
				return sb.String(), nil
			}
		}
	}
	ev, err := readEvent()
	if err != nil || !strings.Contains(ev, "one") {
		t.Fatalf("positive control: first event %q err=%v", ev, err)
	}
	if revoke {
		if !p.SetLicenseRevoked(p.CurrentConfig(), true) {
			t.Fatal("revocation rejected")
		}
		if _, ok := p.Edition().LookupProfile("client"); ok {
			t.Fatal("paid profile still selectable")
		}
	}
	close(release)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	ev, err = readEvent()
	t.Logf("after revocation: event=%q err=%v", ev, err)
	if !revoke {
		if err != nil || !strings.Contains(ev, "two") {
			t.Fatalf("positive control: second event %q err=%v", ev, err)
		}
		return
	}
	if err == nil && strings.Contains(ev, "two") {
		t.Fatalf("paid-profile forward SSE stream delivered post-revocation event %q", ev)
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatalf("connection stayed open: %v", err)
	}
	requireLicenseRevocationOutcome(t, rph)
}
