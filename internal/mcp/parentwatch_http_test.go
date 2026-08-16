// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func deadSessionExitHooks() *sessionExitTestHooks {
	return &sessionExitTestHooks{
		watch: parentWatchOpts{
			interval:  time.Millisecond,
			startPPID: 4242,
			getppid:   func() int { return orphanedPPID },
		},
	}
}

func liveSessionExitHooks() *sessionExitTestHooks {
	return &sessionExitTestHooks{
		watch: parentWatchOpts{
			interval:  time.Millisecond,
			startPPID: 4242,
			getppid:   func() int { return 4242 },
		},
	}
}

func TestSessionExit_HTTPForwardStopsBridge(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Errorf("session-bound bridge forwarded after its session exited")
	}))
	defer upstream.Close()
	sc := testScannerForHTTP(t)

	clientIn := newBlockingReader()
	defer func() { _ = clientIn.Close() }()
	var clientOut, logBuf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- RunHTTPProxy(context.Background(), clientIn, &clientOut, &logBuf, upstream.URL, nil, MCPProxyOpts{
			Scanner:            sc,
			sessionExitForTest: deadSessionExitHooks(),
		})
	}()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("RunHTTPProxy = %v, want clean session exit", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP bridge stayed alive after the spawning session exited")
	}

	if got := logBuf.String(); !bytes.Contains([]byte(got), []byte("spawning session exited")) {
		t.Errorf("missing session-exit explanation in operator log, got %q", got)
	}
}

func TestSessionExit_HTTPForwardLiveSessionIsNotTornDown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Errorf("live session should not send a request in this test")
	}))
	defer upstream.Close()
	sc := testScannerForHTTP(t)

	clientIn := newBlockingReader()
	var clientOut, logBuf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunHTTPProxy(ctx, clientIn, &clientOut, &logBuf, upstream.URL, nil, MCPProxyOpts{
			Scanner:            sc,
			sessionExitForTest: liveSessionExitHooks(),
		})
	}()

	select {
	case err := <-done:
		t.Fatalf("RunHTTPProxy exited while its session was alive: %v; log: %q", err, logBuf.String())
	case <-time.After(250 * time.Millisecond):
	}

	if got := logBuf.String(); bytes.Contains([]byte(got), []byte("spawning session exited")) {
		t.Errorf("session-exit path ran against a live parent, got %q", got)
	}

	_ = clientIn.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP bridge did not stop after its input closed")
	}
}

func TestSessionExit_HTTPListenerStops(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	sc := testScannerForHTTP(t)

	listenConfig := net.ListenConfig{}
	ln, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	var logBuf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- RunHTTPListenerProxy(context.Background(), ln, upstream.URL, &logBuf, MCPProxyOpts{
			Scanner:            sc,
			sessionExitForTest: deadSessionExitHooks(),
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunHTTPListenerProxy = %v, want clean session exit", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP listener stayed alive after the spawning session exited")
	}

	if got := logBuf.String(); !bytes.Contains([]byte(got), []byte("spawning session exited")) {
		t.Errorf("missing session-exit explanation in operator log, got %q", got)
	}
}

func TestSessionExit_HTTPListenerLiveSessionIsNotTornDown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	sc := testScannerForHTTP(t)

	listenConfig := net.ListenConfig{}
	ln, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var logBuf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- RunHTTPListenerProxy(ctx, ln, upstream.URL, &logBuf, MCPProxyOpts{
			Scanner:            sc,
			sessionExitForTest: liveSessionExitHooks(),
		})
	}()

	baseURL := "http://" + ln.Addr().String()
	waitForHTTPHealth(t, baseURL)
	select {
	case err := <-done:
		t.Fatalf("HTTP listener exited while its session was alive: %v; log: %q", err, logBuf.String())
	case <-time.After(250 * time.Millisecond):
	}

	if got := logBuf.String(); bytes.Contains([]byte(got), []byte("spawning session exited")) {
		t.Errorf("session-exit path ran against a live parent, got %q", got)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunHTTPListenerProxy after cancel = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP listener did not stop after context cancellation")
	}
}
