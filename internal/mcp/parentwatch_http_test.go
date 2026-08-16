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

	"github.com/luckyPipewrench/pipelock/internal/testwait"
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
	var clientOut bytes.Buffer
	var logBuf lockedBuffer
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

	testwait.For(t, 5*time.Second, func() bool {
		return bytes.Contains([]byte(logBuf.String()), []byte("spawning session exited"))
	}, "the session-exit explanation to reach the HTTP forwarder log")
}

func TestSessionExit_HTTPForwardBoundsNonClosableInput(t *testing.T) {
	clientIn := newNonClosableBlockingReader()
	t.Cleanup(clientIn.unblock)
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Errorf("session-bound bridge forwarded after its session exited")
	}))
	defer upstream.Close()

	var clientOut, logBuf lockedBuffer
	done := make(chan error, 1)
	go func() {
		done <- RunHTTPProxy(context.Background(), clientIn, &clientOut, &logBuf, upstream.URL, nil, MCPProxyOpts{
			Scanner:            testScannerForHTTP(t),
			sessionExitForTest: deadSessionExitHooks(),
		})
	}()

	select {
	case <-clientIn.started:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP bridge never started reading the non-closable client input")
	}

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("RunHTTPProxy = %v, want clean session-bound shutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP bridge waited indefinitely for non-closable input after session exit")
	}

	clientIn.unblock()
	select {
	case <-clientIn.returned:
	case <-time.After(5 * time.Second):
		t.Fatal("non-closable HTTP input did not release after the test")
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

	var logBuf lockedBuffer
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

	testwait.For(t, 5*time.Second, func() bool {
		return bytes.Contains([]byte(logBuf.String()), []byte("spawning session exited"))
	}, "the session-exit explanation to reach the HTTP listener log")
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
