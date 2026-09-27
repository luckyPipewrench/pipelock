// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testIdleTimeout = 150 * time.Millisecond

// idleBridge starts a bridge with a short idle timeout in front of a parent
// Unix listener. Accepted parent-side connections arrive on the channel.
func idleBridge(t *testing.T, timeout time.Duration) (*BridgeProxy, <-chan net.Conn, context.CancelFunc) {
	t.Helper()
	socketPath := ProxySocketPath(shortTempDir(t))
	parentLn, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("parent listen: %v", err)
	}
	t.Cleanup(func() { _ = parentLn.Close() })
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := parentLn.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
			accepted <- c
		}
	}()

	bp, err := NewBridgeProxy(socketPath, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewBridgeProxy: %v", err)
	}
	bp.SetIdleTimeout(timeout)
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		_ = bp.Serve(ctx)
		close(serveDone)
	}()
	t.Cleanup(func() {
		cancel()
		<-serveDone
		bp.Close()
	})
	return bp, accepted, cancel
}

func dialBridge(t *testing.T, bp *BridgeProxy, accepted <-chan net.Conn) (net.Conn, net.Conn) {
	t.Helper()
	agent, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", bp.Addr())
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	t.Cleanup(func() { _ = agent.Close() })
	// The bridge dials the parent only after accepting, so push one byte to
	// make the pairing observable, then drain it on the parent side.
	if _, err := agent.Write([]byte{'x'}); err != nil {
		t.Fatalf("agent write: %v", err)
	}
	select {
	case parent := <-accepted:
		buf := make([]byte, 1)
		if _, err := io.ReadFull(parent, buf); err != nil {
			t.Fatalf("parent read: %v", err)
		}
		return agent, parent
	case <-time.After(5 * time.Second):
		t.Fatal("parent never accepted the bridged connection")
	}
	return nil, nil
}

// expectClosed waits for the peer to observe the relay closing.
func expectClosed(t *testing.T, c net.Conn) {
	const within = 3 * time.Second
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 16)
	for {
		_, err := c.Read(buf)
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("relay still open after %v", within)
		}
		return
	}
}

// expectOpen proves the relay still forwards in the parent-to-agent direction.
func expectOpen(t *testing.T, agent, parent net.Conn) {
	t.Helper()
	if _, err := parent.Write([]byte("ok")); err != nil {
		t.Fatalf("parent write on live relay: %v", err)
	}
	_ = agent.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(agent, buf); err != nil {
		t.Fatalf("relay closed while active: %v", err)
	}
	_ = agent.SetReadDeadline(time.Time{})
}

func trackedConns(bp *BridgeProxy) int {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	return len(bp.conns)
}

func waitNoTrackedConns(t *testing.T, bp *BridgeProxy, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for trackedConns(bp) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("bridge still holds %d connections after %v", trackedConns(bp), within)
		}
		time.Sleep(5 * time.Millisecond) // poll-with-deadline
	}
}

func TestBridgeIdle_StalledRelayIsClosed(t *testing.T) {
	bp, accepted, _ := idleBridge(t, testIdleTimeout)
	agent, parent := dialBridge(t, bp, accepted)
	expectClosed(t, agent)
	expectClosed(t, parent)
	waitNoTrackedConns(t, bp, 3*time.Second)
}

// keepAlive sends a byte every tick for the given span, several idle timeouts
// long, so only a shared activity clock keeps the relay open.
func keepAlive(t *testing.T, from, to net.Conn, span time.Duration) {
	t.Helper()
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := to.Read(buf); err != nil {
				readErr <- err
				return
			}
		}
	}()
	ticker := time.NewTicker(testIdleTimeout / 4)
	defer ticker.Stop()
	end := time.After(span)
	for {
		select {
		case <-end:
			_ = to.SetReadDeadline(time.Now()) // stop the reader goroutine
			<-readErr
			_ = to.SetReadDeadline(time.Time{})
			return
		case err := <-readErr:
			t.Fatalf("relay closed during steady traffic: %v", err)
		case <-ticker.C:
			if _, err := from.Write([]byte{'.'}); err != nil {
				t.Fatalf("write during steady traffic: %v", err)
			}
		}
	}
}

func TestBridgeIdle_ParentToAgentTrafficKeepsRelayOpen(t *testing.T) {
	bp, accepted, _ := idleBridge(t, testIdleTimeout)
	agent, parent := dialBridge(t, bp, accepted)
	keepAlive(t, parent, agent, 5*testIdleTimeout)
	expectOpen(t, agent, parent)
}

func TestBridgeIdle_AgentToParentTrafficKeepsRelayOpen(t *testing.T) {
	bp, accepted, _ := idleBridge(t, testIdleTimeout)
	agent, parent := dialBridge(t, bp, accepted)
	keepAlive(t, agent, parent, 5*testIdleTimeout)
	expectOpen(t, agent, parent)
}

func TestBridgeIdle_HalfCloseStillDeliversResponse(t *testing.T) {
	bp, accepted, _ := idleBridge(t, testIdleTimeout)
	agent, parent := dialBridge(t, bp, accepted)
	if err := agent.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("agent CloseWrite: %v", err)
	}
	_ = parent.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := parent.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("parent did not see agent EOF: %v", err)
	}
	expectOpen(t, agent, parent)
}

// A parent that hangs up while the agent stays silent used to leave the
// agent-to-parent copy blocked forever.
func TestBridgeIdle_SilentAgentAfterParentHangupIsReaped(t *testing.T) {
	bp, accepted, _ := idleBridge(t, testIdleTimeout)
	agent, parent := dialBridge(t, bp, accepted)
	_ = parent.Close()
	_ = agent.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := agent.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("agent did not see parent EOF: %v", err)
	}
	waitNoTrackedConns(t, bp, 3*time.Second)
}

func TestBridgeIdle_ContextCancelClosesActiveRelays(t *testing.T) {
	// A long idle timeout proves cancellation, not the watchdog, closed it.
	bp, accepted, cancel := idleBridge(t, time.Hour)
	agent, parent := dialBridge(t, bp, accepted)
	cancel()
	expectClosed(t, agent)
	expectClosed(t, parent)
}

func TestBridgeIdle_DefaultAndReset(t *testing.T) {
	bp, err := NewBridgeProxy(ProxySocketPath(shortTempDir(t)), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bp.Close()
	if bp.idleTimeout != DefaultBridgeIdleTimeout {
		t.Fatalf("default idle timeout = %v", bp.idleTimeout)
	}
	bp.SetIdleTimeout(time.Second)
	bp.SetIdleTimeout(0)
	if bp.idleTimeout != DefaultBridgeIdleTimeout {
		t.Fatalf("non-positive timeout did not restore default: %v", bp.idleTimeout)
	}
}

func TestParseBridgeIdleTimeout(t *testing.T) {
	maxSecs := strconv.FormatInt(int64(maxBridgeIdleTimeout/time.Second), 10)
	tests := []struct {
		raw  string
		want time.Duration
	}{
		{"", DefaultBridgeIdleTimeout},
		{"abc", DefaultBridgeIdleTimeout},
		{"0", DefaultBridgeIdleTimeout},
		{"-5", DefaultBridgeIdleTimeout},
		{"1.5", DefaultBridgeIdleTimeout},
		{"99999999999999999999", maxBridgeIdleTimeout},
		{"-99999999999999999999", DefaultBridgeIdleTimeout},
		{maxSecs + "0", maxBridgeIdleTimeout},
		{"6048000", 6048000 * time.Second},
		{"1", time.Second},
		{"120", 120 * time.Second},
		{maxSecs, maxBridgeIdleTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := parseBridgeIdleTimeout(tt.raw); got != tt.want {
				t.Fatalf("parseBridgeIdleTimeout(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestRelayActivityIdleForIsMonotonic(t *testing.T) {
	a := newRelayActivity()
	a.touch()
	if idle := a.idleFor(); idle < 0 || idle > time.Second {
		t.Fatalf("fresh idleFor = %v", idle)
	}
	// Rewinding start simulates elapsed monotonic time without the wall clock.
	a.start = a.start.Add(-time.Minute)
	if idle := a.idleFor(); idle < time.Minute {
		t.Fatalf("idleFor after a minute = %v", idle)
	}
	if !strings.Contains(a.start.String(), "m=") {
		t.Fatal("activity clock lost its monotonic reading")
	}
}

func TestBridgeIdleTimeoutEnvEntryRoundTrip(t *testing.T) {
	if got := bridgeIdleTimeoutEnvEntry(0); got != nil {
		t.Fatalf("zero timeout produced %v", got)
	}
	if got := bridgeIdleTimeoutEnvEntry(500 * time.Millisecond); got != nil {
		t.Fatalf("sub-second timeout produced %v", got)
	}
	entry := bridgeIdleTimeoutEnvEntry(90 * time.Second)
	want := bridgeIdleTimeoutEnv + "=90"
	if len(entry) != 1 || entry[0] != want {
		t.Fatalf("entry = %v, want [%s]", entry, want)
	}
	if got := parseBridgeIdleTimeout("90"); got != 90*time.Second {
		t.Fatalf("round trip = %v", got)
	}
}
