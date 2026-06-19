// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// streamChunk is the per-tick payload a modeled streaming backend writes.
const streamChunk = "data: token\n\n"

// streamAbortBackend models a real streaming server (SSE / long reasoning
// response): it writes a chunk every gap until it has sent nChunks, and it
// ABORTS early if it observes the client half-close its write direction (the
// relay's CloseWrite on a reaped direction arrives here as a read EOF). This
// is the real-world trigger that turns the per-direction idle reap into a
// stream kill. Returns the listener; the caller closes it.
func streamAbortBackend(t *testing.T, gap time.Duration, nChunks int) net.Listener {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// A real server stops producing when the client goes away. The relay's
		// half-close on a reaped direction surfaces here as a read EOF.
		stop := make(chan struct{})
		go func() {
			_, _ = io.Copy(io.Discard, conn)
			close(stop)
		}()

		ticker := time.NewTicker(gap)
		defer ticker.Stop()
		for i := 0; i < nChunks; i++ {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if _, err := conn.Write([]byte(streamChunk)); err != nil {
					return
				}
			}
		}
	}()
	return ln
}

// disableSNIVerify turns off forward-proxy SNI verification for a test. SNI
// verification reads a TLS ClientHello from the client; a plaintext relay test
// sends no ClientHello, so leaving it on would fail the tunnel on the SNI read
// timeout instead of exercising the relay idle path. SNI verification is
// orthogonal to tunnel liveness, and the relay code under test is identical
// whether or not it ran.
func disableSNIVerify(cfg *config.Config) {
	off := false
	cfg.ForwardProxy.SNIVerification = &off
}

// TestConnectStreamSurvivesSilentClientDirection is the red repro for the
// long-lived-stream kill. A server streams a response (chunks every gap, well
// inside idle_timeout) while the client->server tunnel direction is
// legitimately silent (the request was already sent). The tunnel must stay
// alive while bytes flow in EITHER direction.
//
// Pre-fix: the silent client->server copy loop reaps itself at idle_timeout
// and half-closes the upstream; the modeled server treats that as a hangup and
// aborts, so the client receives only the chunks sent before idle_timeout.
func TestConnectStreamSurvivesSilentClientDirection(t *testing.T) {
	const (
		idleSeconds = 1
		gap         = 300 * time.Millisecond
		nChunks     = 8
	)

	ln := streamAbortBackend(t, gap, nChunks)
	defer func() { _ = ln.Close() }()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ForwardProxy.IdleTimeoutSeconds = idleSeconds
		cfg.ForwardProxy.MaxTunnelSeconds = 30
		disableSNIVerify(cfg)
	})
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	target := ln.Addr().String()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Client never writes again on the client->server direction; it only reads
	// the streamed response, which runs well past idle_timeout.
	want := nChunks * len(streamChunk)
	got := 0
	buf := make([]byte, 256)
	for got < want {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, rErr := br.Read(buf)
		got += n
		if rErr != nil {
			break
		}
	}

	if got < want {
		t.Fatalf("stream killed early: received %d/%d bytes; the silent client->server direction reaped the tunnel at idle_timeout", got, want)
	}
}

// TestConnectIdleReapBothSilent confirms the shared idle clock still reaps a
// genuinely idle tunnel: a backend that accepts but never sends, with a silent
// client, must be torn down near idle_timeout (not held open).
func TestConnectIdleReapBothSilent(t *testing.T) {
	ln := listenHold(t) // accepts, discards, never sends
	defer func() { _ = ln.Close() }()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ForwardProxy.IdleTimeoutSeconds = 1
		disableSNIVerify(cfg)
	})
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	target := ln.Addr().String()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()

	// Both directions silent: the watchdog must reap near idle_timeout. The
	// generous 5s client deadline only guards against a hang; a working reap
	// returns the error well before it.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, rErr := br.Read(make([]byte, 1))
	elapsed := time.Since(start)

	if rErr == nil {
		t.Fatal("expected idle tunnel to be reaped, got no error")
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("idle tunnel closed too early after %v; expected the shared idle timeout to drive teardown", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("idle reap took %v; expected near idle_timeout (1s)", elapsed)
	}
}

// streamThenCloseBackend streams nChunks (one every gap) then closes the
// connection: a normal completed streaming response that ends with a genuine
// EOF rather than an idle reap.
func streamThenCloseBackend(t *testing.T, gap time.Duration, nChunks int) net.Listener {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		ticker := time.NewTicker(gap)
		defer ticker.Stop()
		for i := 0; i < nChunks; i++ {
			<-ticker.C
			if _, err := conn.Write([]byte(streamChunk)); err != nil {
				return
			}
		}
	}()
	return ln
}

// TestConnectStreamCompletesOnServerClose verifies a completed streaming
// response delivers every byte and then propagates EOF, even though the
// client->server direction is silent the whole time. Genuine EOF must
// half-close the peer (no data lost), distinct from an idle reap.
func TestConnectStreamCompletesOnServerClose(t *testing.T) {
	const (
		idleSeconds = 3 // longer than the whole stream so completion is via EOF, not idle
		gap         = 200 * time.Millisecond
		nChunks     = 5
	)

	ln := streamThenCloseBackend(t, gap, nChunks)
	defer func() { _ = ln.Close() }()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ForwardProxy.IdleTimeoutSeconds = idleSeconds
		disableSNIVerify(cfg)
	})
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	target := ln.Addr().String()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	want := nChunks * len(streamChunk)
	got := 0
	buf := make([]byte, 256)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, rErr := br.Read(buf)
		got += n
		if rErr != nil {
			break // expect EOF once the server closes after the last chunk
		}
	}

	if got != want {
		t.Fatalf("completed stream lost data: received %d/%d bytes", got, want)
	}
}

// scriptConn is a controllable net.Conn for exercising relay error and
// teardown branches deterministically. Read and Write delegate to the provided
// funcs; Close unblocks any read parked on the done channel. Only Read, Write,
// and Close are invoked by the relay, so the embedded nil net.Conn is never
// dereferenced.
type scriptConn struct {
	net.Conn
	readFn  func([]byte) (int, error)
	writeFn func([]byte) (int, error)
	done    chan struct{}
	once    sync.Once
}

func newScriptConn(readFn, writeFn func([]byte) (int, error)) *scriptConn {
	return &scriptConn{readFn: readFn, writeFn: writeFn, done: make(chan struct{})}
}

func (s *scriptConn) Read(b []byte) (int, error)  { return s.readFn(b) }
func (s *scriptConn) Write(b []byte) (int, error) { return s.writeFn(b) }

func (s *scriptConn) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}

// blockUntilClosed parks until the conn is closed, then reports closure as a
// read error (mirroring a real conn whose blocked read is woken by Close).
func (s *scriptConn) blockUntilClosed() (int, error) {
	<-s.done
	return 0, errors.New("scriptConn closed")
}

// TestCopyDirWriteErrorTearsDownTunnel covers the copyDir write-error path: a
// read succeeds but the write to the peer fails, which must tear the whole
// tunnel down (closeBoth), not leak the other direction.
func TestCopyDirWriteErrorTearsDownTunnel(t *testing.T) {
	sentOnce := make(chan struct{})
	var clientReadOnce sync.Once

	target := newScriptConn(
		func(_ []byte) (int, error) { return 0, errors.New("blocked read") }, // never feeds the reverse direction
		func(_ []byte) (int, error) { return 0, errors.New("write failed") }, // forces the write-error branch
	)
	client := newScriptConn(
		func(b []byte) (int, error) {
			sent := false
			clientReadOnce.Do(func() {
				b[0] = 'x'
				sent = true
				close(sentOnce)
			})
			if sent {
				return 1, nil
			}
			return 0, errors.New("blocked read")
		},
		func(_ []byte) (int, error) { return 0, errors.New("no write") },
	)
	// Wire blocked reads to wake on Close so both directions terminate.
	target.readFn = func(_ []byte) (int, error) { return target.blockUntilClosed() }
	client.writeFn = func(_ []byte) (int, error) { return client.blockUntilClosed() }

	done := make(chan int64, 1)
	go func() { done <- bidirectionalCopy(client, target, 10*time.Second, time.Time{}, nil) }()

	select {
	case <-done:
		// client->target read returned 'x', target.Write failed, tunnel torn down.
	case <-time.After(3 * time.Second):
		t.Fatal("bidirectionalCopy did not return after a write error")
	}
	<-sentOnce
}

// TestCopyDirShortWriteTearsDownTunnel covers the short-write guard: a writer
// that returns written < n without an error must still tear the tunnel down
// rather than silently drop the unwritten bytes on the next read.
func TestCopyDirShortWriteTearsDownTunnel(t *testing.T) {
	var clientReadOnce sync.Once
	sent := make(chan struct{})

	target := newScriptConn(nil, func(p []byte) (int, error) {
		return len(p) - 1, nil // short write, no error (contract-violating)
	})
	client := newScriptConn(func(b []byte) (int, error) {
		first := false
		clientReadOnce.Do(func() {
			b[0], b[1] = 'x', 'y'
			first = true
			close(sent)
		})
		if first {
			return 2, nil
		}
		return 0, errors.New("blocked read")
	}, nil)
	target.readFn = func(_ []byte) (int, error) { return target.blockUntilClosed() }
	client.writeFn = func(_ []byte) (int, error) { return client.blockUntilClosed() }

	doneCh := make(chan struct{})
	go func() { _ = bidirectionalCopy(client, target, 10*time.Second, time.Time{}, nil); close(doneCh) }()

	select {
	case <-doneCh:
	case <-time.After(3 * time.Second):
		t.Fatal("bidirectionalCopy did not return after a short write")
	}
	<-sent
}

// TestCopyDirPostReadKillSwitch covers the post-read kill-switch check: the
// switch flips active during a read, so the freshly read chunk must NOT be
// forwarded.
func TestCopyDirPostReadKillSwitch(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	ks := killswitch.New(cfg)

	var forwarded bool
	var readOnce sync.Once

	target := newScriptConn(nil, func(_ []byte) (int, error) {
		forwarded = true // a forwarded chunk would call target.Write
		return 0, errors.New("write")
	})
	client := newScriptConn(func(b []byte) (int, error) {
		var done bool
		readOnce.Do(func() {
			ks.SetAPI(true) // activate between the pre-read and post-read checks
			b[0] = 'x'
			done = true
		})
		if done {
			return 1, nil
		}
		return 0, errors.New("blocked read")
	}, nil)
	target.readFn = func(_ []byte) (int, error) { return target.blockUntilClosed() }
	client.writeFn = func(_ []byte) (int, error) { return client.blockUntilClosed() }

	doneCh := make(chan struct{})
	go func() { _ = bidirectionalCopy(client, target, 10*time.Second, time.Time{}, ks); close(doneCh) }()

	select {
	case <-doneCh:
	case <-time.After(3 * time.Second):
		t.Fatal("bidirectionalCopy did not return after kill switch activated")
	}
	if forwarded {
		t.Error("chunk was forwarded after the kill switch activated mid-read")
	}
}

// TestWatchdogKillSwitchOnIdleTunnel covers the watchdog kill-switch path: a
// tunnel that is idle (both directions blocked in Read) must be terminated by
// the watchdog when the kill switch activates, without waiting out the long
// idle timeout. This is the kill-switch responsiveness the watchdog adds.
func TestWatchdogKillSwitchOnIdleTunnel(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	ks := killswitch.New(cfg)

	// Signal when each direction has entered Read so the kill switch is flipped
	// only after both copy loops are parked (so the watchdog, not a copyDir
	// pre-read check, is what terminates the tunnel). Deterministic, no sleep.
	clientReading := make(chan struct{})
	targetReading := make(chan struct{})
	var cOnce, tOnce sync.Once
	client := newScriptConn(nil, nil)
	target := newScriptConn(nil, nil)
	client.readFn = func(_ []byte) (int, error) {
		cOnce.Do(func() { close(clientReading) })
		return client.blockUntilClosed()
	}
	client.writeFn = func(_ []byte) (int, error) { return client.blockUntilClosed() }
	target.readFn = func(_ []byte) (int, error) {
		tOnce.Do(func() { close(targetReading) })
		return target.blockUntilClosed()
	}
	target.writeFn = func(_ []byte) (int, error) { return target.blockUntilClosed() }

	doneCh := make(chan struct{})
	start := time.Now()
	// Long idle timeout: only the watchdog kill-switch path can end this.
	go func() { _ = bidirectionalCopy(client, target, 1*time.Hour, time.Time{}, ks); close(doneCh) }()

	// Once both directions are parked in Read, activate the kill switch.
	<-clientReading
	<-targetReading
	ks.SetAPI(true)

	select {
	case <-doneCh:
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("watchdog took %v to honor the kill switch on an idle tunnel", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watchdog did not terminate the idle tunnel after the kill switch activated")
	}
}
