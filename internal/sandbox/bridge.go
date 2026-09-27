// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// bridgeListenAddr is the address the child-side bridge proxy listens on
// inside the sandbox network namespace. Agent processes use this as
// HTTP_PROXY/HTTPS_PROXY to route traffic through pipelock's scanner.
const bridgeListenAddr = "127.0.0.1:8888"

// DefaultBridgeIdleTimeout bounds a relay whose two sides have both gone
// quiet when the launcher did not supply a timeout. It matches the larger of
// the forward proxy and WebSocket idle defaults, so the bridge never cuts a
// connection the parent proxy would still keep open.
const DefaultBridgeIdleTimeout = 300 * time.Second

// bridgeIdleTimeoutEnv carries the relay idle timeout, in whole seconds,
// from the launcher to sandbox-init.
const bridgeIdleTimeoutEnv = "__PIPELOCK_SANDBOX_BRIDGE_IDLE_SECONDS"

// bridgeIdleTimeoutEnvEntry returns the control environment entry that hands d to
// sandbox-init. A non-positive d yields no entry, so the child uses the default.
func bridgeIdleTimeoutEnvEntry(d time.Duration) []string {
	secs := int64(d / time.Second)
	if secs <= 0 {
		return nil
	}
	return []string{bridgeIdleTimeoutEnv + "=" + strconv.FormatInt(secs, 10)}
}

// parseBridgeIdleTimeout reads the value sandbox-init received. A missing,
// malformed, or non-positive value falls back to the default rather than to
// an unbounded relay.
func parseBridgeIdleTimeout(raw string) time.Duration {
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || secs <= 0 || secs > int64(maxBridgeIdleTimeout/time.Second) {
		return DefaultBridgeIdleTimeout
	}
	return time.Duration(secs) * time.Second
}

// maxBridgeIdleTimeout keeps a parsed value far from time.Duration overflow.
const maxBridgeIdleTimeout = 7 * 24 * time.Hour

// BridgeProxy runs inside the sandboxed child process. It listens on
// loopback and bridges each TCP connection to the parent's Unix domain
// socket proxy. The parent runs pipelock's scanner on the traffic.
//
// Architecture:
//
//	Agent (HTTP_PROXY=127.0.0.1:8888)
//	  → BridgeProxy (loopback, inside sandbox)
//	  → Unix socket (/tmp/pipelock-sandbox-<pid>/proxy.sock)
//	  → Parent (pipelock proxy + scanner, host namespace)
//	  → Internet
type BridgeProxy struct {
	listener        net.Listener
	socketPath      string // parent's Unix domain socket path
	wg              sync.WaitGroup
	mu              sync.Mutex
	closed          bool
	failure         error
	failureOnce     sync.Once
	done            chan struct{}
	doneOnce        sync.Once
	watcherDone     chan struct{}
	watcherDoneOnce sync.Once
	watcherStarted  bool
	conns           map[net.Conn]struct{}
	closeOnce       sync.Once
	idleTimeout     time.Duration
}

// NewBridgeProxy creates a bridge proxy inside the sandbox namespace.
// socketPath is the Unix domain socket where the parent's proxy listens.
// listenAddr overrides the default listen address if non-empty.
func NewBridgeProxy(socketPath string, listenAddr ...string) (*BridgeProxy, error) {
	addr := bridgeListenAddr
	if len(listenAddr) > 0 && listenAddr[0] != "" {
		addr = listenAddr[0]
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("bridge proxy listen: %w", err)
	}
	return &BridgeProxy{
		listener:    ln,
		socketPath:  socketPath,
		done:        make(chan struct{}),
		watcherDone: make(chan struct{}),
		conns:       make(map[net.Conn]struct{}),
		idleTimeout: DefaultBridgeIdleTimeout,
	}, nil
}

// SetIdleTimeout sets how long a relay may carry no bytes in either direction
// before both of its connections are closed. A non-positive d restores the
// default. It applies to connections accepted after the call.
func (bp *BridgeProxy) SetIdleTimeout(d time.Duration) {
	if d <= 0 {
		d = DefaultBridgeIdleTimeout
	}
	bp.mu.Lock()
	bp.idleTimeout = d
	bp.mu.Unlock()
}

// Addr returns the proxy's listen address.
func (bp *BridgeProxy) Addr() string {
	return bp.listener.Addr().String()
}

// Serve accepts connections and bridges them to the parent's Unix socket.
// It returns nil only when ctx is cancelled or Close shuts down the listener.
// An unexpected listener failure or an unavailable parent socket is fatal.
func (bp *BridgeProxy) Serve(ctx context.Context) error {
	bp.mu.Lock()
	if bp.closed {
		bp.mu.Unlock()
		return nil
	}
	bp.watcherStarted = true
	bp.mu.Unlock()
	go func() {
		defer bp.watcherDoneOnce.Do(func() { close(bp.watcherDone) })
		select {
		case <-ctx.Done():
			bp.mu.Lock()
			_ = bp.listener.Close()
			for conn := range bp.conns {
				_ = conn.Close()
			}
			bp.mu.Unlock()
		case <-bp.done:
		}
	}()

	for {
		conn, err := bp.listener.Accept()
		if err != nil {
			if failure := bp.getFailure(); failure != nil {
				return failure
			}
			if bp.isShutdown(ctx) {
				return nil
			}
			return fmt.Errorf("bridge listener accept: %w", err)
		}
		bp.mu.Lock()
		if bp.closed {
			bp.mu.Unlock()
			_ = conn.Close()
			return nil
		}
		bp.trackConnLocked(conn)
		bp.wg.Add(1)
		bp.mu.Unlock()
		go func(conn net.Conn) {
			defer bp.wg.Done()
			defer bp.untrackConn(conn)
			bp.handleConn(conn)
		}(conn)
	}
}

func (bp *BridgeProxy) isShutdown(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	bp.mu.Lock()
	defer bp.mu.Unlock()
	return bp.closed
}

func (bp *BridgeProxy) getFailure() error {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	return bp.failure
}

// fail records the first fatal bridge failure and wakes Serve by closing the
// listener. It intentionally does not call Close because this may run from an
// active connection handler that Close waits on.
func (bp *BridgeProxy) fail(err error) {
	bp.failureOnce.Do(func() {
		bp.mu.Lock()
		if bp.closed {
			bp.mu.Unlock()
			return
		}
		bp.failure = err
		bp.doneOnce.Do(func() { close(bp.done) })
		_ = bp.listener.Close()
		for conn := range bp.conns {
			_ = conn.Close()
		}
		bp.mu.Unlock()
	})
}

// Close shuts down the proxy and waits for active connections.
func (bp *BridgeProxy) Close() {
	bp.closeOnce.Do(func() {
		bp.doneOnce.Do(func() { close(bp.done) })
		bp.mu.Lock()
		bp.closed = true
		waitForWatcher := bp.watcherStarted
		_ = bp.listener.Close()
		for conn := range bp.conns {
			_ = conn.Close()
		}
		bp.mu.Unlock()
		bp.wg.Wait()
		if waitForWatcher {
			<-bp.watcherDone
		} else {
			// Serve may not have started yet even though the listener already
			// accepted a queued connection. Complete the watcher lifecycle so
			// a later Serve observes closed and callers never wait forever.
			bp.watcherDoneOnce.Do(func() { close(bp.watcherDone) })
		}
	})
}

func (bp *BridgeProxy) trackConn(conn net.Conn) bool {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	if bp.closed {
		return false
	}
	bp.trackConnLocked(conn)
	return true
}

func (bp *BridgeProxy) trackConnLocked(conn net.Conn) {
	bp.conns[conn] = struct{}{}
}

func (bp *BridgeProxy) untrackConn(conn net.Conn) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	delete(bp.conns, conn)
}

// handleConn bridges a single TCP connection from the sandbox to the
// parent's Unix domain socket proxy. Raw TCP forwarding - the parent's
// proxy handles HTTP CONNECT, DLP scanning, etc.
func (bp *BridgeProxy) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Connect to parent's proxy via Unix socket.
	parentConn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", bp.socketPath)
	if err != nil {
		bp.fail(fmt.Errorf("bridge connect to parent proxy: %w", err))
		return
	}
	if !bp.trackConn(parentConn) {
		_ = parentConn.Close()
		return
	}
	bp.mu.Lock()
	idleTimeout := bp.idleTimeout
	bp.mu.Unlock()
	defer bp.untrackConn(parentConn)
	defer func() { _ = parentConn.Close() }()

	// Bridge data bidirectionally. Both directions share one activity clock:
	// a long download while the agent sends nothing is still an active relay.
	activity := &relayActivity{}
	activity.touch()
	relayDone := make(chan struct{})
	defer close(relayDone)
	go watchRelayIdle(idleTimeout, activity, relayDone, conn, parentConn)

	var wg sync.WaitGroup
	wg.Add(2) //nolint:mnd // two copy directions

	go func() {
		defer wg.Done()
		_, _ = io.Copy(parentConn, activityReader{r: conn, a: activity}) // agent → parent
		// Signal parent that agent is done sending.
		if uc, ok := parentConn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, activityReader{r: parentConn, a: activity}) // parent → agent
		// Signal agent that parent is done sending.
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}

// relayActivity records when a relay last moved bytes in either direction.
type relayActivity struct{ last atomic.Int64 }

func (a *relayActivity) touch() { a.last.Store(time.Now().UnixNano()) }

func (a *relayActivity) idleFor() time.Duration {
	return time.Since(time.Unix(0, a.last.Load()))
}

// activityReader marks the relay active whenever a read returns bytes. Being a
// plain struct, it also keeps io.Copy off the splice fast path, which would
// move bytes without passing through this reader.
type activityReader struct {
	r io.Reader
	a *relayActivity
}

func (ar activityReader) Read(p []byte) (int, error) {
	n, err := ar.r.Read(p)
	if n > 0 {
		ar.a.touch()
	}
	return n, err
}

// watchRelayIdle closes both relay connections once neither direction has
// moved bytes for timeout. It returns when done closes. Closing both sides
// also ends a half-closed relay whose remaining direction has gone silent.
func watchRelayIdle(timeout time.Duration, a *relayActivity, done <-chan struct{}, conns ...net.Conn) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-done:
			return
		case <-timer.C:
			idle := a.idleFor()
			if idle >= timeout {
				for _, c := range conns {
					_ = c.Close()
				}
				return
			}
			timer.Reset(timeout - idle)
		}
	}
}
