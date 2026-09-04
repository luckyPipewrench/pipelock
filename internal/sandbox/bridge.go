// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// bridgeListenAddr is the address the child-side bridge proxy listens on
// inside the sandbox network namespace. Agent processes use this as
// HTTP_PROXY/HTTPS_PROXY to route traffic through pipelock's scanner.
const bridgeListenAddr = "127.0.0.1:8888"

// defaultBridgeIdleTimeout bounds how long a bridged connection may sit idle
// (no bytes in either direction) before the watchdog force-closes it. Matches
// the forward proxy's default (internal/config/normalize.go ForwardProxy),
// since this bridge relays the same kind of agent egress traffic, just one
// hop earlier, inside the sandbox namespace.
const defaultBridgeIdleTimeout = 120 * time.Second

// bridgeCopyBufSize is the buffer size for bridge relay reads.
const bridgeCopyBufSize = 32 * 1024

// bridgeWatchdogPollInterval is how often a bridged connection's watchdog
// re-checks the idle clock and the bridge-wide stop signal. Capped at the
// idle timeout so very short idle timeouts still reap promptly.
const bridgeWatchdogPollInterval = 250 * time.Millisecond

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
	listener         net.Listener
	socketPath       string // parent's Unix domain socket path
	wg               sync.WaitGroup
	mu               sync.Mutex
	closed           bool
	failure          error
	failureOnce      sync.Once
	done             chan struct{}
	doneOnce         sync.Once
	watcherDone      chan struct{}
	watcherDoneOnce  sync.Once
	watcherStarted   bool
	conns            map[net.Conn]struct{}
	closeOnce        sync.Once
	teardownOnce     sync.Once
	idleTimeoutNanos atomic.Int64 // time.Duration; 0 or negative disables the idle watchdog
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
	bp := &BridgeProxy{
		listener:    ln,
		socketPath:  socketPath,
		done:        make(chan struct{}),
		watcherDone: make(chan struct{}),
		conns:       make(map[net.Conn]struct{}),
	}
	bp.idleTimeoutNanos.Store(int64(defaultBridgeIdleTimeout))
	return bp, nil
}

// Addr returns the proxy's listen address.
func (bp *BridgeProxy) Addr() string {
	return bp.listener.Addr().String()
}

// SetIdleTimeout overrides the default idle timeout applied to connections
// bridged after this call: a bridged connection with no bytes flowing in
// either direction for longer than d is force-closed. A value <= 0 disables
// the idle watchdog entirely. Safe to call concurrently with Serve.
func (bp *BridgeProxy) SetIdleTimeout(d time.Duration) {
	bp.idleTimeoutNanos.Store(int64(d))
}

// idleTimeout returns the currently configured idle timeout.
func (bp *BridgeProxy) idleTimeout() time.Duration {
	return time.Duration(bp.idleTimeoutNanos.Load())
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
			// A cancelled context is a terminal shutdown signal, same as an
			// explicit Close: stop accepting new connections AND force-close
			// every connection already bridged, so a caller that cancels ctx
			// without also calling Close does not leak them.
			bp.teardown()
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
// listener and every tracked connection. It intentionally does not call
// teardown/Close or set bp.closed: this may run from an active connection
// handler that Close waits on, and - unlike a clean shutdown - Serve must
// still surface the recorded failure even if it observes bp.closed before
// ever reaching its Accept loop (Close/teardown's closed=true would make
// Serve return nil early instead, silently dropping the failure).
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

// teardown marks the bridge permanently closed, stops the listener,
// force-closes every tracked connection (including active bridged
// connections, waking any goroutine blocked on a stalled read), and signals
// done - exactly once, regardless of whether it is triggered by ctx
// cancellation or an explicit Close. Close alone additionally waits for
// handlers to finish; the ctx-cancellation watcher needs the teardown without
// that wait, since it must not block.
func (bp *BridgeProxy) teardown() {
	bp.teardownOnce.Do(func() {
		bp.mu.Lock()
		bp.closed = true
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
		bp.mu.Lock()
		waitForWatcher := bp.watcherStarted
		bp.mu.Unlock()
		bp.teardown()
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
	defer bp.untrackConn(parentConn)
	defer func() { _ = parentConn.Close() }()

	// Bridge data bidirectionally, bounded by an idle timeout and torn down
	// promptly if the bridge itself is told to stop (ctx cancellation, fail,
	// or Close all funnel through bp.done via teardown).
	newBridgeRelay(conn, parentConn, bp.idleTimeout(), bp.done).run()
}

// bridgeRelay relays one bridged agent<->parent connection pair, bounded by
// an idle timeout and a bridge-wide stop signal.
//
// Idle is measured across the whole connection via a single shared activity
// clock: bytes flowing in either direction keep it alive, mirroring
// internal/proxy/relay.go's tunnelRelay (the same liveness contract a
// long-lived MCP/HTTP stream depends on). A single watchdog owns liveness: it
// force-closes both ends when the shared clock expires or stop fires, waking
// any blocked read; a genuine EOF on one direction still half-closes the peer
// so bidirectional teardown is preserved.
//
// This is the sandbox-side sibling of tunnelRelay. It cannot reuse it
// directly: the bridge relays a TCP connection (agent) against a Unix domain
// socket (parent's scanning proxy) rather than two same-kind connections, and
// it runs inside the sandboxed child process, which has no reference to the
// parent process's *killswitch.Controller - bp.done (closed by teardown, see
// Close/fail/the ctx-cancellation watcher in Serve) is what this relay checks
// instead.
type bridgeRelay struct {
	agent, parent net.Conn
	idleTimeout   time.Duration
	stop          <-chan struct{}

	clockStart   time.Time
	lastActivity atomic.Int64 // monotonic nanoseconds since clockStart of the last byte seen in either direction
	closeOnce    sync.Once
}

func newBridgeRelay(agent, parent net.Conn, idleTimeout time.Duration, stop <-chan struct{}) *bridgeRelay {
	return &bridgeRelay{
		agent:       agent,
		parent:      parent,
		idleTimeout: idleTimeout,
		stop:        stop,
		clockStart:  time.Now(),
	}
}

// touch records activity on the shared clock. Called on every successful read
// in either direction so the watchdog treats the connection as alive while
// bytes move on either side.
func (r *bridgeRelay) touch() {
	r.lastActivity.Store(time.Since(r.clockStart).Nanoseconds())
}

// closeBoth tears the connection down exactly once, closing both ends. This is
// what wakes a read blocked on the silent direction.
func (r *bridgeRelay) closeBoth() {
	r.closeOnce.Do(func() {
		_ = r.agent.Close()
		_ = r.parent.Close()
	})
}

func (r *bridgeRelay) run() {
	done := make(chan struct{})
	go r.watchdog(done)

	var wg sync.WaitGroup
	wg.Add(2) //nolint:mnd // two copy directions
	go func() {
		defer wg.Done()
		r.copyDir(r.parent, r.agent) // agent → parent
	}()
	go func() {
		defer wg.Done()
		r.copyDir(r.agent, r.parent) // parent → agent
	}()
	wg.Wait()
	close(done)   // stop the watchdog
	r.closeBoth() // ensure both ends are closed (idempotent)
}

// watchdog owns connection liveness: it force-closes both ends when the
// bridge-wide stop signal fires or the shared idle clock expires, and exits
// once both copy directions have finished on their own.
func (r *bridgeRelay) watchdog(done <-chan struct{}) {
	interval := bridgeWatchdogPollInterval
	if r.idleTimeout > 0 && r.idleTimeout < interval {
		interval = r.idleTimeout
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-r.stop:
			r.closeBoth()
			return
		case <-ticker.C:
			if r.idleTimeout > 0 {
				idleFor := time.Since(r.clockStart) - time.Duration(r.lastActivity.Load())
				if idleFor >= r.idleTimeout {
					r.closeBoth()
					return
				}
			}
		}
	}
}

// copyDir copies src->dst until EOF, error, or the watchdog closes the
// connection. It updates the shared activity clock on every read. A genuine
// EOF half-closes the peer (preserving bidirectional teardown, matching the
// original per-direction CloseWrite behavior for whichever concrete type dst
// is - *net.TCPConn on the agent side, *net.UnixConn on the parent side); any
// other read/write error tears the connection down.
func (r *bridgeRelay) copyDir(dst, src net.Conn) {
	buf := make([]byte, bridgeCopyBufSize)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			r.touch()
			written, wErr := dst.Write(buf[:n])
			// A conforming io.Writer never returns written < n without an
			// error, but treat a short write as a teardown anyway (matching
			// io.Copy's ErrShortWrite) so a misbehaving conn cannot silently
			// drop the unwritten bytes when the next read overwrites buf.
			if wErr == nil && written < n {
				wErr = io.ErrShortWrite
			}
			if wErr != nil {
				r.closeBoth()
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				switch conn := dst.(type) {
				case *net.TCPConn:
					_ = conn.CloseWrite()
				case *net.UnixConn:
					_ = conn.CloseWrite()
				}
			} else {
				// Read error (watchdog/stop close, reset, timeout): tear down.
				r.closeBoth()
			}
			return
		}
	}
}
