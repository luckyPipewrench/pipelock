// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// The contained agent keeps the long-standing 127.0.0.1 proxy contract, but
// its network namespace is private and carries no interface and no route, so
// nothing in it can reach the host proxy directly.
//
// A systemd .socket unit cannot supply that listener. systemd.socket(5) states
// plainly that "all network sockets allocated through .socket units are
// allocated in the host's network namespace"; PrivateNetwork= and
// JoinsNamespaceOf= on a socket unit place the ACTIVATED SERVICE's processes in
// a namespace, never the listening socket itself. An earlier revision of this
// feature assumed the opposite and failed at install time, binding the host's
// already-occupied proxy port instead of a fresh one inside the namespace.
//
// So the in-namespace listener has to be created by a process that is already
// in the namespace, which is what this command is. It crosses the boundary
// through a PATHNAME unix socket: network_namespaces(7) isolates only the
// "UNIX domain abstract socket namespace", so a unix socket addressed by a
// filesystem path is reachable from both sides. That is the single doorway,
// and it is a filesystem object with an owner and a mode rather than a route.
//
// systemd-socket-proxyd is not usable here because it can only inherit a
// listener from socket activation, never create one. socat could do it, but
// containment must work on a stock system and socat is not universally
// installed, so the forwarder ships in the binary that already has to be
// present.

const (
	// netnsForwardDialTimeout bounds a single dial of the host doorway. The
	// destination is a local unix socket, so a slow dial means the host side
	// is unhealthy rather than distant.
	netnsForwardDialTimeout = 5 * time.Second
)

type netnsForwardOpts struct {
	listen string
	target string
	// systemdListener takes the listening socket from systemd's socket
	// activation instead of binding one. The host side uses this because the
	// doorway socket's ownership and mode are set by the .socket unit, which
	// a process running as the proxy user could not reproduce: it cannot
	// chgrp a file to a group it does not belong to.
	systemdListener bool
	// targetTCP dials a TCP address instead of a unix path. The host side
	// forwards the doorway to Pipelock's loopback listener.
	targetTCP string
}

func netnsForwardCmd() *cobra.Command {
	opts := netnsForwardOpts{}
	cmd := &cobra.Command{
		Use:   "netns-forward",
		Short: "Forward contained-namespace proxy connections to the host doorway socket",
		Long: `Listen inside the contained agent's private network namespace and forward
each accepted connection to the host's unix doorway socket.

This runs as a systemd service that joins the namespace. It exists because a
systemd socket unit always allocates its listening socket in the host network
namespace, so the in-namespace listener cannot come from socket activation.`,
		Hidden:        true,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.listen == "" && !opts.systemdListener {
				return cliutil.ExitCodeError(cliutil.ExitConfig,
					errors.New("one of --listen or --systemd-listener is required"))
			}
			if opts.listen != "" && opts.systemdListener {
				return cliutil.ExitCodeError(cliutil.ExitConfig,
					errors.New("--listen and --systemd-listener are mutually exclusive"))
			}
			if (opts.target == "") == (opts.targetTCP == "") {
				return cliutil.ExitCodeError(cliutil.ExitConfig,
					errors.New("exactly one of --target or --target-tcp is required"))
			}
			if err := runNetnsForward(cmd.Context(), opts, cmd.ErrOrStderr()); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.listen, "listen", "",
		"TCP address to listen on inside the namespace (e.g. 127.0.0.1:8888)")
	cmd.Flags().StringVar(&opts.target, "target", "",
		"unix socket path on the host to forward accepted connections to")
	cmd.Flags().BoolVar(&opts.systemdListener, "systemd-listener", false,
		"take the listening socket from systemd socket activation instead of binding one")
	cmd.Flags().StringVar(&opts.targetTCP, "target-tcp", "",
		"TCP address to forward accepted connections to")
	return cmd
}

// syncWriter serializes diagnostic writes. Each accepted connection reports
// failures from its own goroutine, and io.Writer promises nothing about
// concurrent use, so interleaved or torn lines are the caller's problem
// unless we take the lock here.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// systemdListenFDStart is the first file descriptor systemd passes to a
// socket-activated service, fixed by the sd_listen_fds protocol.
const systemdListenFDStart = 3

// listenerFromSystemd adopts the single socket systemd passed in. Implemented
// against the documented LISTEN_FDS/LISTEN_PID contract rather than pulling in
// a dependency for twenty lines.
func listenerFromSystemd() (net.Listener, error) {
	if pid := os.Getenv("LISTEN_PID"); pid != strconv.Itoa(os.Getpid()) {
		return nil, fmt.Errorf("LISTEN_PID is %q, not this process; the listener was not passed to us", pid)
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n != 1 {
		return nil, fmt.Errorf("expected exactly one socket from systemd, LISTEN_FDS=%q", os.Getenv("LISTEN_FDS"))
	}
	f := os.NewFile(uintptr(systemdListenFDStart), "systemd-listener")
	if f == nil {
		return nil, errors.New("systemd listener file descriptor is not open")
	}
	defer func() { _ = f.Close() }()
	ln, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("adopt systemd listener: %w", err)
	}
	return ln, nil
}

func (o netnsForwardOpts) dialNetwork() string {
	if o.targetTCP != "" {
		return "tcp"
	}
	return "unix"
}

func (o netnsForwardOpts) dialAddress() string {
	if o.targetTCP != "" {
		return o.targetTCP
	}
	return o.target
}

func runNetnsForward(ctx context.Context, opts netnsForwardOpts, rawErrOut io.Writer) error {
	errOut := &syncWriter{w: rawErrOut}
	// Fail closed on a missing unix doorway rather than accepting connections
	// that cannot go anywhere. An agent that gets a refused connection learns
	// the proxy is down; one that gets an accepted-then-dropped connection
	// sees a network fault and may retry around it. A TCP target is not
	// checked here because refusing at dial time is the same signal.
	if opts.target != "" {
		if _, err := os.Stat(opts.target); err != nil {
			return fmt.Errorf("host doorway socket %s is not usable: %w", opts.target, err)
		}
	}

	var (
		ln     net.Listener
		err    error
		source string
	)
	if opts.systemdListener {
		ln, err = listenerFromSystemd()
		source = "systemd socket activation"
	} else {
		ln, err = (&net.ListenConfig{}).Listen(ctx, "tcp", opts.listen)
		source = opts.listen
	}
	if err != nil {
		return fmt.Errorf("listen on %s: %w", source, err)
	}
	defer func() { _ = ln.Close() }()

	_, _ = fmt.Fprintf(errOut, "pipelock: contained-namespace proxy %s -> %s\n", source, opts.dialAddress())

	var wg sync.WaitGroup
	defer wg.Wait()

	// Closing the listener is what unblocks Accept on shutdown; Accept itself
	// takes no context.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept on %s: %w", source, acceptErr)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proxyOneNetnsConn(ctx, conn, opts.dialNetwork(), opts.dialAddress()); err != nil {
				_, _ = fmt.Fprintf(errOut, "pipelock: contained-namespace proxy connection failed: %v\n", err)
			}
		}()
	}
}

func proxyOneNetnsConn(ctx context.Context, downstream net.Conn, network, target string) error {
	defer func() { _ = downstream.Close() }()

	dialCtx, cancel := context.WithTimeout(ctx, netnsForwardDialTimeout)
	defer cancel()

	upstream, err := (&net.Dialer{}).DialContext(dialCtx, network, target)
	if err != nil {
		return fmt.Errorf("dial host doorway %s: %w", target, err)
	}
	defer func() { _ = upstream.Close() }()

	// Propagate each EOF as a half-close so a peer can finish its response.
	// Keep both connections open until both directions have finished.
	type closeWriter interface{ CloseWrite() error }
	done := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(upstream, downstream)
		if copyErr == nil {
			if writer, ok := upstream.(closeWriter); ok {
				copyErr = writer.CloseWrite()
			}
		}
		done <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(downstream, upstream)
		if copyErr == nil {
			if writer, ok := downstream.(closeWriter); ok {
				copyErr = writer.CloseWrite()
			}
		}
		done <- copyErr
	}()
	var firstErr error
	for range 2 {
		select {
		case err := <-done:
			if firstErr == nil {
				firstErr = err
			}
		case <-ctx.Done():
			return nil
		}
	}
	return firstErr
}
