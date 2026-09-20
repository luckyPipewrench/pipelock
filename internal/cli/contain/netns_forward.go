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
			if opts.listen == "" || opts.target == "" {
				return cliutil.ExitCodeError(cliutil.ExitConfig,
					errors.New("both --listen and --target are required"))
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
	return cmd
}

func runNetnsForward(ctx context.Context, opts netnsForwardOpts, errOut io.Writer) error {
	// Fail closed on a missing doorway rather than accepting connections that
	// cannot go anywhere. An agent that gets a refused connection learns the
	// proxy is down; one that gets an accepted-then-dropped connection sees a
	// network fault and may retry around it.
	if _, err := os.Stat(opts.target); err != nil {
		return fmt.Errorf("host doorway socket %s is not usable: %w", opts.target, err)
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", opts.listen)
	if err != nil {
		return fmt.Errorf("listen %s inside the contained namespace: %w", opts.listen, err)
	}
	defer func() { _ = ln.Close() }()

	_, _ = fmt.Fprintf(errOut, "pipelock: contained-namespace proxy %s -> %s\n", opts.listen, opts.target)

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
			return fmt.Errorf("accept on %s: %w", opts.listen, acceptErr)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proxyOneNetnsConn(ctx, conn, opts.target); err != nil {
				_, _ = fmt.Fprintf(errOut, "pipelock: contained-namespace proxy connection failed: %v\n", err)
			}
		}()
	}
}

func proxyOneNetnsConn(ctx context.Context, downstream net.Conn, target string) error {
	defer func() { _ = downstream.Close() }()

	dialCtx, cancel := context.WithTimeout(ctx, netnsForwardDialTimeout)
	defer cancel()

	upstream, err := (&net.Dialer{}).DialContext(dialCtx, "unix", target)
	if err != nil {
		return fmt.Errorf("dial host doorway %s: %w", target, err)
	}
	defer func() { _ = upstream.Close() }()

	// Copy both directions and return once either side finishes, closing both
	// so the other copy cannot outlive the connection.
	done := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(upstream, downstream)
		done <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(downstream, upstream)
		done <- copyErr
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return nil
	}
}
