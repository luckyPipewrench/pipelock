// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func sandboxCmd() *cobra.Command {
	var workspace string
	var configFile string
	var strict bool

	cmd := &cobra.Command{
		Use:   "sandbox [flags] -- COMMAND [ARGS...]",
		Short: "Run a command in an unprivileged sandbox (Linux only)",
		Long: `Runs a command with three layers of unprivileged containment:

  - Landlock: restricts filesystem access (read, write, exec)
  - seccomp: blocks dangerous syscalls (ptrace, mount, io_uring)
  - Network namespace: isolates network (traffic routed through pipelock scanner)

Agent HTTP/HTTPS traffic is routed through pipelock's full scanner pipeline
(DLP, SSRF, blocklist, rate limiting, entropy analysis) via a bridge proxy.

Examples:
  pipelock sandbox -- python agent.py
  pipelock sandbox --workspace /home/user/project -- node server.js
  pipelock sandbox --config pipelock.yaml -- bash -c "curl https://example.com"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dashIdx := cmd.ArgsLenAtDash()
			if dashIdx < 0 || dashIdx >= len(args) {
				return errors.New("usage: pipelock sandbox -- COMMAND [ARGS...]")
			}
			command := args[dashIdx:]

			// Load config for scanner.
			cfg, err := loadConfigOrDefault(configFile)
			if err != nil {
				return err
			}

			// Resolve workspace: CLI flag > config > cwd.
			if workspace == "" {
				workspace = cfg.Sandbox.Workspace
			}
			if workspace == "" {
				workspace, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("resolving workspace: %w", err)
				}
			}
			workspace, _ = filepath.Abs(workspace)

			// Force forward proxy enabled — sandbox bridge requires it.
			cfg.ForwardProxy.Enabled = true

			sc := scanner.New(cfg)
			defer sc.Close()

			m := metrics.New()
			logger := audit.NewNop() // standalone sandbox uses stderr, not structured audit

			// Build the proxy once, share across connections.
			p, pErr := proxy.New(cfg, logger, sc, m)
			if pErr != nil {
				return fmt.Errorf("proxy init: %w", pErr)
			}
			handler := p.Handler()

			_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
				"pipelock: launching sandboxed process %v (workspace=%s, mode=%s)\n",
				command, workspace, cfg.Mode)

			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			// ProxyHandler: each connection from the sandboxed agent goes
			// through pipelock's full scanner pipeline via an HTTP server
			// that handles both CONNECT tunnels and plain HTTP forwarding.
			//
			// We use http.Server.Serve with a single-connection listener.
			// After the request is served (including CONNECT hijack/tunnel),
			// Serve returns because the next Accept returns ErrClosed.
			proxyHandler := func(conn net.Conn) {
				srv := &http.Server{
					Handler:           handler,
					ReadHeaderTimeout: 30 * time.Second, // prevent slowloris
					IdleTimeout:       30 * time.Second, // don't hold idle connections
				}
				_ = srv.Serve(&singleConnListener{conn: conn})
			}

			useStrict := strict || cfg.Sandbox.Strict

			launchCfg := sandbox.StandaloneLaunchConfig{
				Ctx:          ctx,
				Command:      command,
				Workspace:    workspace,
				Strict:       useStrict,
				ProxyHandler: proxyHandler,
			}

			// Merge custom filesystem policy from config into defaults.
			if cfg.Sandbox.FS != nil {
				p := sandbox.PlatformDefaultPolicy(workspace)
				p.AllowReadDirs = append(p.AllowReadDirs, cfg.Sandbox.FS.AllowRead...)
				p.AllowRWDirs = append(p.AllowRWDirs, cfg.Sandbox.FS.AllowWrite...)
				launchCfg.Policy = &p
			}

			return sandbox.LaunchStandalone(launchCfg)
		},
	}

	cmd.Flags().StringVar(&workspace, "workspace", "", "sandbox workspace directory (default: current directory)")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	cmd.Flags().BoolVar(&strict, "strict", false, "strict mode: error if any containment layer is unavailable, mount private /dev/shm, block clone3")
	return cmd
}

// singleConnListener wraps a net.Conn as a net.Listener that returns
// exactly one connection then ErrClosed on subsequent calls.
type singleConnListener struct {
	conn net.Conn
	done bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, net.ErrClosed
	}
	l.done = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
