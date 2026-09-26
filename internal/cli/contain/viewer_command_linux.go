// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain/viewer"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const viewerControlSocket = "/run/pipelock-contain-viewer/control.sock"

func viewerCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "viewer", Short: "Open the contained display viewer"}
	var origin, display, rfbSocket, operator, agentUser string
	var clipboard bool
	serve := &cobra.Command{
		Use: "serve", Hidden: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := config.ValidateViewerOrigin(origin); err != nil {
				return err
			}
			if operator == "" || rfbSocket == "" || display == "" {
				return errors.New("viewer service requires operator, display, and RFB socket")
			}
			account, err := user.Lookup(operator)
			if err != nil {
				return fmt.Errorf("viewer operator: %w", err)
			}
			uid, err := strconv.ParseUint(account.Uid, 10, 32)
			if err != nil {
				return fmt.Errorf("viewer operator uid: %w", err)
			}
			agent, err := user.Lookup(agentUser)
			if err != nil {
				return fmt.Errorf("viewer agent user: %w", err)
			}
			agentUID, err := strconv.ParseUint(agent.Uid, 10, 32)
			if err != nil {
				return fmt.Errorf("viewer agent uid: %w", err)
			}
			v, err := viewer.New(viewer.Config{Origin: origin, Display: display, SocketPath: rfbSocket, Clipboard: clipboard, ExpectedUID: uint32(agentUID)})
			if err != nil {
				return err
			}
			listener, err := listenerFromSystemd()
			if err != nil {
				return err
			}
			defer func() { _ = listener.Close() }()
			control, err := (&net.ListenConfig{}).Listen(cmd.Context(), "unix", viewerControlSocket)
			if err != nil {
				return fmt.Errorf("viewer control socket: %w", err)
			}
			defer func() { _ = control.Close() }()
			if err := os.Chmod(viewerControlSocket, 0o600); err != nil {
				return err
			}
			if out, code, err := realRunCommand(cmd.Context(), "setfacl", "-m", "u:"+operator+":rw", viewerControlSocket); err != nil {
				return fmt.Errorf("grant viewer control socket to operator: %w", err)
			} else if code != 0 {
				return fmt.Errorf("grant viewer control socket to operator: exit %d: %s", code, out)
			}
			defer func() { _ = os.Remove(viewerControlSocket) }()
			go serveViewerControl(cmd.Context(), control, uint32(uid), v, display)
			server := &http.Server{Handler: v, ReadHeaderTimeout: 10 * time.Second}
			go func() { <-cmd.Context().Done(); _ = server.Close() }()
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
	}
	serve.Flags().StringVar(&origin, "origin", "", "fixed public HTTPS origin")
	serve.Flags().StringVar(&display, "display", "", "managed display")
	serve.Flags().StringVar(&rfbSocket, "rfb-socket", "", "private RFB socket")
	serve.Flags().StringVar(&operator, "operator-user", "", "operator allowed to mint tickets")
	serve.Flags().StringVar(&agentUser, "agent-user", "", "contained agent owning the RFB server")
	serve.Flags().BoolVar(&clipboard, "clipboard", false, "allow clipboard forwarding")
	open := &cobra.Command{
		Use: "open", Short: "Mint a single-use ticket and print the viewer URL", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadForInspection(defaultConfigDir + "/pipelock.yaml")
			if err != nil {
				return err
			}
			v := cfg.Containment.Display.Viewer
			if v.Enabled == nil || !*v.Enabled {
				return errors.New("viewer disabled")
			}
			if err := config.ValidateViewerOrigin(v.PublicOrigin); err != nil {
				return err
			}
			userName := v.OperatorUser
			if userName == "" {
				userName = os.Getenv("USER")
			}
			current, err := user.Current()
			if err != nil {
				return err
			}
			if current.Username != userName {
				return errors.New("viewer open requires the configured operator user")
			}
			dialer := net.Dialer{Timeout: 5 * time.Second}
			conn, err := dialer.DialContext(cmd.Context(), "unix", viewerControlSocket)
			if err != nil {
				return fmt.Errorf("viewer control socket: %w", err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				return fmt.Errorf("mint viewer ticket: %w", err)
			}
			ticket := strings.TrimSpace(line)
			if ticket == "denied" {
				return errors.New("viewer operator was denied")
			}
			if ticket == "" {
				return errors.New("viewer returned an empty ticket")
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), strings.TrimSuffix(v.PublicOrigin, "/")+"/#ticket="+ticket)
			return err
		},
	}
	cmd.AddCommand(serve, open)
	return cmd
}

func serveViewerControl(ctx context.Context, listener net.Listener, allowedUID uint32, v *viewer.Viewer, display string) {
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if !viewerPeerAllowed(conn, allowedUID) {
				_, _ = fmt.Fprintln(conn, "denied")
				return
			}
			ticket, err := v.MintTicket(display, "control")
			if err != nil {
				return
			}
			_, _ = fmt.Fprintln(conn, ticket)
		}()
	}
}

func viewerPeerAllowed(conn net.Conn, allowedUID uint32) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var peer *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) { peer, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return false
	}
	return socketErr == nil && peer != nil && peer.Uid == allowedUID
}
