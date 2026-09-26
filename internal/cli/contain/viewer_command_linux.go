// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain/viewer"
)

func viewerCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "viewer", Hidden: true}
	var display, rfbSocket, operator, agentUser string
	var clipboard bool
	serve := &cobra.Command{
		Use: "serve", Hidden: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if operator == "" || agentUser == "" || rfbSocket == "" || display == "" {
				return errors.New("viewer service requires operator, agent user, display, and RFB socket")
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
			v, err := viewer.New(viewer.Config{Display: display, SocketPath: rfbSocket, Clipboard: clipboard, ExpectedUID: uint32(agentUID)})
			if err != nil {
				return err
			}
			// Create the socket private rather than tightening it after bind.
			oldUmask := unix.Umask(0o177)
			listener, err := (&net.ListenConfig{}).Listen(cmd.Context(), "unix", viewerControlSocket)
			unix.Umask(oldUmask)
			if err != nil {
				return fmt.Errorf("viewer control socket: %w", err)
			}
			defer func() { _ = listener.Close() }()
			if err := os.Chmod(viewerControlSocket, 0o600); err != nil {
				return fmt.Errorf("restrict viewer control socket: %w", err)
			}
			if out, code, runErr := realRunCommand(cmd.Context(), "setfacl", "-m", "u:"+operator+":rw", viewerControlSocket); runErr != nil {
				return fmt.Errorf("grant viewer control socket to operator: %w", runErr)
			} else if code != 0 {
				return fmt.Errorf("grant viewer control socket to operator: exit %d: %s", code, out)
			}
			defer func() { _ = os.Remove(viewerControlSocket) }()
			serveViewerControl(cmd.Context(), listener, uint32(uid), v)
			return nil
		},
	}
	serve.Flags().StringVar(&display, "display", "", "managed display")
	serve.Flags().StringVar(&rfbSocket, "rfb-socket", "", "private RFB socket")
	serve.Flags().StringVar(&operator, "operator-user", "", "operator allowed to view the display")
	serve.Flags().StringVar(&agentUser, "agent-user", "", "contained agent owning the RFB server")
	serve.Flags().BoolVar(&clipboard, "clipboard", false, "allow clipboard forwarding")
	cmd.AddCommand(serve)
	return cmd
}

func serveViewerControl(ctx context.Context, listener net.Listener, allowedUID uint32, v *viewer.Viewer) {
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if !viewerPeerAllowed(conn, allowedUID) {
				_, _ = fmt.Fprintln(conn, "denied")
				return
			}
			mode, readErr := readViewerMode(conn)
			if readErr != nil || (mode != "view\n" && mode != "control\n") {
				_, _ = fmt.Fprintln(conn, "denied")
				return
			}
			_ = conn.SetReadDeadline(time.Time{})
			_ = v.Serve(ctx, conn, strings.TrimSuffix(mode, "\n"))
		}()
	}
}

func readViewerMode(conn net.Conn) (string, error) {
	var line [8]byte
	for i := range line {
		if _, err := conn.Read(line[i : i+1]); err != nil {
			return "", fmt.Errorf("read viewer mode: %w", err)
		}
		if line[i] == '\n' {
			return string(line[:i+1]), nil
		}
	}
	return "", errors.New("viewer mode line is too long")
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
