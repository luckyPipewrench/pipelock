// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func viewCmd() *cobra.Command {
	var control bool
	var socket string
	cmd := &cobra.Command{
		Use: "view", Short: "Connect a VNC client to the contained display", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadForInspection(defaultConfigDir + "/pipelock.yaml")
			if err != nil {
				return fmt.Errorf("load viewer configuration: %w", err)
			}
			v := cfg.Containment.Display.Viewer
			if v.Enabled == nil || !*v.Enabled {
				return errors.New("contained display viewer is disabled")
			}
			account, err := user.Current()
			if err != nil {
				return fmt.Errorf("current viewer user: %w", err)
			}
			if v.OperatorUser == "" || account.Username != v.OperatorUser {
				return errors.New("contain view requires the configured operator user")
			}
			if socket == "" {
				runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
				if runtimeDir == "" {
					return errors.New("XDG_RUNTIME_DIR is unset; provide --socket PATH")
				}
				socket = filepath.Join(runtimeDir, "pipelock-contain-view.sock")
			}
			mode := "view"
			if control {
				mode = "control"
			}
			return runContainView(cmd.Context(), socket, viewerControlSocket, mode, currentViewerUID(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().BoolVar(&control, "control", false, "allow keyboard and pointer control")
	cmd.Flags().StringVar(&socket, "socket", "", "local Unix socket for the VNC client")
	return cmd
}

func currentViewerUID() uint32 {
	// Linux uid_t is uint32. An out-of-range value maps to (uid_t)-1, which
	// the kernel never reports as a peer credential, so the peer check fails closed.
	uid := os.Geteuid()
	if uid < 0 || uid > math.MaxUint32-1 {
		return math.MaxUint32
	}
	return uint32(uid)
}

func runContainView(ctx context.Context, socketPath, controlPath, mode string, uid uint32, out, errOut io.Writer) error {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return errors.New("viewer socket path must be clean and absolute")
	}
	if mode != "view" && mode != "control" {
		return errors.New("invalid viewer mode")
	}
	if err := removeStaleViewSocket(socketPath, uid); err != nil {
		return err
	}
	oldMask := unix.Umask(0o177)
	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", socketPath)
	unix.Umask(oldMask)
	if err != nil {
		return fmt.Errorf("listen for VNC client: %w", err)
	}
	defer func() { _ = listener.Close() }()
	created, err := os.Lstat(socketPath)
	if err != nil {
		return fmt.Errorf("inspect VNC socket: %w", err)
	}
	defer func() {
		current, statErr := os.Lstat(socketPath)
		if statErr == nil && os.SameFile(created, current) {
			_ = os.Remove(socketPath)
		}
	}()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("restrict VNC socket: %w", err)
	}
	if _, err := fmt.Fprintln(out, socketPath); err != nil {
		return fmt.Errorf("print VNC socket: %w", err)
	}
	if _, err := fmt.Fprintf(out, "ssh -L 5901:%s <host>\n", socketPath); err != nil {
		return fmt.Errorf("print SSH forwarding example: %w", err)
	}
	if _, err := fmt.Fprintln(out, "Connect a VNC client to localhost:5901"); err != nil {
		return fmt.Errorf("print VNC connection example: %w", err)
	}
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		local, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept VNC client: %w", acceptErr)
		}
		go func() {
			if err := bridgeViewClient(ctx, local, controlPath, mode, uid); err != nil {
				_, _ = fmt.Fprintf(errOut, "VNC client: %v\n", err)
			}
		}()
	}
}

func removeStaleViewSocket(path string, uid uint32) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect VNC socket: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("viewer socket path is a symlink")
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("viewer socket path is not a socket")
	}
	owner, ok := fileOwnerUID(info)
	if !ok || owner != uid {
		return errors.New("viewer socket is not owned by the caller")
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	active, dialErr := (&net.Dialer{}).DialContext(probeCtx, "unix", path)
	if dialErr == nil {
		_ = active.Close()
		return errors.New("viewer socket is already active")
	}
	if !errors.Is(dialErr, unix.ECONNREFUSED) {
		return fmt.Errorf("check stale VNC socket: %w", dialErr)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale VNC socket: %w", err)
	}
	return nil
}

func bridgeViewClient(ctx context.Context, local net.Conn, controlPath, mode string, uid uint32) error {
	defer func() { _ = local.Close() }()
	if !viewerPeerAllowed(local, uid) {
		return errors.New("local VNC peer uid does not match operator")
	}
	remote, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", controlPath)
	if err != nil {
		return fmt.Errorf("connect viewer control socket: %w", err)
	}
	defer func() { _ = remote.Close() }()
	_ = remote.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(remote, mode+"\n"); err != nil {
		return fmt.Errorf("request viewer mode: %w", err)
	}
	response, err := readViewerMode(remote)
	if err != nil {
		return fmt.Errorf("read viewer response: %w", err)
	}
	if response != "ok\n" {
		return fmt.Errorf("viewer %s: %s", mode, strings.TrimSpace(response))
	}
	_ = remote.SetDeadline(time.Time{})
	done := make(chan error, 1)
	go func() { _, copyErr := io.Copy(local, remote); done <- copyErr; _ = local.Close() }()
	_, clientErr := io.Copy(remote, local)
	_ = remote.Close()
	_ = local.Close()
	serverErr := <-done
	if clientErr != nil && !errors.Is(clientErr, net.ErrClosed) {
		return fmt.Errorf("read VNC client: %w", clientErr)
	}
	if serverErr != nil && !errors.Is(serverErr, net.ErrClosed) {
		return fmt.Errorf("read viewer stream: %w", serverErr)
	}
	return nil
}
