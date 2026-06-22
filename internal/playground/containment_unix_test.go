// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package playground_test

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"golang.org/x/sys/unix"
)

func TestLocalEscapeProbe_UnixSocketRefused_NotBlocked(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "closed.sock")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("create unix socket: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: socketPath}); err != nil {
		_ = unix.Close(fd)
		t.Fatalf("bind unix socket: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("close bound unix socket: %v", err)
	}

	result := playground.ProbeLocalEscape(t.Context(), "unix:"+socketPath)
	if result.Open || result.Blocked {
		t.Fatalf("closed unix socket must be Open=false Blocked=false, got: %+v", result)
	}
	if !strings.Contains(result.Detail, "connection refused") {
		t.Fatalf("detail = %q, want connection refused", result.Detail)
	}
}

func TestLocalEscapeProbe_UnixSocketOpen(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "open.sock")
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer func() { _ = ln.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		_ = conn.Close()
	}()

	result := playground.ProbeLocalEscape(t.Context(), "unix:"+socketPath)
	if !result.Open || result.Blocked {
		t.Fatalf("open unix socket must be Open=true Blocked=false, got: %+v", result)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept goroutine did not finish")
	}
}
