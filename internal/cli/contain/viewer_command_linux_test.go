// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain/viewer"
)

func TestViewerControlPeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := viewer.New(viewer.Config{Origin: "https://viewer.example", Display: ":99", Dial: func() (net.Conn, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serveViewerControl(ctx, ln, uint32(os.Geteuid()&0xffff), v, ":99")
	read := func() string {
		t.Helper()
		conn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(line)
	}
	if got := read(); got == "denied" || got == "" {
		t.Fatalf("valid peer ticket = %q", got)
	}
	// A separate control listener with the same client UID must deny when
	// configured for another UID. This is the authorization boundary.
	cancel()
	_ = ln.Close()
	path2 := filepath.Join(t.TempDir(), "denied.sock")
	ln2, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path2)
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go serveViewerControl(ctx2, ln2, uint32((os.Geteuid()+1)&0xffff), v, ":99")
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", path2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(line) != "denied" {
		t.Fatalf("wrong peer got %q", line)
	}
}
