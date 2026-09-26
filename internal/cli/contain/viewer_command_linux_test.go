// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"bufio"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain/viewer"
)

func TestViewerControlProtocolAndPeer(t *testing.T) {
	for _, tc := range []struct {
		name, mode, response string
		uid                  uint32
	}{
		{"view", "view\n", "ok\n", currentViewerUID()},
		{"control", "control\n", "ok\n", currentViewerUID()},
		{"unknown mode", "other\n", "denied\n", currentViewerUID()},
		{"wrong peer", "view\n", "denied\n", currentViewerUID() + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "control.sock")
			ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			upstream, server := net.Pipe()
			defer func() { _ = server.Close() }()
			v, err := viewer.New(viewer.Config{Display: ":99", Dial: func() (net.Conn, error) { return upstream, nil }})
			if err != nil {
				t.Fatal(err)
			}
			go serveViewerControl(ctx, ln, tc.uid, v)
			conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if _, err := conn.Write([]byte(tc.mode)); err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil || line != tc.response {
				t.Fatalf("response = %q: %v", line, err)
			}
		})
	}
}

func TestReadViewerModeDoesNotConsumeRFB(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close(); _ = client.Close() }()
	go func() { _, _ = client.Write([]byte("view\nRFB 003.008\n")) }()
	mode, err := readViewerMode(server)
	if err != nil || mode != "view\n" {
		t.Fatalf("mode = %q: %v", mode, err)
	}
	buf := make([]byte, 12)
	if _, err := server.Read(buf); err != nil || !strings.HasPrefix(string(buf), "RFB") {
		t.Fatalf("RFB prefix = %q: %v", buf, err)
	}
}
