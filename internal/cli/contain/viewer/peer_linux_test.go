// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package viewer

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPeerUIDReadsUnixCredentialsAndRejectsOtherTransport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rfb.sock")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	client, err := (&net.Dialer{}).DialContext(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	uid, err := peerUID(server)
	if err != nil || uid != uint32(os.Getuid()) {
		t.Fatalf("Unix peer uid=%d err=%v, want %d", uid, err, os.Getuid())
	}
	first, second := net.Pipe()
	defer func() { _ = first.Close(); _ = second.Close() }()
	if _, err := peerUID(first); err == nil || !strings.Contains(err.Error(), "Unix") {
		t.Fatalf("non-Unix peer error=%v", err)
	}
}
