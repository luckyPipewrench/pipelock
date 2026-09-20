// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newDoorwayEcho starts a unix listener that echoes what it reads, standing in
// for the host-side doorway socket. It returns the socket path.
func newDoorwayEcho(t *testing.T) string {
	t.Helper()
	// A unix socket path has a hard length limit well below PATH_MAX, so keep
	// it short rather than nesting under a long temp dir name.
	dir, err := os.MkdirTemp("", "plnf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "d.sock")

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatalf("listen unix %s: %v", path, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return path
}

func TestProxyOneNetnsConnForwardsBothDirections(t *testing.T) {
	target := newDoorwayEcho(t)

	// A socketpair stands in for the accepted in-namespace connection: one end
	// is handed to the forwarder, the other is the agent.
	agent, forwarded := net.Pipe()
	t.Cleanup(func() { _ = agent.Close() })

	done := make(chan error, 1)
	go func() { done <- proxyOneNetnsConn(context.Background(), forwarded, "unix", target) }()

	want := []byte("CONNECT example.invalid:443 HTTP/1.1\r\n\r\n")
	if err := agent.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Write(want); err != nil {
		t.Fatalf("write to forwarder: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(agent, got); err != nil {
		t.Fatalf("read echo back through the forwarder: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo = %q, want %q", got, want)
	}

	_ = agent.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forwarder did not return after the agent closed")
	}
}

func TestProxyOneNetnsConnFailsWhenDoorwayIsAbsent(t *testing.T) {
	agent, forwarded := net.Pipe()
	t.Cleanup(func() { _ = agent.Close() })

	err := proxyOneNetnsConn(context.Background(), forwarded, "unix", filepath.Join(t.TempDir(), "missing.sock"))
	if err == nil || !strings.Contains(err.Error(), "dial host doorway") {
		t.Fatalf("err = %v, want a dial failure naming the doorway", err)
	}
}

// The forwarder must refuse to listen at all when the host doorway is absent.
// Accepting connections that cannot be forwarded would show the agent a
// network fault it may retry around, instead of a refused connection that
// says plainly the proxy is not there.
func TestRunNetnsForwardFailsClosedWithoutDoorway(t *testing.T) {
	var out bytes.Buffer
	err := runNetnsForward(context.Background(), netnsForwardOpts{
		listen: "127.0.0.1:0",
		target: filepath.Join(t.TempDir(), "missing.sock"),
	}, &out)
	if err == nil || !strings.Contains(err.Error(), "is not usable") {
		t.Fatalf("err = %v, want a refusal naming the unusable doorway", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want it to wrap os.ErrNotExist", err)
	}
}

// lockedBuffer lets the test read the forwarder's diagnostics while the
// forwarder is still running. The production writer is stderr.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRunNetnsForwardStopsOnContextCancel(t *testing.T) {
	target := newDoorwayEcho(t)
	ctx, cancel := context.WithCancel(context.Background())

	out := &lockedBuffer{}
	done := make(chan error, 1)
	go func() { done <- runNetnsForward(ctx, netnsForwardOpts{listen: "127.0.0.1:0", target: target}, out) }()

	// Wait for the listener to be announced so cancel races the accept loop
	// rather than the setup.
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "contained-namespace proxy") {
		if time.Now().After(deadline) {
			t.Fatal("forwarder never reported its listener")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancel should be a clean shutdown, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forwarder did not stop on context cancellation")
	}
}

func TestNetnsForwardCmdRequiresBothFlags(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--listen", "127.0.0.1:8888"},
		{"--target", "/run/x.sock"},
		// A listener from both sources, or neither target, or both targets.
		{"--listen", "127.0.0.1:8888", "--systemd-listener", "--target", "/run/x.sock"},
		{"--systemd-listener"},
		{"--systemd-listener", "--target", "/run/x.sock", "--target-tcp", "127.0.0.1:8888"},
	} {
		cmd := netnsForwardCmd()
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs(args)
		err := cmd.Execute()
		if err == nil {
			t.Fatalf("args %v: accepted an invalid flag combination", args)
		}
		if !strings.Contains(err.Error(), "required") && !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("args %v: err = %v, want a flag-combination refusal", args, err)
		}
	}
}
