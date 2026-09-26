// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package viewer

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func startViewer(t *testing.T, v *Viewer, mode string) (net.Conn, net.Conn, <-chan error) {
	t.Helper()
	client, operator := net.Pipe()
	upstream, server := net.Pipe()
	v.cfg.Dial = func() (net.Conn, error) { return upstream, nil }
	done := make(chan error, 1)
	go func() { done <- v.Serve(context.Background(), client, mode) }()
	_ = operator.SetReadDeadline(time.Now().Add(time.Second))
	line, err := bufio.NewReader(operator).ReadString('\n')
	if err != nil || line != "ok\n" {
		t.Fatalf("viewer response %q: %v", line, err)
	}
	_ = operator.SetReadDeadline(time.Time{})
	t.Cleanup(func() { _ = operator.Close(); _ = server.Close() })
	return operator, server, done
}

func testViewer(t *testing.T) *Viewer {
	t.Helper()
	v, err := New(Config{Display: ":99", SocketPath: "/unused", PeerUID: func(net.Conn) (uint32, error) { return 42, nil }, ExpectedUID: 42})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestViewerModesAndLease(t *testing.T) {
	for _, mode := range []string{"view", "control"} {
		t.Run(mode, func(t *testing.T) {
			v := testViewer(t)
			operator, server, done := startViewer(t, v, mode)
			handshake := []byte("RFB 003.008\n\x01\x01")
			go func() { _, _ = operator.Write(handshake) }()
			got := make([]byte, len(handshake))
			_ = server.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := io.ReadFull(server, got); err != nil || string(got) != string(handshake) {
				t.Fatalf("handshake = %q: %v", got, err)
			}
			request := []byte{3, 0, 0, 0, 0, 0, 0, 1, 0, 1}
			go func() { _, _ = operator.Write(request) }()
			got = make([]byte, len(request))
			if _, err := io.ReadFull(server, got); err != nil || string(got) != string(request) {
				t.Fatalf("framebuffer request = %v: %v", got, err)
			}
			key := []byte{4, 1, 0, 0, 0, 0, 0, 65}
			go func() { _, _ = operator.Write(key) }()
			if mode == "control" {
				got = make([]byte, len(key))
				if _, err := io.ReadFull(server, got); err != nil || string(got) != string(key) {
					t.Fatalf("control input = %v: %v", got, err)
				}
			} else {
				_ = server.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
				if _, err := server.Read(make([]byte, 1)); err == nil {
					t.Fatal("view mode forwarded key input")
				} else if e, ok := err.(net.Error); !ok || !e.Timeout() {
					t.Fatalf("view mode read: %v", err)
				}
			}
			_ = operator.Close()
			<-done
		})
	}
}

func TestViewerBusyAndRelease(t *testing.T) {
	v := testViewer(t)
	first, _, firstDone := startViewer(t, v, "control")
	second, peer := net.Pipe()
	result := make(chan error, 1)
	go func() { result <- v.Serve(context.Background(), second, "control") }()
	line, err := bufio.NewReader(peer).ReadString('\n')
	if err != nil || line != "busy\n" {
		t.Fatalf("second control = %q: %v", line, err)
	}
	if err := <-result; err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("busy reason = %v", err)
	}
	_ = peer.Close()
	_ = first.Close()
	<-firstDone
	third, _, thirdDone := startViewer(t, v, "control")
	_ = third.Close()
	<-thirdDone
}

func TestViewerRejectsModeAndWrongPeer(t *testing.T) {
	v := testViewer(t)
	for _, tc := range []struct {
		mode, line, reason string
		uid                uint32
	}{
		{"other", "denied\n", "invalid mode", 42},
		{"view", "denied\n", "peer uid", 43},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			v.cfg.PeerUID = func(net.Conn) (uint32, error) { return tc.uid, nil }
			client, operator := net.Pipe()
			upstream, server := net.Pipe()
			v.cfg.Dial = func() (net.Conn, error) { return upstream, nil }
			done := make(chan error, 1)
			go func() { done <- v.Serve(context.Background(), client, tc.mode) }()
			line, err := bufio.NewReader(operator).ReadString('\n')
			if err != nil || line != tc.line {
				t.Fatalf("response = %q: %v", line, err)
			}
			if err := <-done; err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("reason = %v", err)
			}
			_ = operator.Close()
			_ = server.Close()
		})
	}
	v.cfg.PeerUID = func(net.Conn) (uint32, error) { return 42, nil }
	operator, _, done := startViewer(t, v, "view")
	_ = operator.Close()
	<-done
}

func TestViewerCap(t *testing.T) {
	v := testViewer(t)
	v.cfg.MaxViewers = 1
	first, _, firstDone := startViewer(t, v, "view")
	second, peer := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- v.Serve(context.Background(), second, "view") }()
	line, err := bufio.NewReader(peer).ReadString('\n')
	if err != nil || line != "denied\n" {
		t.Fatalf("cap response = %q: %v", line, err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "viewer cap") {
		t.Fatalf("cap reason = %v", err)
	}
	_ = peer.Close()
	_ = first.Close()
	<-firstDone
}

func TestViewerCancellation(t *testing.T) {
	v := testViewer(t)
	client, operator := net.Pipe()
	upstream, server := net.Pipe()
	v.cfg.Dial = func() (net.Conn, error) { return upstream, nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- v.Serve(ctx, client, "view") }()
	line, err := bufio.NewReader(operator).ReadString('\n')
	if err != nil || line != "ok\n" {
		t.Fatalf("response = %q: %v", line, err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}
	_ = operator.Close()
	_ = server.Close()
}
