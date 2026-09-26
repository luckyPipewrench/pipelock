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
	"sync/atomic"
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
				} else if !isTimeout(err) {
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
		uid, expected      uint32
	}{
		{"other", "denied\n", "invalid mode", 42, 42},
		{"view", "denied\n", "peer uid", 43, 42},
		{"view", "denied\n", "peer uid", 1, 0},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			v.cfg.ExpectedUID = tc.expected
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
	v.cfg.ExpectedUID = 0
	v.cfg.PeerUID = func(net.Conn) (uint32, error) { return 0, nil }
	rootOperator, _, rootDone := startViewer(t, v, "view")
	_ = rootOperator.Close()
	<-rootDone
	v.cfg.ExpectedUID = 42
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

func TestViewerFilterDisplayMessagesAndInput(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		clipboard  bool
	}{
		{"view", "view", false},
		{"control", "control", false},
		{"control clipboard", "control", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := testViewer(t)
			v.cfg.Clipboard = tc.clipboard
			operator, server, done := startViewer(t, v, tc.mode)
			handshake := []byte("RFB 003.008\n\x01\x01")
			go func() { _, _ = operator.Write(handshake) }()
			got := make([]byte, len(handshake))
			_ = server.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := io.ReadFull(server, got); err != nil {
				t.Fatal(err)
			}
			messages := [][]byte{
				make([]byte, 20),
				{2, 0, 0, 0},
				{3, 0, 0, 0, 0, 0, 0, 1, 0, 1},
				{4, 1, 0, 0, 0, 0, 0, 65},
				{5, 1, 0, 1, 0, 1},
				{6, 0, 0, 0, 0, 0, 0, 3, 'a', 'b', 'c'},
			}
			for i, message := range messages {
				go func() { _, _ = operator.Write(message) }()
				wantForward := i < 3 || (tc.mode == "control" && (i < 5 || tc.clipboard))
				if wantForward {
					got := make([]byte, len(message))
					_ = server.SetReadDeadline(time.Now().Add(time.Second))
					if _, err := io.ReadFull(server, got); err != nil || string(got) != string(message) {
						t.Fatalf("message %d = %v: %v", i, got, err)
					}
				} else {
					_ = server.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
					if _, err := server.Read(make([]byte, 1)); err == nil {
						t.Fatalf("message %d unexpectedly forwarded", i)
					} else if !isTimeout(err) {
						t.Fatalf("message %d read: %v", i, err)
					}
				}
			}
			_ = operator.Close()
			<-done
		})
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func TestViewerLeaseRenewsWhileConnected(t *testing.T) {
	var seconds atomic.Int64
	base := time.Now()
	v := testViewer(t)
	v.cfg.Now = func() time.Time { return base.Add(time.Duration(seconds.Load()) * time.Second) }
	operator, server, done := startViewer(t, v, "control")
	handshake := []byte("RFB 003.008\n\x01\x01")
	go func() { _, _ = operator.Write(handshake) }()
	got := make([]byte, len(handshake))
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	seconds.Store(20)
	deadline := time.After(12 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		v.mu.Lock()
		expires := v.lease.expires
		v.mu.Unlock()
		if expires.Equal(base.Add(50 * time.Second)) {
			break
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatal("live control lease was not renewed")
		}
	}
	seconds.Store(35)
	key := []byte{4, 1, 0, 0, 0, 0, 0, 65}
	go func() { _, _ = operator.Write(key) }()
	got = make([]byte, len(key))
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(server, got); err != nil || string(got) != string(key) {
		t.Fatalf("renewed control input = %v: %v", got, err)
	}
	_ = operator.Close()
	<-done
}
