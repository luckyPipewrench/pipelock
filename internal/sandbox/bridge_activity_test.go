// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestBridgeProxy_ActivityInEitherDirectionRefreshesIdleTimeout(t *testing.T) {
	dir := shortTempDir(t)
	socketPath := ProxySocketPath(dir)
	parentLn, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = parentLn.Close() }()

	parentConnCh := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := parentLn.Accept()
		if acceptErr == nil {
			parentConnCh <- conn
		}
	}()

	bp, err := NewBridgeProxy(socketPath, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewBridgeProxy: %v", err)
	}
	const idleTimeout = 120 * time.Millisecond
	bp.SetIdleTimeout(idleTimeout)

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = bp.Serve(ctx)
	}()
	defer func() {
		cancel()
		bp.Close()
		<-serveDone
	}()

	clientRaw, err := (&net.Dialer{}).DialContext(ctx, "tcp", bp.Addr())
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	client := clientRaw.(*net.TCPConn)
	defer func() { _ = client.Close() }()

	var parent net.Conn
	select {
	case parent = <-parentConnCh:
		defer func() { _ = parent.Close() }()
	case <-time.After(time.Second):
		t.Fatal("bridge never connected to parent socket")
	}

	// Keep the relay alive for several idle-timeout periods. Alternate the
	// active direction so either side independently refreshes the shared clock.
	const rounds = 12
	const interval = 40 * time.Millisecond
	for i := range rounds {
		var src, dst net.Conn
		if i%2 == 0 {
			src, dst = client, parent
		} else {
			src, dst = parent, client
		}
		want := []byte{byte(i)}
		if err := src.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("round %d set write deadline: %v", i, err)
		}
		if _, err := src.Write(want); err != nil {
			t.Fatalf("round %d write after %s: %v", i, time.Duration(i)*interval, err)
		}
		if err := dst.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("round %d set read deadline: %v", i, err)
		}
		got := make([]byte, 1)
		if _, err := io.ReadFull(dst, got); err != nil {
			t.Fatalf("round %d read after %s: %v", i, time.Duration(i)*interval, err)
		}
		if got[0] != want[0] {
			t.Fatalf("round %d got %d, want %d", i, got[0], want[0])
		}
		time.Sleep(interval)
	}
}

func TestBridgeProxy_ClientHalfClosePreservesParentResponse(t *testing.T) {
	dir := shortTempDir(t)
	socketPath := ProxySocketPath(dir)
	parentLn, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = parentLn.Close() }()

	const request = "request before half-close"
	const response = "response after client EOF"
	parentResult := make(chan error, 1)
	go func() {
		conn, acceptErr := parentLn.Accept()
		if acceptErr != nil {
			parentResult <- acceptErr
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			parentResult <- err
			return
		}
		got, readErr := io.ReadAll(conn)
		if readErr != nil {
			parentResult <- readErr
			return
		}
		if string(got) != request {
			parentResult <- &bridgeTestMismatch{got: string(got), want: request}
			return
		}
		_, writeErr := io.WriteString(conn, response)
		parentResult <- writeErr
	}()

	bp, err := NewBridgeProxy(socketPath, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewBridgeProxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = bp.Serve(ctx)
	}()
	defer func() {
		cancel()
		bp.Close()
		<-serveDone
	}()

	clientRaw, err := (&net.Dialer{}).DialContext(ctx, "tcp", bp.Addr())
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	client := clientRaw.(*net.TCPConn)
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("half-close client write side: %v", err)
	}

	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read response after CloseWrite: %v", err)
	}
	if string(got) != response {
		t.Fatalf("response after CloseWrite = %q, want %q", got, response)
	}
	if err := <-parentResult; err != nil {
		t.Fatalf("parent relay: %v", err)
	}
}

type bridgeTestMismatch struct {
	got  string
	want string
}

func (e *bridgeTestMismatch) Error() string {
	return "got " + e.got + ", want " + e.want
}
