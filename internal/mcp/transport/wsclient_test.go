package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gobwas/ws"
	gobwasutil "github.com/gobwas/ws/wsutil"
)

// wsTestServer creates an httptest server that upgrades to WebSocket and runs handler.
func wsTestServer(t *testing.T, handler func(conn net.Conn)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}
		handler(conn)
	}))
}

func TestWSClient_SingleTextFrame(t *testing.T) {
	clientDone := make(chan struct{})
	srv := wsTestServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_ = gobwasutil.WriteServerMessage(conn, ws.OpText, []byte(`{"jsonrpc":"2.0","id":1}`))
		<-clientDone
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, err := NewWSClient(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	msg, err := client.ReadMessage()
	close(clientDone)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) != `{"jsonrpc":"2.0","id":1}` { //nolint:goconst // test value
		t.Errorf("unexpected message: %s", msg)
	}
}

func TestWSClient_WriteMessage(t *testing.T) {
	received := make(chan string, 1)
	srv := wsTestServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		msgs, err := gobwasutil.ReadClientMessage(conn, nil)
		if err != nil || len(msgs) == 0 {
			return
		}
		received <- string(msgs[0].Payload)
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, err := NewWSClient(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	err = client.WriteMessage([]byte(`{"jsonrpc":"2.0","method":"test"}`))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case msg := <-received:
		if msg != `{"jsonrpc":"2.0","method":"test"}` {
			t.Errorf("server received unexpected: %s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server to receive message")
	}
}

func TestWSClient_FragmentedMessage(t *testing.T) {
	clientDone := make(chan struct{})
	srv := wsTestServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		// Send a fragmented message: two frames.
		part1 := []byte(`{"json`)
		part2 := []byte(`rpc":"2.0","id":1}`)
		_ = ws.WriteHeader(conn, ws.Header{
			Fin:    false,
			OpCode: ws.OpText,
			Length: int64(len(part1)),
		})
		_, _ = conn.Write(part1)
		// Continuation with FIN.
		_ = ws.WriteHeader(conn, ws.Header{
			Fin:    true,
			OpCode: ws.OpContinuation,
			Length: int64(len(part2)),
		})
		_, _ = conn.Write(part2)
		// Wait for client to finish reading before closing.
		<-clientDone
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, err := NewWSClient(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	msg, err := client.ReadMessage()
	close(clientDone)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	expected := `{"jsonrpc":"2.0","id":1}`
	if string(msg) != expected {
		t.Errorf("got %q, want %q", string(msg), expected)
	}
}

func TestWSClient_BinaryFrameRejected(t *testing.T) {
	clientDone := make(chan struct{})
	srv := wsTestServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_ = gobwasutil.WriteServerMessage(conn, ws.OpBinary, []byte{0x00, 0x01})
		<-clientDone
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, err := NewWSClient(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.ReadMessage()
	close(clientDone)
	if err == nil {
		t.Fatal("expected error for binary frame")
	}
	if !strings.Contains(err.Error(), "binary frame rejected") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWSClient_CloseFrameReturnsEOF(t *testing.T) {
	clientDone := make(chan struct{})
	srv := wsTestServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		// Send a close frame.
		_ = ws.WriteHeader(conn, ws.Header{
			Fin:    true,
			OpCode: ws.OpClose,
			Length: 2,
		})
		// Status code: 1000 (normal closure).
		_, _ = conn.Write([]byte{0x03, 0xE8})
		<-clientDone
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, err := NewWSClient(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.ReadMessage()
	close(clientDone)
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF, got: %v", err)
	}
}

func TestWSClient_PingPong(t *testing.T) {
	pongReceived := make(chan bool, 1)
	clientDone := make(chan struct{})
	srv := wsTestServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		// Send ping.
		_ = gobwasutil.WriteServerMessage(conn, ws.OpPing, []byte("ping"))
		// Read pong response.
		hdr, err := ws.ReadHeader(conn)
		if err != nil {
			return
		}
		payload := make([]byte, hdr.Length)
		if hdr.Length > 0 {
			_, _ = io.ReadFull(conn, payload)
			if hdr.Masked {
				ws.Cipher(payload, hdr.Mask, 0)
			}
		}
		if hdr.OpCode == ws.OpPong {
			pongReceived <- true
		}
		// Send a text message so the client's ReadMessage returns.
		_ = gobwasutil.WriteServerMessage(conn, ws.OpText, []byte(`{"ok":true}`))
		<-clientDone
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, err := NewWSClient(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	// ReadMessage should handle the ping internally and return the text message.
	msg, err := client.ReadMessage()
	close(clientDone)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) != `{"ok":true}` {
		t.Errorf("unexpected message: %s", msg)
	}

	select {
	case <-pongReceived:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("server did not receive pong")
	}
}

func TestWSClient_InvalidUTF8Rejected(t *testing.T) {
	clientDone := make(chan struct{})
	srv := wsTestServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		// Send invalid UTF-8 as a text frame.
		invalid := []byte{0xFF, 0xFE}
		if utf8.Valid(invalid) {
			return // skip if somehow valid
		}
		_ = gobwasutil.WriteServerMessage(conn, ws.OpText, invalid)
		<-clientDone
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, err := NewWSClient(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.ReadMessage()
	close(clientDone)
	if err == nil {
		t.Fatal("expected error for invalid UTF-8")
	}
	if !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWSClient_DialFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := NewWSClient(ctx, "ws://127.0.0.1:1") // port 1 should be unreachable
	if err == nil {
		t.Fatal("expected dial error")
	}
}

func TestWSClient_ConnectionClosed(t *testing.T) {
	srv := wsTestServer(t, func(conn net.Conn) {
		// Close immediately without sending anything.
		_ = conn.Close()
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, err := NewWSClient(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.ReadMessage()
	if err == nil {
		t.Fatal("expected error on closed connection")
	}
}

func TestWSClient_MessageReaderInterface(t *testing.T) {
	// Compile-time check that WSClient implements MessageReader.
	var _ MessageReader = (*WSClient)(nil)
}

func TestWSClient_MessageWriterInterface(t *testing.T) {
	// Compile-time check that WSClient implements MessageWriter.
	var _ MessageWriter = (*WSClient)(nil)
}

func TestWSClient_ReadOversizedFrame(t *testing.T) {
	clientDone := make(chan struct{})
	srv := wsTestServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		// Send a frame header claiming a payload larger than MaxLineSize.
		// The client should reject before allocating.
		_ = ws.WriteHeader(conn, ws.Header{
			Fin:    true,
			OpCode: ws.OpText,
			Length: int64(MaxLineSize) + 1,
		})
		// Don't send the payload; the client should reject on the header alone.
		<-clientDone
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, err := NewWSClient(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.ReadMessage()
	close(clientDone)
	if err == nil {
		t.Fatal("expected error for oversized frame")
	}
	if !strings.Contains(err.Error(), "frame too large") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWSClient_WriteMessageTooLarge(t *testing.T) {
	clientDone := make(chan struct{})
	srv := wsTestServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		<-clientDone
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, err := NewWSClient(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	huge := make([]byte, MaxLineSize+1)
	err = client.WriteMessage(huge)
	close(clientDone)
	if err == nil {
		t.Fatal("expected error for oversized message")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWSClient_NewWSClientFromConn(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()

	wsc := NewWSClientFromConn(client, false)
	if wsc == nil {
		t.Fatal("expected non-nil WSClient")
	}
	if wsc.conn != client {
		t.Error("conn not set correctly")
	}
	if wsc.isServer {
		t.Error("expected client mode")
	}
	_ = wsc.Close()
}

func TestWSClient_NewWSClientFromConn_ServerMode(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()

	wsc := NewWSClientFromConn(client, true)
	if wsc == nil {
		t.Fatal("expected non-nil WSClient")
	}
	if !wsc.isServer {
		t.Error("expected server mode")
	}
	_ = wsc.Close()
}

func TestWSClient_ServerModeWriteUnmasked(t *testing.T) {
	// Verify server-mode WSClient sends unmasked frames.
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	wsc := NewWSClientFromConn(serverConn, true)

	go func() {
		_ = wsc.WriteMessage([]byte(`{"jsonrpc":"2.0","method":"test"}`))
	}()

	// Read the frame header from the client side.
	// Server-mode frames must be unmasked (Masked=false).
	hdr, err := ws.ReadHeader(clientConn)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if hdr.Masked {
		t.Error("server-mode frame should not be masked")
	}
	if hdr.OpCode != ws.OpText {
		t.Errorf("expected text frame, got %v", hdr.OpCode)
	}
	payload := make([]byte, hdr.Length)
	if hdr.Length > 0 {
		_, _ = io.ReadFull(clientConn, payload)
	}
	if string(payload) != `{"jsonrpc":"2.0","method":"test"}` {
		t.Errorf("unexpected payload: %s", payload)
	}
	_ = wsc.Close()
}

func TestWSClient_CloseIdempotent(t *testing.T) {
	clientDone := make(chan struct{})
	srv := wsTestServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		<-clientDone
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, err := NewWSClient(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	close(clientDone)

	// Close twice should not panic.
	_ = client.Close()
	_ = client.Close()
}

func TestWSClient_OversizedControlFrame(t *testing.T) {
	clientDone := make(chan struct{})
	srv := wsTestServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		// Send a ping with payload > 125 bytes (RFC 6455 limit for control frames).
		_ = ws.WriteHeader(conn, ws.Header{
			Fin:    true,
			OpCode: ws.OpPing,
			Length: 126,
		})
		_, _ = conn.Write(make([]byte, 126))
		<-clientDone
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, err := NewWSClient(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.ReadMessage()
	close(clientDone)
	if err == nil {
		t.Fatal("expected error for oversized control frame")
	}
	// The exact error depends on how the WS library parses the malformed
	// control frame. It may report "control frame too large" (our check)
	// or a fragment/parse error from the underlying reader. Either way,
	// the client must reject it — that's what we're testing.
}

func TestWSClient_UnsolicitedPongIgnored(t *testing.T) {
	clientDone := make(chan struct{})
	srv := wsTestServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		// Send unsolicited pong, then a text message.
		_ = gobwasutil.WriteServerMessage(conn, ws.OpPong, []byte("pong"))
		_ = gobwasutil.WriteServerMessage(conn, ws.OpText, []byte(`{"id":1}`))
		<-clientDone
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, err := NewWSClient(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	msg, err := client.ReadMessage()
	close(clientDone)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) != `{"id":1}` { //nolint:goconst // test value
		t.Errorf("expected text message, got: %s", msg)
	}
}
