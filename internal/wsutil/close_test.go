package wsutil

import (
	"net"
	"testing"
	"time"

	"github.com/gobwas/ws"
)

func TestWriteCloseFrame_BasicClose(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 256)
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := server.Read(buf)
		done <- buf[:n]
	}()

	WriteCloseFrame(client, ws.StatusNormalClosure, "goodbye")

	data := <-done
	if len(data) < 4 {
		t.Fatalf("close frame too short: %d bytes", len(data))
	}
	// First byte: FIN + OpClose (0x88).
	if data[0] != 0x88 {
		t.Errorf("expected FIN+OpClose (0x88), got 0x%02x", data[0])
	}
}

func TestWriteCloseFrame_LongReasonTruncated(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 512)
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := server.Read(buf)
		done <- buf[:n]
	}()

	// Reason longer than 123 bytes should be truncated.
	longReason := make([]byte, 200)
	for i := range longReason {
		longReason[i] = 'a'
	}
	WriteCloseFrame(client, ws.StatusProtocolError, string(longReason))

	data := <-done
	// WS header (2 bytes) + status code (2 bytes) + truncated reason (<=123 bytes).
	// Total payload: 2 + 123 = 125 bytes. Header indicates payload length.
	payloadLen := int(data[1] & 0x7F) // mask bit should be 0
	if payloadLen > MaxControlPayload {
		t.Errorf("payload %d exceeds max control payload %d", payloadLen, MaxControlPayload)
	}
}

func TestWriteCloseFrame_EmptyReason(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 256)
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := server.Read(buf)
		done <- buf[:n]
	}()

	WriteCloseFrame(client, ws.StatusNormalClosure, "")

	data := <-done
	if len(data) < 4 {
		t.Fatalf("close frame too short: %d bytes", len(data))
	}
	// Payload should be exactly 2 bytes (status code only).
	payloadLen := int(data[1] & 0x7F)
	if payloadLen != 2 {
		t.Errorf("expected payload length 2 for empty reason, got %d", payloadLen)
	}
}

func TestWriteClientCloseFrame_Masked(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 256)
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := server.Read(buf)
		done <- buf[:n]
	}()

	WriteClientCloseFrame(client, ws.StatusNormalClosure, "bye")

	data := <-done
	if len(data) < 4 {
		t.Fatalf("close frame too short: %d bytes", len(data))
	}
	// First byte: FIN + OpClose (0x88).
	if data[0] != 0x88 {
		t.Errorf("expected FIN+OpClose (0x88), got 0x%02x", data[0])
	}
	// Second byte: mask bit should be set (0x80 | payloadLen).
	if data[1]&0x80 == 0 {
		t.Error("client close frame must be masked (RFC 6455)")
	}
}
