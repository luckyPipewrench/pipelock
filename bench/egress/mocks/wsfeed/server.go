// Package wsfeed is a deterministic WebSocket mock used by the egress
// benchmark. It implements a minimal text-frame responder using raw TCP +
// hand-rolled WebSocket frame parsing. Hand-rolled to keep the bench
// dependency-free; pipelock's production WebSocket code uses gobwas/ws.
package wsfeed

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 is required by RFC 6455 handshake
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// rfc6455GUID is the magic string appended to Sec-WebSocket-Key per RFC 6455 §4.2.
const rfc6455GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Server is a minimal WebSocket echo responder.
type Server struct {
	listener net.Listener
	stop     chan struct{}
	done     chan struct{}
}

// Start binds on a random port and accepts WebSocket connections.
func Start(ctx context.Context) (*Server, string, error) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("listen: %w", err)
	}
	s := &Server{
		listener: ln,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go s.acceptLoop()
	return s, ln.Addr().String(), nil
}

// Close shuts down the server.
func (s *Server) Close() error {
	close(s.stop)
	err := s.listener.Close()
	<-s.done
	return err
}

func (s *Server) acceptLoop() {
	defer close(s.done)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
				return
			}
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	key := req.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return
	}
	accept := computeAcceptKey(key)
	_, _ = fmt.Fprintf(conn,
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n", accept)
	for {
		payload, opcode, err := readFrame(br)
		if err != nil {
			return
		}
		if opcode == 0x8 { // close
			return
		}
		if err := writeTextFrame(conn, payload); err != nil {
			return
		}
	}
}

// computeAcceptKey returns the Sec-WebSocket-Accept value per RFC 6455 §4.2.2.
func computeAcceptKey(clientKey string) string {
	h := sha1.New() //nolint:gosec // SHA-1 is required by RFC 6455 handshake
	_, _ = io.WriteString(h, strings.TrimSpace(clientKey)+rfc6455GUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// readFrame reads one WebSocket frame, unmasking the payload. Supports text,
// binary, and close frames with payloads up to 65535 bytes (2-byte length).
// Bench payloads are tiny so larger extended lengths are not needed.
func readFrame(br *bufio.Reader) ([]byte, byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, 0, err
	}
	opcode := header[0] & 0x0F
	masked := header[1]&0x80 != 0
	length := int(header[1] & 0x7F)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(br, ext); err != nil {
			return nil, 0, err
		}
		length = int(ext[0])<<8 | int(ext[1])
	case 127:
		return nil, 0, fmt.Errorf("frames >64 KiB not supported by mock")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(br, mask[:]); err != nil {
			return nil, 0, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, 0, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return payload, opcode, nil
}

// writeTextFrame writes an unmasked text frame (server -> client per RFC 6455 §5.3).
func writeTextFrame(w io.Writer, payload []byte) error {
	header := []byte{0x81} // FIN=1, opcode=text
	switch n := len(payload); {
	case n <= 125:
		header = append(header, byte(n)) //nolint:gosec // n <= 125 fits in a byte
	case n < 65536:
		header = append(header, 126, byte(n>>8&0xFF), byte(n&0xFF))
	default:
		return fmt.Errorf("frames >64 KiB not supported by mock")
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// SetDeadlineSoon helps the bench tear down cleanly.
func (s *Server) SetDeadlineSoon() {
	type tcpDeadline interface {
		SetDeadline(time.Time) error
	}
	if d, ok := s.listener.(tcpDeadline); ok {
		_ = d.SetDeadline(time.Now().Add(time.Millisecond))
	}
}
