//go:build ignore

// WebSocket probe client for examples/websocket-proxy/verify.sh.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

func main() {
	proxy := flag.String("proxy", "", "pipelock proxy host:port")
	backend := flag.String("backend", "", "echo server host:port")
	message := flag.String("message", "", "text frame payload")
	frame := flag.String("frame", "text", "text or binary")
	expect := flag.String("expect", "echo", "echo or close")
	flag.Parse()

	if *proxy == "" || *backend == "" {
		fmt.Fprintln(os.Stderr, "missing required flags")
		os.Exit(2)
	}
	if *frame == "text" && *message == "" {
		fmt.Fprintln(os.Stderr, "missing -message for text frame")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wsURL := fmt.Sprintf("ws://%s/ws?url=ws://%s", *proxy, *backend)
	conn, _, _, err := ws.Dialer{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
	}.Dial(ctx, wsURL)
	if err != nil {
		if *expect == "close" {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "dial failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close() //nolint:errcheck

	switch *frame {
	case "binary":
		if err := wsutil.WriteClientMessage(conn, ws.OpBinary, []byte{0x01, 0x02, 0x03}); err != nil {
			fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
			os.Exit(1)
		}
	case "text":
		if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(*message)); err != nil {
			fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown frame type %q\n", *frame)
		os.Exit(2)
	}

	reply, _, err := wsutil.ReadServerData(conn)
	switch *expect {
	case "close":
		if err != nil {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "expected connection close, got reply %q\n", reply)
		os.Exit(1)
	case "echo":
		if err != nil {
			fmt.Fprintf(os.Stderr, "read failed: %v\n", err)
			os.Exit(1)
		}
		if string(reply) != *message {
			fmt.Fprintf(os.Stderr, "echo mismatch: got %q want %q\n", reply, *message)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown expect mode %q\n", *expect)
		os.Exit(2)
	}
}
