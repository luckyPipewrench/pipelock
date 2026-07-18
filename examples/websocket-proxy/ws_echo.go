// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// WebSocket echo server for examples/websocket-proxy/verify.sh.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

func main() {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	// First line of stdout is the listen address for verify.sh.
	fmt.Println(ln.Addr().String())

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _, _, upgradeErr := ws.UpgradeHTTP(r, w)
			if upgradeErr != nil {
				return
			}
			defer conn.Close() //nolint:errcheck
			for {
				msg, op, readErr := wsutil.ReadClientData(conn)
				if readErr != nil {
					return
				}
				if op != ws.OpText {
					return
				}
				if writeErr := wsutil.WriteServerMessage(conn, ws.OpText, msg); writeErr != nil {
					return
				}
			}
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Fatal(serveErr)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
