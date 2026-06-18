// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

// watchKillSwitch wires the operator kill switch to signals: SIGUSR1 trips it
// (terminate active sessions + refuse new ones), SIGUSR2 clears it. The watcher
// runs until ctx is cancelled. This mirrors the SIGUSR1 convention the pipelock
// core kill switch uses.
func watchKillSwitch(ctx context.Context, srv *livechat.Server) {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case sig := <-ch:
				switch sig {
				case syscall.SIGUSR1:
					srv.Kill()
				case syscall.SIGUSR2:
					srv.Resume()
				}
			}
		}
	}()
}
