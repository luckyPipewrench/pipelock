// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const sessionCloseReasonGracefulShutdown = "graceful_shutdown"

type receiptHeartbeatEmitter func() *receipt.Emitter

func startReceiptHeartbeat(
	ctx context.Context,
	wg *sync.WaitGroup,
	interval time.Duration,
	emitterFn receiptHeartbeatEmitter,
	logW io.Writer,
	requireReceipts bool,
	onRequiredFailure func(error),
) {
	if wg == nil || emitterFn == nil {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				e := emitterFn()
				if e == nil {
					continue
				}
				if err := e.EmitHeartbeat(); err != nil && !errors.Is(err, receipt.ErrChainSealed) {
					if logW != nil {
						_, _ = fmt.Fprintf(logW, "pipelock: receipt heartbeat emit failed: %v\n", err)
					}
					if requireReceipts {
						e.MarkUnhealthy(err)
						if onRequiredFailure != nil {
							onRequiredFailure(err)
						}
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func startStandaloneReceiptLifecycle(
	parent context.Context,
	interval time.Duration,
	e *receipt.Emitter,
	logW io.Writer,
	requireReceipts bool,
	onRequiredFailure func(error),
) func() {
	if !receiptEmitterReady(e) {
		return func() {}
	}
	ctx, cancel := context.WithCancel(parent)
	var wg sync.WaitGroup
	startReceiptHeartbeat(ctx, &wg, interval, func() *receipt.Emitter { return e }, logW, requireReceipts, onRequiredFailure)
	return func() {
		cancel()
		wg.Wait()
		if err := emitSessionCloseAndTranscriptRoot(e, transcriptRootSessionID, sessionCloseReasonGracefulShutdown); err != nil && logW != nil {
			_, _ = fmt.Fprintf(logW, "pipelock: receipt shutdown seal failed: %v\n", err)
		}
	}
}

func emitSessionCloseAndTranscriptRoot(e *receipt.Emitter, sessionID, closeReason string) error {
	if e == nil {
		return nil
	}
	if err := e.EmitSessionClose(closeReason); err != nil && !errors.Is(err, receipt.ErrChainSealed) {
		return err
	}
	return e.EmitTranscriptRoot(sessionID)
}
