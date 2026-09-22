// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// transcriptRootSessionID is the legacy session base. Production code no
// longer labels anything with it directly: each process acquires its own run
// session (see acquireRunSession) and every consumer reads that session from
// the recorder or the emitter. It remains the fallback for a recorder that
// was never bound.
const transcriptRootSessionID = recorder.DefaultSessionBase

// acquireRunSession binds rec to a fresh per-process run session derived from
// the default base and returns it. Every writer sharing rec (the v1 receipt
// emitter, the v2 proxy_decision emitter, and the proxy's own decision
// entries) must record under the returned session; the recorder refuses any
// other. A nil or no-op recorder returns the base unchanged.
func acquireRunSession(rec *recorder.Recorder) (string, error) {
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		return "", fmt.Errorf("acquiring flight recorder run session: %w", err)
	}
	return session, nil
}

// recorderSessionOf returns the session rec is bound to, falling back to the
// legacy base for a recorder that has not been bound.
func recorderSessionOf(rec *recorder.Recorder) string {
	if s := rec.SessionID(); s != "" {
		return s
	}
	return transcriptRootSessionID
}

type liveFileSentryScanner struct {
	load func() *scanner.Scanner
}

func (s liveFileSentryScanner) ScanTextForDLP(ctx context.Context, text string) scanner.TextDLPResult {
	sc := s.load()
	if sc == nil {
		return scanner.TextDLPResult{
			Matches: []scanner.TextDLPMatch{{
				PatternName: "scanner unavailable",
				Severity:    "critical",
			}},
		}
	}
	return sc.ScanTextForDLP(ctx, text)
}

func (s *Server) liveReceiptEmitter() *receipt.Emitter {
	if s.proxy != nil {
		return s.proxy.ReceiptEmitterPtr().Load()
	}
	return s.receiptEmitter
}

func receiptEmitterReady(e *receipt.Emitter) bool {
	return e != nil && e.InitError() == nil && e.HealthError() == nil
}

func (s *Server) liveReceiptEmitterReady() bool {
	return receiptEmitterReady(s.liveReceiptEmitter())
}

// sealTranscriptRoot writes the signed session_close and compat transcript root
// for the live receipt chain at graceful shutdown, anchoring the receipts
// emitted this run so a chain truncated by a CLEAN exit becomes detectable:
// verify can see the sealed root instead of reporting a silently-shortened
// chain as VALID. EmitTranscriptRoot has no other production caller, so without
// this the completeness anchor never fires.
//
// Drain-then-seal contract: call this ONLY after every receipt-emitting listener
// has drained. Once the root is written the chain is sealed and a racing Emit
// returns ErrChainSealed; sealing after the listener WaitGroup join means no Emit
// races the seal. Uses the LIVE emitter (hot reload swaps it) so the seal lands
// on the emitter holding the current chain state.
//
// Best-effort and nil-safe at every layer (no recorder/key -> nil emitter -> the
// EmitTranscriptRoot no-op; no receipts emitted -> no-op). A seal failure is
// logged, never fatal: receipts are evidence, not enforcement. This closes ONLY
// the clean-exit case - a SIGKILL still truncates the tail with no root, which
// needs an external/periodic anchor (separate, deferred work).
func (s *Server) sealTranscriptRoot() {
	e := s.liveReceiptEmitter()
	if e == nil {
		return
	}
	if err := emitSessionCloseAndTranscriptRoot(e, e.Session(), sessionCloseReasonGracefulShutdown); err != nil {
		if s.logger != nil {
			s.logger.LogError(audit.NewResourceLogContext("SHUTDOWN", "transcript_root"), err)
		}
	}
}

func (s *Server) liveV2ReceiptEmitter() *proxydecision.Emitter {
	if s.proxy != nil {
		return s.proxy.V2EmitterPtr().Load()
	}
	return nil
}

func (s *Server) liveEnvelopeEmitter() *envelope.Emitter {
	if s.proxy != nil {
		return s.proxy.EnvelopeEmitterPtr().Load()
	}
	return s.envelopeEmitter
}
