// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// transcriptRootSessionID labels the shutdown transcript root. It matches the
// flight recorder's single pinned session ("proxy"). Per-run/session binding of
// the signed receipt set is tracked separately (run-nonce work) and intentionally
// out of scope here.
const transcriptRootSessionID = "proxy"

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

// sealTranscriptRoot writes the transcript root for the live receipt chain at
// graceful shutdown, anchoring the receipts emitted this run so a chain truncated
// by a CLEAN exit becomes detectable: verify can see the sealed root instead of
// reporting a silently-shortened chain as VALID. EmitTranscriptRoot has no other
// production caller, so without this the completeness anchor never fires.
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
	if err := e.EmitTranscriptRoot(transcriptRootSessionID); err != nil {
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
