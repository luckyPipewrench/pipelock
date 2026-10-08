// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// buildServerReceiptShardGroup is the startup construction path below the
// public receipt_chains gate. Keeping it callable here lets tests exercise
// group publication and v1/v2 pairing before that gate is lifted.
func buildServerReceiptShardGroup(template receipt.EmitterConfig, count int, keyPath string, deferOpen bool, onRequiredFailure ...func(error)) (*receipt.ReceiptShardSet, []proxy.Option, error) {
	if template.Recorder == nil {
		return nil, nil, fmt.Errorf("receipt group requires a persistent recorder")
	}
	trusted, err := receipt.TrustedGroupSignerKeys(template)
	if err != nil {
		return nil, nil, err
	}
	previousID, hasPrevious, err := receipt.FindTerminalReceiptGroup(template.Recorder.Dir(), recorder.DefaultSessionBase, trusted)
	if err != nil {
		return nil, nil, fmt.Errorf("find previous receipt group: %w", err)
	}
	var shards *receipt.ReceiptShardSet
	if hasPrevious {
		if deferOpen {
			shards, err = receipt.PrepareSuccessorReceiptShardSet(template, recorder.DefaultSessionBase, count, 0, previousID)
		} else {
			shards, err = receipt.OpenSuccessorReceiptShardSet(template, recorder.DefaultSessionBase, count, 0, previousID)
		}
	} else if deferOpen {
		shards, err = receipt.PrepareInitialReceiptShardSet(template, recorder.DefaultSessionBase, count, 0)
	} else {
		shards, err = receipt.OpenInitialReceiptShardSet(template, recorder.DefaultSessionBase, count, 0)
	}
	if err != nil {
		return nil, nil, err
	}
	open, _ := shards.Opening()
	v2 := make([]*proxydecision.Emitter, open.ShardCount)
	for i, shard := range open.Shards {
		v2[i] = proxydecision.NewEmitter(proxydecision.EmitterConfig{
			Recorder: template.Recorder, Signer: proxydecision.NewKeyedSigner(template.PrivKey),
			Sanitize:  proxydecision.SanitizeFromRedactor(template.Recorder.ReceiptRedactor()),
			Principal: template.Principal, Actor: template.Actor, Session: shard.SessionID,
		})
		if v2[i] == nil {
			return nil, nil, fmt.Errorf("initialize receipt group shard %d v2 emitter", i)
		}
	}
	groupOption, err := proxy.WithReceiptShardSet(shards, v2, onRequiredFailure...)
	if err != nil {
		return nil, nil, fmt.Errorf("pair receipt shard emitters: %w", err)
	}
	return shards, []proxy.Option{
		proxy.WithSession(open.Shards[open.ProcessShardIndex].SessionID),
		groupOption,
		proxy.WithReceiptKeyPath(keyPath),
	}, nil
}

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
	if s.receiptShardSet != nil {
		for _, shard := range s.receiptShardSet.Emitters() {
			if err := emitSessionCloseAndTranscriptRoot(shard, shard.Session()); err != nil && s.logger != nil {
				s.logger.LogError(audit.NewResourceLogContext("SHUTDOWN", "transcript_root"), err)
			}
		}
		if _, err := s.receiptShardSet.PublishClose(); err != nil && s.logger != nil {
			s.logger.LogError(audit.NewResourceLogContext("SHUTDOWN", "receipt_group_close"), err)
		}
		return
	}
	e := s.liveReceiptEmitter()
	if e == nil {
		return
	}
	if err := emitSessionCloseAndTranscriptRoot(e, e.Session()); err != nil {
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
