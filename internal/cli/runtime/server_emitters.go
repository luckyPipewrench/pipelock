// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"

	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

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
