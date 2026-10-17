// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/cardtest"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestBodySigV4SortedTextNullBarrier(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Joined credential", Regex: `^alpha\.omega$`, Severity: config.SeverityHigh})
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	views := extractBodyTextForDLP([]byte(`["omega",null,"alpha"]`), BodyScanRequest{ContentType: contentTypeJSON})
	for _, sigv4 := range []bool{false, true} {
		matches := scanBodyTextViewsForDLPWithAudience(t.Context(), sc, bodyDLPViews{texts: views.Texts, cards: views.CardTexts, atoms: views.Atoms}, "", nil, nil, sigv4, nil, "", nil)
		if !hasDLPMatchName(matches, "Joined credential") {
			t.Errorf("SigV4=%v lost the sorted cross-field credential", sigv4)
		}
	}
}

func TestCardJSONNumberStreamKeepsKnownValueEnforcement(t *testing.T) {
	card := cardtest.Number()
	for _, known := range []bool{false, true} {
		cfg := testScannerConfig()
		cfg.DLP.ScanEnv = false
		if known {
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Known stream fixture", Regex: card, Severity: config.SeverityHigh})
		}
		relay, _ := newWebSocketFrameSuppressionRelay(t, cfg, "wss://api.vendor.example/socket")
		var wire bytes.Buffer
		for _, part := range []string{card[:8], card[8:]} {
			if err := wsutil.WriteClientMessage(&wire, ws.OpText, []byte(`{"kind":"status","n":`+part+`}`)); err != nil {
				t.Fatal(err)
			}
		}
		source := &receiptFrameConn{input: bytes.NewReader(wire.Bytes())}
		sink := &receiptFrameConn{input: bytes.NewReader(nil)}
		relay.clientConn, relay.upstreamConn = source, sink
		ctx, cancel := context.WithCancel(t.Context())
		_, _, _, blocked := relay.clientToUpstream(ctx, cancel, time.Minute)
		cancel()
		if blocked != known {
			t.Fatalf("known=%v blocked=%v", known, blocked)
		}
		forwarded := 0
		frames := bytes.NewReader(sink.output.Bytes())
		for frames.Len() > 0 {
			frame, err := ws.ReadFrame(frames)
			if err != nil {
				t.Fatal(err)
			}
			if frame.Header.OpCode == ws.OpText {
				forwarded++
			}
		}
		want := 2
		if known {
			want = 1
		}
		if forwarded != want {
			t.Fatalf("forwarded=%d want=%d", forwarded, want)
		}
	}
}
