// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type receiptFrameConn struct {
	discardConn
	input           *bytes.Reader
	output          bytes.Buffer
	syncs           *atomic.Int32
	syncsAtDelivery int32
}

func (c *receiptFrameConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *receiptFrameConn) Write(p []byte) (int, error) {
	if c.output.Len() == 0 && c.syncs != nil {
		c.syncsAtDelivery = c.syncs.Load()
	}
	return c.output.Write(p)
}

func TestWSRequiredResponseDecision(t *testing.T) {
	for _, action := range []string{config.ActionWarn, config.ActionStrip} {
		for _, grouped := range []bool{false, true} {
			for _, opcode := range []ws.OpCode{ws.OpText, ws.OpPing, ws.OpPong} {
				if action == config.ActionStrip && opcode != ws.OpText {
					continue
				}
				for _, failure := range []string{"healthy", "missing", "v1", "v2", "v1 sync", "v2 sync", "optional"} {
					t.Run(action+"/"+map[bool]string{false: "single", true: "group"}[grouped]+"/"+map[ws.OpCode]string{ws.OpText: "text", ws.OpPing: "ping", ws.OpPong: "pong"}[opcode]+"/"+failure, func(t *testing.T) {
						f := newDualEmitFixture(t, false)
						p, rec := f.p, f.rec
						var shard receipt.EmitOpts
						if grouped {
							var shards *receipt.ReceiptShardSet
							rec, shards, p, _ = newReceiptFailureGroup(t)
							_ = shards.Admit(receipt.EmitOpts{})
							shard = shards.Admit(receipt.EmitOpts{})
						}
						cfg := config.Defaults()
						cfg.Internal = nil
						cfg.Taint.Enabled = false
						cfg.ResponseScanning.Enabled = true
						cfg.ResponseScanning.Action = action
						cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "response marker", Regex: "POLICY_MARKER"}}
						cfg.FlightRecorder.RequireReceipts = failure != "optional"
						p.cfgPtr.Store(cfg)
						sc := scanner.MustNew(cfg)
						defer sc.Close()
						if err := p.emitRequiredReceipt(withReceiptShard(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: TransportWS, Method: "GET", Target: "wss://api.vendor.example/socket"}, shard)); err != nil {
							t.Fatal(err)
						}
						var syncs atomic.Int32
						rec.SetSyncForTest(func(*os.File) error {
							n := syncs.Add(1)
							if failure == "v1 sync" && n == 1 || failure == "v2 sync" && n == 2 {
								return errors.New("frame sync failure")
							}
							return nil
						})
						e1, e2 := p.receiptEmitterPtr.Load(), p.v2EmitterPtr.Load()
						if grouped {
							e1, _ = p.receiptGroupPtr.Load().shards.SelectedEmitter(shard)
							e2 = p.receiptGroupPtr.Load().v2[shard.ShardIndex]
						}
						switch failure {
						case "missing":
							p.receiptGroupPtr.Store(nil)
							p.receiptEmitterPtr.Store(nil)
							p.v2EmitterPtr.Store(nil)
						case "v1":
							e1.MarkUnhealthy(errors.New("frame writer unavailable"))
						case "v2", "optional":
							if _, _, err := e2.Retire(); err != nil {
								t.Fatal(err)
							}
						}
						var wire bytes.Buffer
						payload := []byte("ordinary text POLICY_MARKER rest")
						err := wsutil.WriteServerMessage(&wire, opcode, payload)
						if err != nil {
							t.Fatal(err)
						}
						source := &receiptFrameConn{input: bytes.NewReader(wire.Bytes())}
						sink := &receiptFrameConn{input: bytes.NewReader(nil), syncs: &syncs}
						relay := &wsRelay{proxy: p, cfg: cfg, scanner: sc, receiptShard: shard, hostname: "api.vendor.example", targetURL: "wss://api.vendor.example/socket", maxMsg: 4096, allowBinary: true, scanText: true}
						ctx, cancel := context.WithCancel(t.Context())
						defer cancel()
						relay.upstreamConn = source
						relay.clientConn = sink
						_, _, _, blocked := relay.upstreamToClient(ctx, cancel, time.Minute)
						frames := bytes.NewReader(sink.output.Bytes())
						delivered := false
						for {
							frame, readErr := ws.ReadFrame(frames)
							if errors.Is(readErr, io.EOF) {
								break
							}
							if readErr != nil {
								t.Fatal(readErr)
							}
							if frame.Header.OpCode == opcode {
								delivered = true
								if action == config.ActionStrip && bytes.Contains(frame.Payload, []byte("POLICY_MARKER")) {
									t.Fatal("strip delivered the finding unchanged")
								}
							}
						}
						want := failure == "healthy" || failure == "optional"
						if delivered != want || blocked == want {
							t.Fatalf("delivered=%t blocked=%t want deliver=%t", delivered, blocked, want)
						}
						if failure == "healthy" && sink.syncsAtDelivery < 2 {
							t.Fatalf("delivery before both durable families: syncs=%d", sink.syncsAtDelivery)
						}
						if failure == "optional" && syncs.Load() != 0 {
							t.Fatalf("optional frame synced %d times", syncs.Load())
						}
					})
				}
			}
		}
	}
}
