// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestAllowReceiptRequiredFamilies(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, grouped := range []bool{false, true} {
			for _, failure := range []string{"healthy", "v2 unavailable", "v2 sync", "optional"} {
				for _, fallback := range []bool{false, true} {
					t.Run(map[bool]string{false: "proxy", true: "reverse"}[reverse]+"/"+map[bool]string{false: "single", true: "group"}[grouped]+"/"+failure+"/"+map[bool]string{false: "extension", true: "fallback"}[fallback], func(t *testing.T) {
						f := newDualEmitFixture(t, false)
						p, rec := f.p, f.rec
						var selected receipt.EmitOpts
						if grouped {
							var shards *receipt.ReceiptShardSet
							rec, shards, p, _ = newReceiptFailureGroup(t)
							_ = shards.Admit(receipt.EmitOpts{})
							selected = shards.Admit(receipt.EmitOpts{})
						}
						cfg := config.Defaults()
						cfg.FlightRecorder.RequireReceipts = failure != "optional"
						var syncs atomic.Int32
						rec.SetSyncForTest(func(*os.File) error {
							if syncs.Add(1) == 2 && failure == "v2 sync" {
								return errors.New("allow v2 sync failure")
							}
							return nil
						})
						if failure == "v2 unavailable" || failure == "optional" {
							emitter := p.v2EmitterPtr.Load()
							if grouped {
								emitter = p.receiptGroupPtr.Load().v2[selected.ShardIndex]
							}
							if _, _, err := emitter.Retire(); err != nil {
								t.Fatal(err)
							}
						}
						opts := withReceiptShard(receipt.EmitOpts{
							ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
							Transport: TransportWS, Target: "https://api.vendor.example/data",
							Method: http.MethodGet, Layer: credentialAudienceReceiptExtensionKey,
							Extension: json.RawMessage(`{"allow":"audience"}`),
						}, selected)
						if fallback {
							opts.Extension = json.RawMessage("null")
						}
						var err error
						if reverse {
							rp := &ReverseProxyHandler{owner: p, receiptEmitterPtr: &p.receiptEmitterPtr, v2EmitterPtr: &p.v2EmitterPtr, logger: p.logger, metrics: p.metrics}
							err = rp.emitCredentialAudienceReceipt(cfg, opts)
						} else {
							err = p.emitCredentialAudienceReceipt(cfg, opts)
						}
						wantErr := failure == "v2 unavailable" || failure == "v2 sync"
						if (err != nil) != wantErr {
							t.Fatalf("allow receipt error=%v, want error=%t; syncs=%d", err, wantErr, syncs.Load())
						}
						if failure == "v2 sync" && !errors.Is(err, recorder.ErrDurability) {
							t.Fatalf("error=%v, want durability classification", err)
						}
						if failure == "healthy" && syncs.Load() != 2 {
							t.Fatalf("allow synced %d times, want both families", syncs.Load())
						}
						if failure == "optional" && syncs.Load() != 0 {
							t.Fatalf("optional allow synced %d times", syncs.Load())
						}
					})
				}
			}
		}
	}
}

func TestAllowReceiptRequiredFailureQuarantinesGroup(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, failure := range []string{"v1", "v2", "v1 sync", "v2 sync"} {
			t.Run(map[bool]string{false: "proxy", true: "reverse"}[reverse]+"/"+failure, func(t *testing.T) {
				rec, shards, p, cancels := newReceiptFailureGroup(t)
				_ = shards.Admit(receipt.EmitOpts{})
				opts := shards.Admit(receipt.EmitOpts{
					ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
					Transport: TransportWS, Method: http.MethodGet,
					Target: "https://api.vendor.example/data", Layer: credentialAudienceReceiptExtensionKey,
				})
				group := p.receiptGroupPtr.Load()
				switch failure {
				case "v1":
					e, err := shards.SelectedEmitter(opts)
					if err != nil {
						t.Fatal(err)
					}
					e.MarkUnhealthy(errors.New("allow v1 unavailable"))
				case "v2":
					if _, _, err := group.v2[opts.ShardIndex].Retire(); err != nil {
						t.Fatal(err)
					}
				default:
					var syncs atomic.Int32
					failAt := int32(1)
					if failure == "v2 sync" {
						failAt = 2
					}
					rec.SetSyncForTest(func(*os.File) error {
						if syncs.Add(1) == failAt {
							return errors.New("allow sync failure")
						}
						return nil
					})
				}
				cfg := config.Defaults()
				cfg.FlightRecorder.RequireReceipts = true
				var err error
				if reverse {
					rp := &ReverseProxyHandler{owner: p, receiptEmitterPtr: &p.receiptEmitterPtr, v2EmitterPtr: &p.v2EmitterPtr, logger: p.logger, metrics: p.metrics}
					err = rp.emitCredentialAudienceReceipt(cfg, opts)
				} else {
					err = p.emitCredentialAudienceReceipt(cfg, opts)
				}
				if err == nil {
					t.Fatal("required allow receipt accepted a failed family")
				}
				if *cancels != 1 || shards.ProcessEmitter().HealthError() == nil {
					t.Fatalf("required group failure did not quarantine: cancels=%d, process health=%v", *cancels, shards.ProcessEmitter().HealthError())
				}
				next := shards.Admit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: TransportForward, Method: http.MethodGet, Target: "https://api.vendor.example/next"})
				if err := p.emitRequiredReceiptWithEmitter(next, shards.ProcessEmitter()); err == nil {
					t.Fatal("another shard admitted after required group failure")
				}
			})
		}
	}
}
