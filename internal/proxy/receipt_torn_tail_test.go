// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func tornTailProxy(t *testing.T, required bool) (*Proxy, *config.Config, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, Session: session, ConfigHash: "baseline", Principal: "local", Actor: "pipelock"})
	if err := e.InitError(); err != nil {
		t.Fatal(err)
	}
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "receipt.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FlightRecorder.SigningKeyPath = keyPath
	cfg.FlightRecorder.RequireReceipts = required
	p, err := New(cfg, audit.NewNop(), scanner.MustNew(cfg), metrics.New(), WithRecorder(rec), WithReceiptEmitter(e), WithReceiptKeyPath(keyPath), WithSession(session))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	return p, cfg, files[0], body
}

func TestReceiptTornTailReload(t *testing.T) {
	for _, required := range []bool{false, true} {
		for _, rotate := range []bool{false, true} {
			for _, damage := range []string{"nul", "truncated", "missing_newline"} {
				t.Run(fmt.Sprintf("%s/required=%t/rotate=%t", damage, required, rotate), func(t *testing.T) {
					p, cfg, path, body := tornTailProxy(t, required)
					old := p.receiptEmitterPtr.Load()
					oldSession := p.recorder.SessionID()
					switch damage {
					case "nul":
						body = append(body, 0, 0, 0)
					case "truncated":
						body = append(body, []byte(`{"v":2,"seq":9`)...)
					case "missing_newline":
						body = bytes.TrimSuffix(body, []byte("\n"))
					}
					if err := os.WriteFile(path, body, 0o600); err != nil {
						t.Fatal(err)
					}
					before := sha256.Sum256(body)
					if rotate {
						_, key, err := ed25519.GenerateKey(rand.Reader)
						if err != nil {
							t.Fatal(err)
						}
						if err := signing.SavePrivateKey(key, cfg.FlightRecorder.SigningKeyPath); err != nil {
							t.Fatal(err)
						}
					}
					for attempt := 1; attempt <= 2; attempt++ {
						next := *cfg
						next.FetchProxy.TimeoutSeconds++
						if !p.Reload(&next, scanner.MustNew(&next)) {
							t.Fatalf("reload %d rejected torn recovery", attempt)
						}
						cfg = &next
						fresh := p.receiptEmitterPtr.Load()
						if fresh == nil || fresh.InitError() != nil || fresh.HealthError() != nil {
							t.Fatal("reload published unhealthy emitter")
						}
						if fresh.SessionID() == oldSession {
							t.Fatal("reload reused torn run")
						}
						p.recordDecision("allow", "test", "", "fetch", "test-request")
					}
					if old.HealthError() == nil {
						t.Fatal("old emitter still accepts receipts")
					}
					after, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if sha256.Sum256(after) != before {
						t.Fatal("damaged shard changed")
					}
					if p.metrics.EvidenceTornTailSnapshot().Total != 1 {
						t.Fatal("torn state not recorded exactly once")
					}
					files, err := filepath.Glob(filepath.Join(p.recorder.Dir(), "evidence-"+p.recorder.SessionID()+"-*.jsonl"))
					if err != nil || len(files) == 0 {
						t.Fatalf("fresh shards=%v err=%v", files, err)
					}
					for _, file := range files {
						entries, err := recorder.ReadEntries(file)
						if err != nil {
							t.Fatal(err)
						}
						if err := recorder.VerifyChain(entries); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}

func TestReceiptTornTailReloadTamper(t *testing.T) {
	for _, suffix := range []string{"garbage\n", "garbage\n\x00\x00", "middle", "broken_link", "broken_link_with_nul"} {
		t.Run(fmt.Sprintf("%x", suffix), func(t *testing.T) {
			p, cfg, path, body := tornTailProxy(t, true)
			switch suffix {
			case "broken_link", "broken_link_with_nul":
				p.recordDecision("allow", "test", "", "fetch", "request")
				entries, err := recorder.ReadEntries(path)
				if err != nil {
					t.Fatal(err)
				}
				last := &entries[len(entries)-1]
				last.PrevHash = recorder.GenesisHash
				last.Hash = recorder.ComputeHash(*last)
				var data bytes.Buffer
				for _, entry := range entries {
					line, err := json.Marshal(entry)
					if err != nil {
						t.Fatal(err)
					}
					data.Write(line)
					data.WriteByte('\n')
				}
				body = data.Bytes()
				if suffix == "broken_link_with_nul" {
					body = append(body, 0)
				}
			case "middle":
				body = append([]byte("garbage\n"), body...)
			default:
				body = append(body, []byte(suffix)...)
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			before := sha256.Sum256(body)
			old := p.receiptEmitterPtr.Load()
			for attempt := range 2 {
				if p.Reload(cfg, scanner.MustNew(cfg)) {
					t.Fatalf("tamper reload %d accepted", attempt)
				}
			}
			if p.receiptEmitterPtr.Load() != old {
				t.Fatal("tamper changed emitter")
			}
			if old.HealthError() == nil {
				t.Fatal("tamper left receipt admission healthy")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(after) != before {
				t.Fatal("tamper file changed")
			}
		})
	}
}

func TestReceiptTornTailReloadBadSignature(t *testing.T) {
	for _, suffix := range []string{"\n", "", "\n\x00\x00"} {
		t.Run(fmt.Sprintf("suffix=%x", suffix), func(t *testing.T) {
			p, cfg, path, _ := tornTailProxy(t, true)
			entries, err := recorder.ReadEntries(path)
			if err != nil {
				t.Fatal(err)
			}
			var body bytes.Buffer
			for _, entry := range entries {
				if entry.Type == "action_receipt" {
					r, err := receipt.Unmarshal(entry.RawDetail)
					if err != nil {
						t.Fatal(err)
					}
					r.Signature = "ed25519:" + fmt.Sprintf("%0128x", 0)
					entry.Detail = r
					entry.RawDetail = nil
					entry.Hash = recorder.ComputeHash(entry)
				}
				line, err := json.Marshal(entry)
				if err != nil {
					t.Fatal(err)
				}
				body.Write(line)
				body.WriteByte('\n')
			}
			data := append(bytes.TrimSuffix(body.Bytes(), []byte("\n")), []byte(suffix)...)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if p.Reload(cfg, scanner.MustNew(cfg)) {
				t.Fatal("invalid signature accepted")
			}
			if p.metrics.EvidenceTornTailSnapshot().Total != 0 {
				t.Fatal("signature corruption classified as torn recovery")
			}
		})
	}
}

func TestReceiptTornTailReloadFreshFailure(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			p, cfg, path, data := tornTailProxy(t, required)
			data = append(data, 0)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			old := p.receiptEmitterPtr.Load()
			p.recorder.SetSyncForTest(func(*os.File) error { return errors.New("storage sync unavailable") })
			next := *cfg
			next.FetchProxy.TimeoutSeconds++
			if p.Reload(&next, scanner.MustNew(&next)) {
				t.Fatal("unhealthy replacement published")
			}
			if p.receiptEmitterPtr.Load() != old || old.HealthError() == nil {
				t.Fatal("old emitter was not left fail closed")
			}
			p.recorder.SetSyncForTest((*os.File).Sync)
			if !p.Reload(&next, scanner.MustNew(&next)) {
				t.Fatal("retry after storage repair rejected")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, after) {
				t.Fatal("fresh failure or retry changed damaged bytes")
			}
		})
	}
}
