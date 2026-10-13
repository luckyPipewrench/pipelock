// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	guardfs "github.com/luckyPipewrench/pipelock/internal/guard"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestGuardStartupPublicationWindow(t *testing.T) {
	for _, own := range []bool{false, true} {
		t.Run(map[bool]string{false: "unrelated_file", true: "predecessor_file"}[own], func(t *testing.T) {
			pub, key, err := signing.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), "evidence")
			keyPath := filepath.Join(t.TempDir(), "receipt.key")
			if err = signing.SavePrivateKey(key, keyPath); err != nil {
				t.Fatal(err)
			}
			cfg := config.Defaults()
			cfg.FlightRecorder.Enabled, cfg.FlightRecorder.Dir, cfg.FlightRecorder.SigningKeyPath = true, dir, keyPath
			cfg.FlightRecorder.RequireReceipts, cfg.FlightRecorder.ReceiptChains = true, 2
			sc, err := scanner.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer sc.Close()
			trusted := []string{hex.EncodeToString(pub)}
			proof := guardfs.ExecutionProof{ConfigPolicyHash: strings.Repeat("a", 64), EffectivePolicyHash: strings.Repeat("b", 64), Binary: "/usr/bin/true"}
			run := func(between func()) error {
				ev, err := newGuardEvidence(t.Context(), cfg, sc, metrics.New(), io.Discard)
				if err != nil {
					return err
				}
				defer ev.close()
				ev.onRequiredFailure = func(error) {}
				if between != nil {
					between()
				}
				return ev.activate(proof)
			}
			if err = run(nil); err != nil {
				t.Fatal(err)
			}
			previous, found, err := receipt.FindTerminalReceiptGroup(dir, "proxy", trusted)
			if err != nil || !found {
				t.Fatalf("predecessor: %s %t %v", previous, found, err)
			}
			verified := receipt.VerifyReceiptGroup(dir, previous, trusted)
			if verified.Verdict != receipt.GroupValid {
				t.Fatalf("guard close: %+v", verified)
			}
			openName, err := receipt.ReceiptGroupFileName(previous, "open")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Clean(filepath.Join(dir, openName)))
			if err != nil {
				t.Fatal(err)
			}
			opening, err := receipt.UnmarshalReceiptGroupOpen(raw, trusted)
			if err != nil {
				t.Fatal(err)
			}
			err = run(func() {
				path := filepath.Join(dir, "operator-notes.txt")
				if own {
					files, globErr := filepath.Glob(filepath.Join(dir, "evidence-"+opening.Shards[0].SessionID+"-*.jsonl"))
					if globErr != nil || len(files) == 0 {
						t.Fatalf("predecessor paths: %v %v", files, globErr)
					}
					path = files[len(files)-1]
				}
				if own {
					f, openErr := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_APPEND, 0)
					if openErr != nil {
						t.Fatal(openErr)
					}
					_, writeErr := f.WriteString("{}\n")
					_ = f.Close()
					if writeErr != nil {
						t.Fatal(writeErr)
					}
				} else if writeErr := os.WriteFile(path, []byte("notes"), 0o600); writeErr != nil {
					t.Fatal(writeErr)
				}
			})
			if (err != nil) != own {
				t.Fatalf("activation own=%t: %v", own, err)
			}
			if own {
				return
			}
			terminal, found, err := receipt.FindTerminalReceiptGroup(dir, "proxy", trusted)
			if err != nil || !found || terminal == previous {
				t.Fatalf("successor: %s %t %v", terminal, found, err)
			}
			name, err := receipt.ReceiptGroupFileName(terminal, "transition")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = os.Stat(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if result := receipt.VerifyReceiptGroup(dir, terminal, trusted); result.Verdict != receipt.GroupValid {
				t.Fatalf("guard successor: %+v", result)
			}
			if err = run(nil); err != nil {
				t.Fatalf("later start refused: %v", err)
			}
		})
	}
}
