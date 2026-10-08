// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func sealDefaultGroup(t *testing.T, set *receipt.ReceiptShardSet) {
	t.Helper()
	for _, emitter := range set.Emitters() {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := set.PublishClose(); err != nil {
		t.Fatal(err)
	}
}

func writeDefaultLegacyRun(t *testing.T, dir string, key ed25519.PrivateKey) {
	t.Helper()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: key, Principal: "pipelock", Actor: "proxy"})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	if err := emitter.Emit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: "allow", Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/legacy"}); err != nil {
		t.Fatal(err)
	}
	if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
		t.Fatal(err)
	}
	if err := emitter.EmitTranscriptRoot("proxy"); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyReceiptDefaultGroupDirectoryAndMixedLegacy(t *testing.T) {
	for _, whole := range []bool{false, true} {
		t.Run(map[bool]string{false: "chain", true: "whole-recorder"}[whole], func(t *testing.T) {
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
			if err != nil {
				t.Fatal(err)
			}
			set, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
				Recorder: rec, PrivKey: key, ConfigHash: "sha256:" + strings.Repeat("a", 64), Principal: "pipelock", Actor: "proxy",
			}, "proxy", 2, 0)
			if err != nil {
				t.Fatal(err)
			}
			sealDefaultGroup(t, set)
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			writeDefaultLegacyRun(t, dir, key)

			args := []string{"--chain", dir, "--key", hex.EncodeToString(pub)}
			if whole {
				args = append(args, "--whole-recorder")
			}
			cmd := VerifyReceiptCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("default directory verification: %v\n%s", err, out.String())
			}
			if !strings.Contains(out.String(), "GROUP_VALID") || !strings.Contains(out.String(), "(session proxy)") {
				t.Fatalf("group or legacy result missing: %s", out.String())
			}
		})
	}
}

func TestVerifyReceiptDefaultGroupDirectoryRejectsIncompleteAndOrphanGate(t *testing.T) {
	for _, orphan := range []bool{false, true} {
		t.Run(map[bool]string{false: "incomplete", true: "orphan-gate"}[orphan], func(t *testing.T) {
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
			if err != nil {
				t.Fatal(err)
			}
			set, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
				Recorder: rec, PrivKey: key, ConfigHash: "sha256:" + strings.Repeat("b", 64), Principal: "pipelock", Actor: "proxy",
			}, "proxy", 2, 0)
			if err != nil {
				t.Fatal(err)
			}
			open, _ := set.Opening()
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			if orphan {
				name, _ := receipt.ReceiptGroupFileName(open.GroupID, "open")
				if err := os.Remove(filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			cmd := VerifyReceiptCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs([]string{"--chain", dir, "--key", hex.EncodeToString(pub)})
			if err := cmd.Execute(); err == nil {
				t.Fatalf("invalid group returned success: %s", out.String())
			}
			want := "GROUP_INCOMPLETE"
			if orphan {
				want = "GROUP_INVALID"
			}
			if !strings.Contains(out.String(), want) {
				t.Fatalf("output lacks %s: %s", want, out.String())
			}
		})
	}
}
