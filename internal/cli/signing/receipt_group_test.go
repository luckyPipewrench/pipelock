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

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestVerifyReceiptCmdGroupRejectsDeletedShard(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := rec.Close(); err != nil {
			t.Errorf("close recorder: %v", err)
		}
	})
	set, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: "sha256:" + strings.Repeat("a", 64),
		Principal: "pipelock", Actor: "proxy",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := set.Opening()
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
	verify := func() (string, error) {
		t.Helper()
		cmd := VerifyReceiptCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"--chain", dir, "--group", open.GroupID, "--key", hex.EncodeToString(pub)})
		err := cmd.Execute()
		return out.String(), err
	}
	if out, err := verify(); err != nil || !strings.Contains(out, "GROUP_VALID") {
		t.Fatalf("complete group output=%q err=%v", out, err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "evidence-"+open.Shards[1].SessionID+"-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("shard evidence files=%v err=%v", files, err)
	}
	if err := os.Remove(files[0]); err != nil {
		t.Fatal(err)
	}
	if out, err := verify(); err == nil || !strings.Contains(out, "GROUP_INVALID") || cliutil.ExitCodeOf(err) != cliutil.ExitGeneral {
		t.Fatalf("deleted shard output=%q err=%v exit=%d", out, err, cliutil.ExitCodeOf(err))
	}
}
