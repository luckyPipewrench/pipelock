// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestVerifyRunSignedHeadAndDamage(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	const run = "0123456789abcdef0123456789abcdef"
	e := NewEmitter(rec, priv, run, 30)
	if e == nil {
		t.Fatal("nil emitter")
	}
	for _, emit := range []func() error{e.EmitOpen, func() error {
		return e.EmitActivity(Activity{Class: "read", ID: "action-1", Direction: "in"}, true)
	}, e.EmitClose} {
		if err := emit(); err != nil {
			t.Fatal(err)
		}
	}
	signer := hex.EncodeToString(pub)
	head, err := VerifyRun(dir, run, signer)
	if err != nil {
		t.Fatalf("VerifyRun: %v", err)
	}
	if head.RecordCount != 3 || head.FinalSeq != 2 || len(head.FinalHash) != 64 || head.FinalHash == zeroHash {
		t.Fatalf("unexpected verified head: %+v", head)
	}
	if _, err := VerifyRun(dir, run, strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted wrong trusted signer")
	}
	path := filepath.Join(e.Dir(), "recorders", "pipelock.jsonl")
	// #nosec G304 -- path is derived from this test's temporary evidence directory.
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(original, []byte{'\n'})
	if len(lines) != 4 {
		t.Fatalf("line count = %d", len(lines)-1)
	}
	if err := os.WriteFile(path, bytes.Join(lines[:2], nil), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRun(dir, run, signer); err == nil || !strings.Contains(err.Error(), "no signed close") {
		t.Fatalf("truncated run accepted: %v", err)
	}
	if head, err := VerifyPresentRun(dir, run, signer); err != nil || head.RecordCount != 2 {
		t.Fatalf("intact open prefix = %+v, %v", head, err)
	}
	if err := os.WriteFile(path, append(bytes.Join(lines[:2], nil), []byte("partial")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if head, err := VerifyPresentRun(dir, run, signer); err != nil || head.RecordCount != 2 {
		t.Fatalf("torn final line = %+v, %v", head, err)
	}
	if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if head, err := VerifyPresentRun(dir, run, signer); err != nil || head.RecordCount != 0 {
		t.Fatalf("torn opening = %+v, %v", head, err)
	}
	if err := os.WriteFile(path, append(bytes.Join(lines[:2], nil), []byte("bad-complete\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPresentRun(dir, run, signer); err == nil {
		t.Fatal("accepted malformed complete line in open run")
	}
	corrupt := bytes.Clone(original)
	corrupt[10] = 'A'
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRun(dir, run, signer); err == nil {
		t.Fatal("accepted tampered signed record")
	}
	if _, err := VerifyPresentRun(dir, run, signer); err == nil {
		t.Fatal("accepted tampered signed record in open run")
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(e.Dir(), "keys")
	if err := os.Rename(keys, keys+"-real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys+"-real", keys); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := VerifyRun(dir, run, signer); err == nil {
		t.Fatal("accepted symlinked native AEL keys directory")
	}
}
