// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func TestNativeVerificationProgressAndCancellation(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	r, err := recorder.New(recorder.Config{Enabled: true, Dir: dir}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	const run = "0123456789abcdef0123456789abcdef"
	e := NewEmitter(r, key, run, 30)
	if e == nil {
		t.Fatal("nil native emitter")
	}
	if err = e.EmitOpen(); err != nil {
		t.Fatal(err)
	}
	if err = e.EmitClose(); err != nil {
		t.Fatal(err)
	}
	var records uint64
	var readBytes int64
	head, err := VerifyRunWithOptions(dir, run, hex.EncodeToString(pub), true, verification.Options{Progress: func(p verification.Progress) error { records += p.Records; readBytes += p.Bytes; return nil }})
	if err != nil || records != head.RecordCount || readBytes == 0 {
		t.Fatalf("head=%+v records=%d bytes=%d err=%v", head, records, readBytes, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = VerifyRunWithOptions(dir, run, hex.EncodeToString(pub), true, verification.Options{Context: ctx, Progress: func(p verification.Progress) error {
		if p.Bytes > 0 {
			cancel()
		}
		return nil
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled native verification=%v", err)
	}
	failure := errors.New("progress notification failed")
	_, err = VerifyRunWithOptions(dir, run, hex.EncodeToString(pub), true, verification.Options{Progress: func(verification.Progress) error { return failure }})
	if !errors.Is(err, failure) {
		t.Fatalf("progress failure became success: %v", err)
	}
}
