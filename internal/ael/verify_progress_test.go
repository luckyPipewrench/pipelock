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

func TestNativeProgressRefusesAtEachBoundary(t *testing.T) {
	for _, phase := range []string{"before", "next_record", "record_report"} {
		t.Run(phase, func(t *testing.T) {
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
			emitter := NewEmitter(r, key, run, 30)
			if emitter == nil {
				t.Fatal("nil emitter")
			}
			if err = emitter.EmitOpen(); err != nil {
				t.Fatal(err)
			}
			if err = emitter.EmitClose(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("authenticated record report failed")
			records := 0
			options := verification.Options{Context: ctx, Progress: func(p verification.Progress) error {
				if p.Kind == "native_ael" {
					records++
					if phase == "record_report" {
						return failure
					}
					if phase == "next_record" {
						cancel()
					}
				}
				return nil
			}}
			if phase == "before" {
				cancel()
			}
			head, err := VerifyRunWithOptions(dir, run, hex.EncodeToString(pub), true, options)
			want := context.Canceled
			if phase == "record_report" {
				want = failure
			}
			if !errors.Is(err, want) || head != (VerifiedHead{}) {
				t.Fatalf("head=%+v err=%v want=%v", head, err, want)
			}
			wantRecords := 1
			if phase == "before" {
				wantRecords = 0
			}
			if records != wantRecords {
				t.Fatalf("records=%d want=%d", records, wantRecords)
			}
		})
	}
}
