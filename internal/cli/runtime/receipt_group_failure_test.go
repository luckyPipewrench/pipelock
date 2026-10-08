// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestRequiredGroupHeartbeatFailureCancelsAndQuarantinesEveryShard(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	shards, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64),
		Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var failures int
	stop := startStandaloneReceiptGroupLifecycle(ctx, time.Minute, shards, nil, true, func(failure error) {
		if failure == nil {
			t.Fatal("required heartbeat callback had no failure")
		}
		failures++
		cancel()
	})
	defer stop()
	if !errors.Is(ctx.Err(), context.Canceled) || failures == 0 {
		t.Fatalf("group heartbeat did not request process cancellation: ctx=%v failures=%d", ctx.Err(), failures)
	}
	for i, shard := range shards.Emitters() {
		if shard.HealthError() == nil {
			t.Fatalf("shard %d stayed healthy after required heartbeat failure", i)
		}
	}
}

func TestRequiredGroupShutdownSealFailureIsReported(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	shards, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	var failures []error
	stop := startStandaloneReceiptGroupLifecycle(context.Background(), time.Hour, shards, nil, true, func(err error) {
		failures = append(failures, err)
	})
	if len(failures) != 0 {
		t.Fatalf("healthy start reported failure: %v", failures)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	stop()
	if len(failures) < 3 {
		t.Fatalf("required shard seals and group close failures were not all reported: %v", failures)
	}
	for i, shard := range shards.Emitters() {
		if shard.HealthError() == nil {
			t.Fatalf("shard %d stayed healthy after shutdown failure", i)
		}
	}
}
