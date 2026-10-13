// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func TestReceiptGroupRestartReadyAfterSharedVerification(t *testing.T) {
	messages := newNotifySocket(t)
	dir := t.TempDir()
	keyPath := dir + "/receipt.key"
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err = signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	path := writeServerTestConfig(t, fmt.Sprintf("mode: balanced\nflight_recorder:\n  enabled: true\n  require_receipts: true\n  receipt_chains: 2\n  dir: %q\n  signing_key_path: %q\n", dir, keyPath))
	opts := ServerOpts{ConfigFile: path, Listen: serverTestEphemeralListen, ListenChanged: true, allowEphemeralListenersForTesting: true, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}}
	first, err := NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { first.cleanup() })
	firstDone := make(chan error, 1)
	go func() { firstDone <- first.Start(context.Background()) }()
	if got := receiveNotify(t, messages); got != "READY=1" {
		t.Fatalf("initial notification=%q", got)
	}
	assertListening := func(stderr *syncBuffer) {
		t.Helper()
		for _, line := range strings.Split(stderr.String(), "\n") {
			if !strings.HasPrefix(line, "  Listen: ") {
				continue
			}
			client := &http.Client{Timeout: testwait.Deadline(time.Second)}
			request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+strings.TrimPrefix(line, "  Listen: ")+"/health", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("bound listener status=%d", response.StatusCode)
			}
			return
		}
		t.Fatal("READY without a bound listener address")
	}
	assertListening(opts.Stderr.(*syncBuffer))
	for range 8 {
		set := first.receiptShardSet
		if err := set.EmitDurable(set.Admit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Target: "https://api.vendor.example/data"})); err != nil {
			t.Fatal(err)
		}
	}
	prior, _ := first.receiptShardSet.Opening()
	if err = first.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = <-firstDone; err != nil {
		t.Fatal(err)
	}
	if got := receiveNotify(t, messages); got != "STOPPING=1" {
		t.Fatalf("shutdown=%q", got)
	}
	want := make(map[string]uint64)
	for _, shard := range prior.Shards {
		if err := recorder.WalkSessionHistory(dir, shard.SessionID, func(recorder.Entry) error { want[shard.SessionID]++; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	got := make(map[string]uint64)
	opts.Stdout, opts.Stderr = &syncBuffer{}, &syncBuffer{}
	opts.StartupVerification = verification.Options{Progress: func(p verification.Progress) error {
		if p.Kind == "recorder_record" {
			mu.Lock()
			got[p.Session] += p.Records
			mu.Unlock()
		}
		return nil
	}}
	type constructed struct {
		server *Server
		err    error
	}
	construction := make(chan constructed, 1)
	go func() { s, e := NewServer(opts); construction <- constructed{s, e} }()
	var second *Server
	extensions := 0
	for second == nil {
		select {
		case message := <-messages:
			if !strings.HasPrefix(message, "EXTEND_TIMEOUT_USEC=") {
				t.Fatalf("premature completion=%q", message)
			}
			extensions++
		case result := <-construction:
			if result.err != nil {
				t.Fatal(result.err)
			}
			second = result.server
		}
	}
	t.Cleanup(func() { second.cleanup() })
	for session, count := range want {
		if got[session] != count {
			t.Errorf("time-to-listen work for %s=%d want exactly %d", session, got[session], count)
		}
	}
	opening, _ := second.receiptShardSet.Opening()
	if opening.PreviousGroupID != prior.GroupID {
		t.Fatal("restart lost transition")
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- second.Start(context.Background()) }()
	for {
		message := receiveNotify(t, messages)
		if message == "READY=1" {
			break
		}
		if !strings.HasPrefix(message, "EXTEND_TIMEOUT_USEC=") {
			t.Fatalf("completion order=%q", message)
		}
		extensions++
	}
	if extensions == 0 {
		t.Fatal("history verification made no progress notification")
	}
	assertListening(opts.Stderr.(*syncBuffer))
	if err = second.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = <-secondDone; err != nil {
		t.Fatal(err)
	}
}
