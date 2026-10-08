// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Generate an actual Go-producer recovery group fixture.
// Run from the repository root:
// go run sdk/verifiers/python/tests/fixtures/produce_recovery_group_fixture.go /path/to/empty/output [successor-shards]
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type trustFixture struct {
	GroupID     string   `json:"group_id"`
	TrustedKeys []string `json:"trusted_keys"`
}

func generateKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return public, private
}

func newRecorder(dir string, key ed25519.PrivateKey) *recorder.Recorder {
	r, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		panic(err)
	}
	return r
}

func emitterConfig(r *recorder.Recorder, key ed25519.PrivateKey) receipt.EmitterConfig {
	return receipt.EmitterConfig{
		Recorder: r, PrivKey: key, ConfigHash: "fixture",
		Principal: "local", Actor: "pipelock",
	}
}

func closeGroup(set *receipt.ReceiptShardSet, r *recorder.Recorder) {
	for _, emitter := range set.Emitters() {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			panic(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			panic(err)
		}
	}
	if _, err := set.PublishClose(); err != nil {
		panic(err)
	}
	if err := r.Close(); err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		panic("output directory and optional successor shard count required")
	}
	successorShards := 2
	if len(os.Args) == 3 {
		var parseErr error
		successorShards, parseErr = strconv.Atoi(os.Args[2])
		if parseErr != nil || successorShards < 2 || successorShards > 32 {
			panic("invalid successor shard count")
		}
	}
	root := os.Args[1]
	if err := os.MkdirAll(root, 0o750); err != nil {
		panic(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		panic("output directory must be empty")
	}
	name := "group-recovery-successor"
	if successorShards != 2 {
		name = "group-recovery-count-change"
	}
	dir := filepath.Join(root, name)
	if err := os.Mkdir(dir, 0o750); err != nil {
		panic(err)
	}
	oldPublic, oldPrivate := generateKey()
	oldRecorder := newRecorder(dir, oldPrivate)
	oldSet, err := receipt.OpenInitialReceiptShardSet(emitterConfig(oldRecorder, oldPrivate), "proxy", 2, 0)
	if err != nil {
		panic(err)
	}
	oldOpen, _ := oldSet.Opening()
	if err := oldRecorder.Close(); err != nil {
		panic(err)
	}
	shard := filepath.Join(dir, "evidence-"+oldOpen.Shards[0].SessionID+"-0.jsonl")
	f, err := os.OpenFile(shard, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		panic(err)
	}
	if _, err := f.WriteString(`{"torn":`); err != nil {
		panic(err)
	}
	if err := f.Close(); err != nil {
		panic(err)
	}

	newPublic, newPrivate := generateKey()
	newRecorder := newRecorder(dir, newPrivate)
	newSet, err := receipt.OpenSuccessorReceiptShardSet(emitterConfig(newRecorder, newPrivate), "proxy", successorShards, 0, oldOpen.GroupID)
	if err != nil {
		panic(err)
	}
	newOpen, _ := newSet.Opening()
	closeGroup(newSet, newRecorder)
	result := receipt.VerifyReceiptGroup(dir, newOpen.GroupID, []string{
		hex.EncodeToString(oldPublic), hex.EncodeToString(newPublic),
	})
	if result.Verdict != receipt.GroupValid {
		panic(fmt.Sprintf("Go verifier rejected recovery fixture: %+v", result))
	}
	trust, err := json.Marshal(trustFixture{
		GroupID:     newOpen.GroupID,
		TrustedKeys: []string{hex.EncodeToString(oldPublic), hex.EncodeToString(newPublic)},
	})
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trust.json"), trust, 0o600); err != nil {
		panic(err)
	}
	fmt.Printf("%s: %s after incomplete %s\n", name, newOpen.GroupID, oldOpen.GroupID)
}
