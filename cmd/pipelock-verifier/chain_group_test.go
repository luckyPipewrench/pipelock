// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func addLegacyChainRun(t *testing.T, dir string, key ed25519.PrivateKey) {
	t.Helper()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: key, Principal: "local", Actor: "pipelock"})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	if err := emitter.Emit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: "allow", Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/legacy"}); err != nil {
		t.Fatal(err)
	}
	if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
}

func closeStandaloneTestGroup(t *testing.T, set *receipt.ReceiptShardSet) {
	t.Helper()
	for _, shard := range set.Emitters() {
		if err := shard.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := shard.EmitTranscriptRoot(shard.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := set.PublishClose(); err != nil {
		t.Fatal(err)
	}
}

func TestStandaloneChainDefaultGroupDirectoryAndMixedLegacy(t *testing.T) {
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
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeStandaloneTestGroup(t, set)
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	var groupOnlyOut, groupOnlyErr bytes.Buffer
	err = runChain(&groupOnlyOut, &groupOnlyErr, dir, chainOptions{asDir: true, sessionID: "proxy", jsonOutput: true, signerKeys: []string{hex.EncodeToString(pub)}})
	if err != nil {
		t.Fatalf("group-only JSON: %v: %s", err, groupOnlyErr.String())
	}
	var groupOnlyReport struct {
		Valid  bool                         `json:"valid"`
		Groups []receipt.ReceiptGroupResult `json:"groups"`
		Legacy json.RawMessage              `json:"legacy"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(groupOnlyOut.Bytes()), &groupOnlyReport); err != nil || !groupOnlyReport.Valid || len(groupOnlyReport.Groups) != 1 || groupOnlyReport.Groups[0].Verdict != receipt.GroupValid || string(groupOnlyReport.Legacy) != "null" {
		t.Fatalf("group-only JSON report=%+v err=%v output=%q", groupOnlyReport, err, groupOnlyOut.String())
	}
	addLegacyChainRun(t, dir, key)

	var stdout, stderr bytes.Buffer
	err = runChain(&stdout, &stderr, dir, chainOptions{asDir: true, sessionID: "proxy", signerKeys: []string{hex.EncodeToString(pub)}})
	if err != nil || !strings.Contains(stdout.String(), "GROUP_VALID") || !strings.Contains(stdout.String(), "proxy") {
		t.Fatalf("mixed default directory stdout=%q stderr=%q err=%v", stdout.String(), stderr.String(), err)
	}
}

func TestStandaloneChainDefaultGroupDirectoryJSON(t *testing.T) {
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
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("b", 64), Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeStandaloneTestGroup(t, set)
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	addLegacyChainRun(t, dir, key)

	cmd := newChainCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{dir, "--dir", "--json", "--key", hex.EncodeToString(pub)})
	err = cmd.Execute()
	if err != nil {
		t.Fatalf("default mixed group JSON: %v: %s", err, stderr.String())
	}
	var report struct {
		Valid  bool                         `json:"valid"`
		Groups []receipt.ReceiptGroupResult `json:"groups"`
		Legacy json.RawMessage              `json:"legacy"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &report); err != nil {
		t.Fatalf("combined JSON is not one document: %v output=%q", err, stdout.String())
	}
	if !report.Valid || len(report.Groups) != 1 || report.Groups[0].Verdict != receipt.GroupValid || len(report.Legacy) == 0 || string(report.Legacy) == "null" {
		t.Fatalf("mixed JSON report=%+v output=%q", report, stdout.String())
	}
	var legacy chainReport
	if err := json.Unmarshal(report.Legacy, &legacy); err != nil || !legacy.Valid {
		t.Fatalf("legacy JSON report=%+v err=%v", legacy, err)
	}
}

func TestStandaloneChainIncompleteGroupJSONIsNotValid(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("c", 64), Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := newChainCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{dir, "--dir", "--json", "--key", hex.EncodeToString(pub)})
	err = cmd.Execute()
	if err == nil {
		t.Fatalf("incomplete group returned success: %s", stdout.String())
	}
	var report struct {
		Valid  bool                         `json:"valid"`
		Groups []receipt.ReceiptGroupResult `json:"groups"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &report); err != nil {
		t.Fatalf("incomplete JSON is not one document: %v output=%q", err, stdout.String())
	}
	if report.Valid || len(report.Groups) != 1 || report.Groups[0].Verdict != receipt.GroupIncomplete {
		t.Fatalf("incomplete group JSON report=%+v stderr=%q", report, stderr.String())
	}
}

func TestStandaloneChainGroupVerdicts(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	set, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := set.Opening()
	opts := chainOptions{asDir: true, groupID: open.GroupID, signerKeys: []string{hex.EncodeToString(pub)}}
	verify := func() (string, error) {
		t.Helper()
		var out bytes.Buffer
		err := runChain(&out, &out, dir, opts)
		return out.String(), err
	}
	if out, err := verify(); err == nil || !strings.Contains(out, string(receipt.GroupIncomplete)) {
		t.Fatalf("open group output=%q err=%v", out, err)
	}
	for _, shard := range set.Emitters() {
		if err := shard.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := shard.EmitTranscriptRoot(shard.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := set.PublishClose(); err != nil {
		t.Fatal(err)
	}
	if out, err := verify(); err != nil || !strings.Contains(out, string(receipt.GroupValid)) {
		t.Fatalf("closed group output=%q err=%v", out, err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "evidence-"+open.Shards[1].SessionID+"-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("shard files=%v err=%v", files, err)
	}
	if err := os.Remove(files[0]); err != nil {
		t.Fatal(err)
	}
	if out, err := verify(); err == nil || !strings.Contains(out, string(receipt.GroupInvalid)) {
		t.Fatalf("deleted shard output=%q err=%v", out, err)
	}
	opts.signerKeys = nil
	if out, err := verify(); err == nil || strings.Contains(out, string(receipt.GroupValid)) {
		t.Fatalf("unpinned group output=%q err=%v", out, err)
	}
}
