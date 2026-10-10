// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestRecoveryBindingRejectsInvalidSuccessorPrefix(t *testing.T) {
	dir, seal, _ := recoveryFixture(t)
	path := mustRecorderFiles(t, dir, seal.SuccessorSession)[0]
	es, err := recorder.ReadEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := receiptFromEntry(es[0])
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = signaturePrefix + strings.Repeat("0", 128)
	es[0].RawDetail, err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	previous := recorder.GenesisHash
	for i := range es {
		es[i].PrevHash = previous
		es[i].Hash = recorder.ComputeHash(es[i])
		previous = es[i].Hash
	}
	writeRecoveryStreamEntries(t, path, es, nil)
	if err := VerifyRecoveryBinding(dir, seal, []string{seal.SuccessorSignerKey}); err == nil || !strings.Contains(err.Error(), "tail receipt signature invalid") {
		t.Fatalf("invalid successor prefix accepted: %v", err)
	}
	report, err := VerifyBase(dir, "proxy", BaseVerifyOptions{TrustedKeys: []string{seal.SuccessorSignerKey}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy() {
		t.Fatal("invalid successor prefix reported healthy")
	}
	for _, chain := range report.Chains {
		if chain.RecoverySeal != nil {
			t.Fatal("invalid successor prefix received a seal")
		}
	}
}

func TestRecoverySealConcurrentPublicationRetries(t *testing.T) {
	dir, seal, key := recoveryFixture(t)
	if err := os.Remove(filepath.Join(dir, ChainLinkFileName(seal.PredecessorSession))); err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, seal.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	const publishers = 8
	start := make(chan struct{})
	results := make(chan error, publishers)
	var workers sync.WaitGroup
	for range publishers {
		workers.Go(func() {
			<-start
			got, err := publishRecoverySeal(linkRequest{dir: dir, self: seal.SuccessorSession, privKey: key, now: now}, seal.PredecessorSession)
			if err == nil {
				if got == nil {
					err = errors.New("publication returned no seal")
				} else {
					err = VerifyRecoveryBinding(dir, *got, []string{seal.SuccessorSignerKey})
				}
			}
			results <- err
		})
	}
	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent publication: %v", err)
		}
	}
	claims, err := readChainLinkFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || claims[0].err != nil || claims[0].seal == nil {
		t.Fatalf("publication did not produce one valid claim: %+v", claims)
	}
	report, err := VerifyBase(dir, "proxy", BaseVerifyOptions{TrustedKeys: []string{seal.SuccessorSignerKey}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy() {
		t.Fatal("concurrent seal publication concealed damage")
	}
}

func TestRecoveryCanonicalArtifactMarshalFailure(t *testing.T) {
	if _, err := canonicalArtifactBytes(recoverySealDomain, make(chan int)); err == nil || !strings.Contains(err.Error(), "unsupported type") {
		t.Fatalf("unsupported artifact value accepted: %v", err)
	}
}

func TestRecoveryPrefixRejectsEmptyTrustedKey(t *testing.T) {
	dir, seal, _ := recoveryFixture(t)
	entries := recoveryStreamEntries(t, dir, seal)
	for _, tc := range []struct {
		name   string
		verify func() error
	}{
		{"prefix", func() error { return verifyRecoveryPrefix(seal.PredecessorSession, entries, []string{" "}) }},
		{"observation", func() error {
			_, err := observeRecovery(dir, seal.PredecessorSession, seal.SuccessorSignerKey, []string{" "})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.verify(); err == nil || !strings.Contains(err.Error(), "trusted signer key cannot be empty") {
				t.Fatalf("empty trust accepted: %v", err)
			}
		})
	}
}

func TestRecoveryObservationEarlierShardErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		edit     func(*testing.T, string, []recorder.Entry)
		want     string
		sentinel error
	}{
		{"parse", func(t *testing.T, path string, _ []recorder.Entry) {
			if err := os.WriteFile(path, []byte("{\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "", nil},
		{"torn_non_final", func(t *testing.T, path string, es []recorder.Entry) {
			writeRecoveryStreamEntries(t, path, es, []byte("{"))
		}, "", recorder.ErrTornTail},
		{"stream_invalid_prefix", func(t *testing.T, path string, es []recorder.Entry) {
			es[0].Sequence++
			es[0].Hash = recorder.ComputeHash(es[0])
			writeRecoveryStreamEntries(t, path, es, nil)
		}, "genesis mismatch", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, seal, _ := recoveryFixture(t)
			es := recoveryStreamEntries(t, dir, seal)
			path := filepath.Join(dir, seal.Shard)
			writeRecoveryStreamEntries(t, path, es[:2], nil)
			writeRecoveryStreamEntries(t, filepath.Join(dir, "evidence-"+seal.PredecessorSession+"-2.jsonl"), es[2:], []byte{0})
			if _, err := observeRecovery(dir, seal.PredecessorSession, seal.SuccessorSignerKey, nil); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			tc.edit(t, path, es[:2])
			got, err := observeRecovery(dir, seal.PredecessorSession, seal.SuccessorSignerKey, nil)
			if err == nil || (tc.sentinel != nil && !errors.Is(err, tc.sentinel)) || (tc.want != "" && !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("want %q/%v, got %v", tc.want, tc.sentinel, err)
			}
			if got != (RecoverySeal{}) {
				t.Fatalf("failed observation returned seal: %+v", got)
			}
		})
	}
}

func TestRecoveryPrefixSchemaAndNamespace(t *testing.T) {
	const session = "recovery-prefix"
	for _, tc := range []struct {
		name string
		edit func([]recorder.Entry)
		want string
	}{
		{"schema", func(es []recorder.Entry) { es[0].Summary = "bad\x00summary" }, "summary cannot contain NUL"},
		{"genesis", func(es []recorder.Entry) { es[0].Sequence = 1 }, "genesis mismatch"},
		{"sequence", func(es []recorder.Entry) { es[1].Sequence = 2 }, "sequence or hash link mismatch"},
		{"namespace_version", func(es []recorder.Entry) { es[1].Version = 2; es[1].ChainKind = ""; es[1].WriterInstanceID = "" }, "namespace changed"},
		{"namespace_kind", func(es []recorder.Entry) { es[1].ChainKind = "other" }, "namespace changed"},
		{"namespace_writer", func(es []recorder.Entry) { es[1].WriterInstanceID = "other" }, "namespace changed"},
		{"entry_type", func(es []recorder.Entry) { es[0].Type = "unknown" }, "unexpected recorder entry type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			es := []recorder.Entry{
				{Version: 3, SessionID: session, Type: "capture_drop", ChainKind: recorder.ChainKindRecorder, WriterInstanceID: "writer", PrevHash: recorder.GenesisHash},
				{Version: 3, SessionID: session, Type: "capture_drop", Sequence: 1, ChainKind: recorder.ChainKindRecorder, WriterInstanceID: "writer"},
			}
			es[0].Hash = recorder.ComputeHash(es[0])
			es[1].PrevHash = es[0].Hash
			es[1].Hash = recorder.ComputeHash(es[1])
			if err := verifyRecoveryPrefix(session, es, nil); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			tc.edit(es)
			es[0].Hash = recorder.ComputeHash(es[0])
			es[1].PrevHash = es[0].Hash
			es[1].Hash = recorder.ComputeHash(es[1])
			if err := verifyRecoveryPrefix(session, es, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRecoveryPrefixSessionBinding(t *testing.T) {
	_, key := generateTestKey(t)
	r := signBoundOpen(t, key, time.Now().UTC())
	es := recoveryStreamReceiptEntries(t, recorderSessionID, []Receipt{r})
	if err := verifyRecoveryPrefix(recorderSessionID, es, nil); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	es[0].SessionID = "another-session"
	es[0].Hash = recorder.ComputeHash(es[0])
	if err := verifyRecoveryPrefix(es[0].SessionID, es, nil); err == nil || !strings.Contains(err.Error(), "session binding mismatch") {
		t.Fatalf("cross-session opening accepted: %v", err)
	}
}

func TestRecoveryPrefixV1FailureRemainsLatched(t *testing.T) {
	const session = "recovery-prefix"
	_, key := generateTestKey(t)
	chain := buildChain(t, key, 2)
	// Both signatures are valid, but the first inner receipt is replayed at
	// the second outer position. Signature validation alone cannot catch it.
	es := recoveryStreamReceiptEntries(t, session, []Receipt{chain[0], chain[0]})
	v, err := newRecoveryPrefixVerifier(session, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.add(es[0]); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	if err := v.add(es[1]); err == nil || !strings.Contains(err.Error(), "recovery receipt prefix") {
		t.Fatalf("misplaced inner receipt accepted: %v", err)
	}
	if err := v.finish(); err == nil || !strings.Contains(err.Error(), "recovery receipt prefix") {
		t.Fatalf("failed prefix became healthy: %v", err)
	}
}

func TestRecoveryPrefixV2FailureRemainsLatched(t *testing.T) {
	dir := copyRunChainFixture(t)
	es, err := recorder.ReadEntries(runFile(dir, fixtureRun1))
	if err != nil {
		t.Fatal(err)
	}
	v, err := newRecoveryPrefixVerifier(fixtureRun1, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		if e.Type != contractreceipt.EvidenceEntryType {
			if err := v.add(e); err != nil {
				t.Fatal(err)
			}
			continue
		}
		// This real producer's signed receipt is valid on its own. Repeating
		// it in the outer chain tests the independent inner-chain check.
		if err := v.add(e); err != nil {
			t.Fatal(err)
		}
		// Reuse valid signed wire bytes at a new outer position.
		e.Sequence++
		e.PrevHash = e.Hash
		e.Hash = recorder.ComputeHash(e)
		if err := v.add(e); err == nil || !strings.Contains(err.Error(), "recovery v2 prefix") {
			t.Fatalf("duplicate inner receipt accepted: %v", err)
		}
		if err := v.finish(); err == nil || !strings.Contains(err.Error(), "recovery v2 prefix") {
			t.Fatalf("failed prefix became healthy: %v", err)
		}
		return
	}
	t.Fatal("fixture has no v2 receipt")
}
