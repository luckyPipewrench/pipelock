// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func recoveryStreamEntries(t *testing.T, dir string, seal RecoverySeal) []recorder.Entry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(filepath.Join(dir, seal.Shard)))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(raw[:seal.DamageOffset]))
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func writeRecoveryStreamEntries(t *testing.T, path string, entries []recorder.Entry, suffix []byte) {
	t.Helper()
	var out bytes.Buffer
	for _, e := range entries {
		if len(e.RawDetail) > 0 {
			e.Detail = e.RawDetail
		}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(raw)
		out.WriteByte('\n')
	}
	out.Write(suffix)
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryStreamMultipleShards(t *testing.T) {
	for _, maxBytes := range []int64{0, recorder.MaxEvidenceReadFileBytes} {
		t.Run(map[bool]string{true: "offline", false: "live"}[maxBytes > 0], func(t *testing.T) {
			dir, seal, _ := recoveryFixture(t)
			entries := recoveryStreamEntries(t, dir, seal)
			writeRecoveryStreamEntries(t, filepath.Join(dir, seal.Shard), entries[:2], nil)
			last := "evidence-" + seal.PredecessorSession + "-2.jsonl"
			writeRecoveryStreamEntries(t, filepath.Join(dir, last), entries[2:], []byte{0, 0})
			got, err := observeRecovery(dir, seal.PredecessorSession, seal.SuccessorSignerKey, []string{seal.SuccessorSignerKey}, maxBytes)
			if err != nil {
				t.Fatal(err)
			}
			if got.Shard != last || got.LastGoodSeq != seal.LastGoodSeq || got.LastGoodHash != seal.LastGoodHash || got.PredecessorTailHash != seal.PredecessorTailHash || got.PredecessorTailSeq != seal.PredecessorTailSeq || got.PredecessorSignerKey != seal.PredecessorSignerKey {
				t.Fatalf("durable heads changed across shard boundary: %+v", got)
			}
		})
	}
}

func TestRecoveryStreamEmptyTrustMatchesNil(t *testing.T) {
	dir, seal, _ := recoveryFixture(t)
	entries := recoveryStreamEntries(t, dir, seal)
	for _, tc := range []struct {
		name    string
		trusted []string
	}{
		{name: "nil"},
		{name: "empty", trusted: []string{}},
		{name: "pinned", trusted: []string{seal.SuccessorSignerKey}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyRecoveryPrefix(seal.PredecessorSession, entries, tc.trusted); err != nil {
				t.Fatalf("valid prefix rejected: %v", err)
			}
		})
	}
}

func TestRecoveryStreamFinalRecordWithoutNewline(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{true: "bad_signature", false: "valid"}[corrupt], func(t *testing.T) {
			dir, seal, _ := recoveryFixture(t)
			entries := recoveryStreamEntries(t, dir, seal)[:2]
			if corrupt {
				r, err := receiptFromEntry(entries[1])
				if err != nil {
					t.Fatal(err)
				}
				r.Signature = signaturePrefix + strings.Repeat("0", ed25519.SignatureSize*2)
				entries[1].RawDetail, err = json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				entries[1].Hash = recorder.ComputeHash(entries[1])
			}
			path := filepath.Join(dir, seal.Shard)
			writeRecoveryStreamEntries(t, path, entries, nil)
			raw, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw[:len(raw)-1], 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := observeRecovery(dir, seal.PredecessorSession, seal.SuccessorSignerKey, nil, 0)
			if corrupt {
				if err == nil || !strings.Contains(err.Error(), "signature") {
					t.Fatalf("invalid final receipt concealed by missing LF: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			first, err := receiptFromEntry(entries[0])
			if err != nil {
				t.Fatal(err)
			}
			head, err := ReceiptHash(*first)
			if err != nil {
				t.Fatal(err)
			}
			if got.LastGoodSeq != 0 || got.LastGoodHash != entries[0].Hash || got.PredecessorTailSeq != 0 || got.PredecessorTailHash != head {
				t.Fatalf("non-durable final receipt advanced sealed heads: %+v", got)
			}
		})
	}
}

func TestRecoveryStreamRejectsCorruptPrefix(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]recorder.Entry)
	}{
		{"first_sequence", func(es []recorder.Entry) { es[0].Sequence++ }},
		{"first_previous_hash", func(es []recorder.Entry) { es[0].PrevHash = strings.Repeat("0", 64) }},
		{"sequence_gap", func(es []recorder.Entry) { es[1].Sequence++ }},
		{"outer_hash_link", func(es []recorder.Entry) { es[1].PrevHash = recorder.GenesisHash }},
		{"unknown_entry", func(es []recorder.Entry) { es[1].Type = "unknown" }},
		{"session", func(es []recorder.Entry) { es[1].SessionID = "another-session" }},
		{"namespace_transition", func(es []recorder.Entry) {
			es[1].Version, es[1].ChainKind, es[1].WriterInstanceID = 3, "flight_recorder", "writer"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, seal, _ := recoveryFixture(t)
			entries := recoveryStreamEntries(t, dir, seal)
			tc.edit(entries)
			for i := range entries {
				entries[i].Hash = recorder.ComputeHash(entries[i])
			}
			writeRecoveryStreamEntries(t, filepath.Join(dir, seal.Shard), entries, []byte{0})
			if _, err := observeRecovery(dir, seal.PredecessorSession, seal.SuccessorSignerKey, nil, 0); err == nil {
				t.Fatal("corrupt complete prefix accepted")
			}
		})
	}
}

func TestRecoveryStreamV1RotationTrust(t *testing.T) {
	pub, key := generateTestKey(t)
	newPub, newKey := generateTestKey(t)
	keys := []string{hex.EncodeToString(pub), hex.EncodeToString(newPub)}
	chain := buildRotatedChain(t, key, newKey, 2, 2)
	const session = "recovery-stream"
	entries := recoveryStreamReceiptEntries(t, session, chain)
	if err := verifyRecoveryPrefix(session, entries, keys); err != nil {
		t.Fatalf("trusted rotation rejected: %v", err)
	}
	for _, trusted := range [][]string{nil, keys[:1]} {
		if err := verifyRecoveryPrefix(session, entries, trusted); err == nil {
			t.Fatal("untrusted rotation accepted")
		}
	}
}

func recoveryStreamReceiptEntries(t *testing.T, session string, chain []Receipt) []recorder.Entry {
	t.Helper()
	entries := make([]recorder.Entry, 0, len(chain))
	prev := recorder.GenesisHash
	for i, r := range chain {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		e := recorder.Entry{Version: 2, Sequence: uint64(i), SessionID: session, Type: recorderEntryType, RawDetail: raw, PrevHash: prev}
		e.Hash = recorder.ComputeHash(e)
		prev = e.Hash
		entries = append(entries, e)
	}
	return entries
}

func TestRecoveryStreamSignaturesOnlyStartupAndDoctor(t *testing.T) {
	dir, original, key := recoveryFixture(t)
	oldPub, oldKey := generateTestKey(t)
	chain := buildRotatedChain(t, oldKey, key, 2, 2)
	entries := recoveryStreamReceiptEntries(t, original.PredecessorSession, chain)
	writeRecoveryStreamEntries(t, filepath.Join(dir, original.Shard), entries, []byte{0})
	if err := os.Remove(filepath.Join(dir, ChainLinkFileName(original.PredecessorSession))); err != nil {
		t.Fatal(err)
	}
	// Fresh-start publication holds only its own successor key. Earlier
	// predecessor rotations are observations, not operator trust decisions.
	seal, err := publishRecoverySeal(linkRequest{dir: dir, self: original.SuccessorSession, privKey: key, now: time.Now().UTC()}, original.PredecessorSession)
	if err != nil {
		t.Fatalf("startup did not seal otherwise valid rotated prefix: %v", err)
	}
	if err := VerifyRecoveryBinding(dir, *seal, nil); err == nil || !strings.Contains(err.Error(), "trusted set") {
		t.Fatalf("public nil-trust binding semantics changed: %v", err)
	}
	if err := VerifyRecoveryBinding(dir, *seal, []string{hex.EncodeToString(oldPub), seal.SuccessorSignerKey}); err != nil {
		t.Fatalf("public pinned binding rejected valid prefix: %v", err)
	}
	report, err := VerifyBase(dir, "proxy", BaseVerifyOptions{LinksOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy() || !slices.ContainsFunc(report.Chains, func(c BaseChain) bool { return c.RecoverySeal != nil }) || !slices.ContainsFunc(report.Findings, func(f BaseFinding) bool { return f.Kind == FindingAttestedDiscontinuity }) {
		t.Fatalf("doctor lost attested discontinuity: %+v", report)
	}
}

func TestRecoveryStreamSignaturesOnlyRejectsInvalidRotation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Receipt)
		want string
	}{
		{"signature", func(r *Receipt) { r.Signature = signaturePrefix + strings.Repeat("0", ed25519.SignatureSize*2) }, "signature"},
		{"unmarked_key_change", func(r *Receipt) { r.ActionRecord.KeyTransition = nil }, "seq 0"},
		{"bad_transition", func(r *Receipt) { r.ActionRecord.KeyTransition.PriorChainSeq++ }, "prior_chain_seq"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, original, key := recoveryFixture(t)
			_, oldKey := generateTestKey(t)
			chain := buildRotatedChain(t, oldKey, key, 2, 1)
			tail := &chain[len(chain)-1]
			tc.edit(tail)
			if tc.name != "signature" {
				var err error
				*tail, err = Sign(tail.ActionRecord, key)
				if err != nil {
					t.Fatal(err)
				}
			}
			entries := recoveryStreamReceiptEntries(t, original.PredecessorSession, chain)
			writeRecoveryStreamEntries(t, filepath.Join(dir, original.Shard), entries, []byte{0})
			if _, err := publishRecoverySeal(linkRequest{dir: dir, self: original.SuccessorSession, privKey: key, now: time.Now().UTC()}, original.PredecessorSession); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("startup accepted invalid prefix or wrong rejection: %v", err)
			}
			report, err := VerifyBase(dir, "proxy", BaseVerifyOptions{LinksOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			if slices.ContainsFunc(report.Chains, func(c BaseChain) bool { return c.RecoverySeal != nil }) || !slices.ContainsFunc(report.Findings, func(f BaseFinding) bool {
				return f.Kind == FindingInvalidRecoverySeal && strings.Contains(f.Detail, tc.want)
			}) {
				t.Fatalf("doctor accepted invalid prefix or wrong rejection: %+v", report)
			}
		})
	}
}

func TestRecoveryStreamV2ProducerFixture(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{true: "bad_final_signature", false: "valid"}[corrupt], func(t *testing.T) {
			dir := copyRunChainFixture(t)
			path := runFile(dir, fixtureRun1)
			entries, err := recorder.ReadEntries(path)
			if err != nil {
				t.Fatal(err)
			}
			lastV2 := -1
			for i, e := range entries {
				if e.Type == contractreceipt.EvidenceEntryType {
					lastV2 = i
				}
			}
			if lastV2 < 0 {
				t.Fatal("producer fixture has no v2 receipts")
			}
			if corrupt {
				entries = entries[:lastV2+1]
				var r contractreceipt.EvidenceReceipt
				if err := json.Unmarshal(entries[lastV2].RawDetail, &r); err != nil {
					t.Fatal(err)
				}
				r.Signature.Signature = signaturePrefix + strings.Repeat("0", ed25519.SignatureSize*2)
				entries[lastV2].RawDetail, err = json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				entries[lastV2].Hash = recorder.ComputeHash(entries[lastV2])
			}
			writeRecoveryStreamEntries(t, path, entries, []byte{0})
			if corrupt {
				// Valid final JSON without LF must still have its signature checked.
				raw, err := os.ReadFile(filepath.Clean(path))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw[:len(raw)-2], 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, trusted := range [][]string{nil, {fixtureSignerKey(t)}} {
				_, err := observeRecovery(dir, fixtureRun1, fixtureSignerKey(t), trusted, 0)
				if corrupt {
					if err == nil || !strings.Contains(err.Error(), "signature") {
						t.Fatalf("corrupt v2 receipt accepted: %v", err)
					}
				} else if err != nil {
					t.Fatalf("real v1/v2 producer fixture rejected: %v", err)
				}
			}
		})
	}
}

func TestRecoveryStreamLiveArchiveBeyondOfflineCeiling(t *testing.T) {
	const session = "recovery-stream-large"
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "evidence-"+session+"-0.jsonl")
	f, err := os.OpenFile(filepath.Clean(firstPath), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	enc := json.NewEncoder(f)
	prev := recorder.GenesisHash
	var seq uint64
	var size int64
	for size <= recorder.MaxEvidenceReadFileBytes {
		e := recorder.Entry{Version: 2, Sequence: seq, SessionID: session, Type: "capture_drop", Summary: strings.Repeat("x", 128<<10), PrevHash: prev}
		e.Hash = recorder.ComputeHash(e)
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
		prev, seq = e.Hash, seq+1
		info, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		size = info.Size()
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	last := recorder.Entry{Version: 2, Sequence: seq, SessionID: session, Type: "capture_drop", PrevHash: prev}
	last.Hash = recorder.ComputeHash(last)
	lastPath := filepath.Join(dir, fmt.Sprintf("evidence-%s-%d.jsonl", session, seq))
	writeRecoveryStreamEntries(t, lastPath, []recorder.Entry{last}, []byte{0})
	got, err := observeRecovery(dir, session, "observer", nil, 0)
	if err != nil {
		t.Fatalf("live archive of %d bytes rejected: %v", size, err)
	}
	if got.LastGoodHash != last.Hash || got.LastGoodSeq != seq {
		t.Fatalf("large live archive has wrong durable head: %+v", got)
	}
	if _, err := observeRecovery(dir, session, "observer", nil, recorder.MaxEvidenceReadFileBytes); !errors.Is(err, recorder.ErrEvidenceReadLimitExceeded) {
		t.Fatalf("offline per-file ceiling lost: %v", err)
	}
}

func TestPublishRecoverySealRequiresMatchingSuccessorKey(t *testing.T) {
	dir, original, _ := recoveryFixture(t)
	claim := filepath.Join(dir, ChainLinkFileName(original.PredecessorSession))
	if err := os.Remove(claim); err != nil {
		t.Fatal(err)
	}
	_, otherKey := generateTestKey(t)
	_, err := publishRecoverySeal(linkRequest{dir: dir, self: original.SuccessorSession, privKey: otherKey, now: time.Now().UTC()}, original.PredecessorSession)
	if err == nil || !strings.Contains(err.Error(), "signed by a different key") {
		t.Fatalf("published a seal the verifier would reject, or wrong error: %v", err)
	}
	if _, statErr := os.Stat(claim); !os.IsNotExist(statErr) {
		t.Fatalf("rejected publication still wrote a claim file: %v", statErr)
	}
}

func TestPublishRecoverySealRequiresSuccessorOpen(t *testing.T) {
	dir, original, key := recoveryFixture(t)
	if err := os.Remove(filepath.Join(dir, ChainLinkFileName(original.PredecessorSession))); err != nil {
		t.Fatal(err)
	}
	missing := "proxy.run." + strings.Repeat("e", 32)
	_, err := publishRecoverySeal(linkRequest{dir: dir, self: missing, privKey: key, now: time.Now().UTC()}, original.PredecessorSession)
	if err == nil {
		t.Fatal("sealed a recovery with no successor session_open")
	}
}

func TestPublishRecoverySealRequiresValidSuccessorPrefix(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprintf("corrupt_%t", corrupt), func(t *testing.T) {
			dir, original, key := recoveryFixture(t)
			claim := filepath.Join(dir, ChainLinkFileName(original.PredecessorSession))
			if err := os.Remove(claim); err != nil {
				t.Fatal(err)
			}
			if corrupt {
				entries, err := readSessionEntries(dir, original.SuccessorSession)
				if err != nil {
					t.Fatal(err)
				}
				entries[1].Hash = strings.Repeat("0", 64)
				writeRecoveryStreamEntries(t, filepath.Join(dir, "evidence-"+original.SuccessorSession+"-0.jsonl"), entries, nil)
			}
			seal, err := publishRecoverySeal(linkRequest{dir: dir, self: original.SuccessorSession, privKey: key, now: time.Now().UTC()}, original.PredecessorSession)
			if !corrupt {
				if err != nil || seal == nil {
					t.Fatalf("valid successor rejected: %v", err)
				}
				return
			}
			if err == nil || seal != nil {
				t.Fatalf("published invalid successor prefix: seal=%v err=%v", seal, err)
			}
			if _, err := os.Stat(claim); !os.IsNotExist(err) {
				t.Fatalf("invalid successor consumed the claim slot: %v", err)
			}
		})
	}
}
