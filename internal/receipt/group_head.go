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
	"io"
	"reflect"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// VerifyGroupShardHead derives a close head from one complete on-disk shard.
// The caller must pin the directory ceremony while publishing a close.
func VerifyGroupShardHead(dir string, open ReceiptGroupOpen, openHash string, index int) (ReceiptGroupShardHead, error) {
	return verifyGroupShardHeadWithSession(dir, open, openHash, index, nil)
}

func verifyGroupShardHeadWithSession(dir string, open ReceiptGroupOpen, openHash string, index int, session *startupSessionVerification) (ReceiptGroupShardHead, error) {
	v, err := newGroupShardVerifier(open, openHash, index)
	if err != nil {
		return ReceiptGroupShardHead{}, err
	}
	walk := func(visit func(recorder.Entry) error) error {
		return recorder.WalkSessionHistory(dir, v.shard.SessionID, visit)
	}
	if session != nil {
		v.startup = session
		v.w, v.v1, v.v2 = session.whole, session.v1, session.v2
		walk = session.walkWithInventory
	}
	if err := walk(v.add); err != nil {
		return ReceiptGroupShardHead{}, fmt.Errorf("verify receipt group shard %d: %w", index, err)
	}
	head, err := v.head()
	if err != nil {
		return ReceiptGroupShardHead{}, err
	}
	var aelHead ael.VerifiedHead
	if session == nil {
		aelHead, err = ael.VerifyRun(dir, v.run, open.SignerKey)
	} else {
		aelHead, err = session.verifyAEL(v.run, open.SignerKey, true)
	}
	if err != nil {
		return ReceiptGroupShardHead{}, fmt.Errorf("receipt group native AEL shard %d: %w", index, err)
	}
	head.NativeAELFinalSeq, head.NativeAELFinalHash, head.NativeAELRecordCount = aelHead.FinalSeq, aelHead.FinalHash, aelHead.RecordCount
	return head, nil
}

type groupShardVerifier struct {
	startup                                           *startupSessionVerification
	open                                              ReceiptGroupOpen
	openHash                                          string
	index                                             int
	shard                                             ReceiptGroupShard
	pub                                               ed25519.PublicKey
	w                                                 *WholeRecorderWalker
	v1                                                *ChainWalker
	v2                                                *EvidenceChainWalker
	firstGate, opened, closed, rooted, lastCheckpoint bool
	run, closeHash, rootEntryHash, checkpointHash     string
	finalSeq, count                                   uint64
	finalHash, lastEntryHash                          string
	entryIndex                                        int
}

func newGroupShardVerifier(open ReceiptGroupOpen, openHash string, index int) (*groupShardVerifier, error) {
	if index < 0 || index >= len(open.Shards) {
		return nil, errors.New("receipt group shard index is outside membership")
	}
	pub, err := hex.DecodeString(open.SignerKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid receipt group signer")
	}
	return &groupShardVerifier{open: open, openHash: openHash, index: index, shard: open.Shards[index], pub: pub, w: NewGroupRecorderWalker(), v1: NewChainWalker([]string{open.SignerKey}), v2: NewEvidenceChainWalker([]string{open.SignerKey}, contractreceipt.ChainVerifyOptions{})}, nil
}

func (v *groupShardVerifier) add(entry recorder.Entry) error {
	if v.rooted && (entry.Type != "checkpoint" || entry.PrevHash != v.rootEntryHash || v.lastCheckpoint) {
		return errors.New("receipt group has evidence after transcript root instead of final checkpoint")
	}
	if v.entryIndex == 0 {
		var binding ReceiptGroupBinding
		if entry.Type != recorder.GroupGateEntryType || decodeGroupEntryDetail(entry.Detail, &binding) != nil || !reflect.DeepEqual(binding, groupBinding(v.open, v.openHash, v.index)) {
			return errors.New("receipt group first entry does not match signed gate")
		}
		v.firstGate = true
	}
	if v.entryIndex == 1 && (entry.Type != "checkpoint" || entry.PrevHash != v.lastEntryHash) {
		return errors.New("receipt group gate is not covered by next checkpoint")
	}
	v.entryIndex++
	v.lastEntryHash = entry.Hash
	v.lastCheckpoint = entry.Type == "checkpoint"
	var r Receipt
	var isReceipt bool
	if v.startup == nil {
		r, isReceipt = v.w.Add(entry)
	} else {
		r, isReceipt = v.startup.authenticate(entry)
	}
	if err := v.w.Err(); err != nil {
		return err
	}
	if entry.Type == "checkpoint" {
		if err := verifyGroupCheckpoint(entry, v.pub); err != nil {
			return err
		}
		v.checkpointHash = entry.Hash
	}
	if entry.Type == transcriptRootEntryType {
		var root TranscriptRoot
		if v.rooted || !v.closed || decodeGroupEntryDetail(entry.Detail, &root) != nil || root.SessionID != v.shard.SessionID || root.FinalSeq != v.finalSeq || root.RootHash != v.finalHash || root.ReceiptCount != v.count {
			return errors.New("receipt group transcript root differs from signed closed chain")
		}
		v.rooted = true
		v.rootEntryHash = entry.Hash
	}
	if entry.Type != recorder.GroupGateEntryType {
		if ev, ok, err := contractreceipt.EvidenceReceiptFromEntry(v.entryIndex-1, entry); err != nil {
			return err
		} else if ok {
			v.v2.Add(ev)
		}
	}
	if !isReceipt {
		return nil
	}
	if v.rooted || v.closed {
		return errors.New("receipt group has action after signed close")
	}
	if v.startup == nil {
		v.v1.Add(r)
	}
	v.count++
	v.finalSeq = r.ActionRecord.ChainSeq
	var err error
	v.finalHash, err = ReceiptHash(r)
	if err != nil {
		return err
	}
	control := r.ActionRecord.SessionControl
	if v.count == 1 {
		if control == nil || control.Kind != SessionControlOpen || control.Open == nil || control.Open.RecorderSession != v.shard.SessionID || !reflect.DeepEqual(control.Open.GroupBinding, ptrGroupBinding(v.open, v.openHash, v.index)) {
			return errors.New("receipt group first signed receipt lacks matching session open")
		}
		v.run = control.Open.RunNonce
		v.opened = true
	}
	if control != nil && control.Kind == SessionControlClose {
		if !v.opened || control.Close == nil {
			return errors.New("receipt group has invalid signed close")
		}
		v.closed = true
		v.closeHash = v.finalHash
	}
	return nil
}

func (v *groupShardVerifier) head() (ReceiptGroupShardHead, error) {
	if !v.firstGate || !v.opened || !v.closed || !v.rooted || !v.lastCheckpoint || v.entryIndex < 5 || v.checkpointHash == "" {
		return ReceiptGroupShardHead{}, errors.New("receipt group shard lacks durable gate, close, root, or final checkpoint")
	}
	if result := v.v1.Result(); !result.Valid || result.FinalSeq != v.finalSeq || result.RootHash != v.finalHash || result.ReceiptCount != v.count {
		return ReceiptGroupShardHead{}, fmt.Errorf("receipt group v1 chain failed: %s", result.Error)
	}
	if v.v2.Count() > 0 {
		if result := v.v2.Result(); !result.Valid {
			return ReceiptGroupShardHead{}, fmt.Errorf("receipt group v2 chain failed: %s", result.Error)
		}
	}
	return ReceiptGroupShardHead{
		ShardIndex: v.index, SessionID: v.shard.SessionID,
		FinalChainSeq: v.finalSeq, FinalChainHash: v.finalHash, ReceiptCount: v.count,
		SessionCloseHash: v.closeHash, TranscriptRootHash: v.rootEntryHash,
		CheckpointHash: v.checkpointHash,
	}, nil
}

func groupBinding(open ReceiptGroupOpen, openHash string, index int) ReceiptGroupBinding {
	return ReceiptGroupBinding{
		GroupID: open.GroupID, ShardIndex: index, SessionID: open.Shards[index].SessionID,
		OpenManifestSHA256: openHash, SignerKey: open.SignerKey,
		PreviousGroupID: open.PreviousGroupID, PreviousOpenManifestSHA256: open.PreviousOpenManifestSHA256,
	}
}

func ptrGroupBinding(open ReceiptGroupOpen, openHash string, index int) *ReceiptGroupBinding {
	binding := groupBinding(open, openHash, index)
	return &binding
}

func decodeGroupEntryDetail(detail any, target any) error {
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
		return err
	}
	if err := rejectStructAliases(raw, reflect.TypeOf(target).Elem()); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errors.New("receipt group entry detail has trailing tokens")
	}
	return nil
}

func verifyGroupCheckpoint(entry recorder.Entry, pub ed25519.PublicKey) error {
	var detail recorder.CheckpointDetail
	if err := decodeGroupEntryDetail(entry.Detail, &detail); err != nil {
		return err
	}
	sig, err := hex.DecodeString(detail.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, []byte(entry.PrevHash), sig) {
		return errors.New("receipt group checkpoint signature failed")
	}
	return nil
}
