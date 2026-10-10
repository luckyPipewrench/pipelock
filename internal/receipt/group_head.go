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
// It retains only chain walkers and a few terminal records in memory. The
// caller must pin the directory ceremony while publishing a close.
func VerifyGroupShardHead(dir string, open ReceiptGroupOpen, openHash string, index int) (ReceiptGroupShardHead, error) {
	if index < 0 || index >= len(open.Shards) {
		return ReceiptGroupShardHead{}, errors.New("receipt group shard index is outside membership")
	}
	shard := open.Shards[index]
	pub, err := hex.DecodeString(open.SignerKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return ReceiptGroupShardHead{}, errors.New("invalid receipt group signer")
	}
	w := NewGroupRecorderWalker()
	v1 := NewChainWalker([]string{open.SignerKey})
	v2 := NewEvidenceChainWalker([]string{open.SignerKey}, contractreceipt.ChainVerifyOptions{})
	var firstGate, opened, closed, rooted, lastCheckpoint bool
	var run string
	var closeHash, rootEntryHash, checkpointHash string
	var finalSeq, count uint64
	var finalHash string
	var lastEntryHash string
	entryIndex := 0
	err = recorder.WalkSessionHistory(dir, shard.SessionID, func(entry recorder.Entry) error {
		if rooted && (entry.Type != "checkpoint" || entry.PrevHash != rootEntryHash || lastCheckpoint) {
			return errors.New("receipt group has evidence after transcript root instead of final checkpoint")
		}
		if entryIndex == 0 {
			var binding ReceiptGroupBinding
			if entry.Type != recorder.GroupGateEntryType || decodeGroupEntryDetail(entry.Detail, &binding) != nil || !reflect.DeepEqual(binding, groupBinding(open, openHash, index)) {
				return errors.New("receipt group first entry does not match signed gate")
			}
			firstGate = true
		}
		if entryIndex == 1 && (entry.Type != "checkpoint" || entry.PrevHash != lastEntryHash) {
			return errors.New("receipt group gate is not covered by next checkpoint")
		}
		entryIndex++
		lastEntryHash = entry.Hash
		lastCheckpoint = entry.Type == "checkpoint"
		r, isReceipt := w.Add(entry)
		if err := w.Err(); err != nil {
			return err
		}
		if entry.Type == "checkpoint" {
			if err := verifyGroupCheckpoint(entry, pub); err != nil {
				return err
			}
			checkpointHash = entry.Hash
		}
		if entry.Type == transcriptRootEntryType {
			var root TranscriptRoot
			if rooted || !closed || decodeGroupEntryDetail(entry.Detail, &root) != nil || root.SessionID != shard.SessionID || root.FinalSeq != finalSeq || root.RootHash != finalHash || root.ReceiptCount != count {
				return errors.New("receipt group transcript root differs from signed closed chain")
			}
			rooted = true
			rootEntryHash = entry.Hash
		}
		if entry.Type != recorder.GroupGateEntryType {
			if ev, ok, err := contractreceipt.EvidenceReceiptFromEntry(entryIndex-1, entry); err != nil {
				return err
			} else if ok {
				v2.Add(ev)
			}
		}
		if !isReceipt {
			return nil
		}
		if rooted || closed {
			return errors.New("receipt group has action after signed close")
		}
		v1.Add(r)
		count++
		finalSeq = r.ActionRecord.ChainSeq
		finalHash, err = ReceiptHash(r)
		if err != nil {
			return err
		}
		control := r.ActionRecord.SessionControl
		if count == 1 {
			if control == nil || control.Kind != SessionControlOpen || control.Open == nil || control.Open.RecorderSession != shard.SessionID || !reflect.DeepEqual(control.Open.GroupBinding, ptrGroupBinding(open, openHash, index)) {
				return errors.New("receipt group first signed receipt lacks matching session open")
			}
			run = control.Open.RunNonce
			opened = true
		}
		if control != nil && control.Kind == SessionControlClose {
			if !opened || control.Close == nil {
				return errors.New("receipt group has invalid signed close")
			}
			closed = true
			closeHash = finalHash
		}
		return nil
	})
	if err != nil {
		return ReceiptGroupShardHead{}, fmt.Errorf("verify receipt group shard %d: %w", index, err)
	}
	if !firstGate || !opened || !closed || !rooted || !lastCheckpoint || entryIndex < 5 || checkpointHash == "" {
		return ReceiptGroupShardHead{}, errors.New("receipt group shard lacks durable gate, close, root, or final checkpoint")
	}
	if result := v1.Result(); !result.Valid || result.FinalSeq != finalSeq || result.RootHash != finalHash || result.ReceiptCount != count {
		return ReceiptGroupShardHead{}, fmt.Errorf("receipt group v1 chain failed: %s", result.Error)
	}
	if v2.Count() > 0 {
		if result := v2.Result(); !result.Valid {
			return ReceiptGroupShardHead{}, fmt.Errorf("receipt group v2 chain failed: %s", result.Error)
		}
	}
	aelHead, err := ael.VerifyRun(dir, run, open.SignerKey)
	if err != nil {
		return ReceiptGroupShardHead{}, fmt.Errorf("receipt group native AEL shard %d: %w", index, err)
	}
	return ReceiptGroupShardHead{
		ShardIndex: index, SessionID: shard.SessionID,
		FinalChainSeq: finalSeq, FinalChainHash: finalHash, ReceiptCount: count,
		SessionCloseHash: closeHash, TranscriptRootHash: rootEntryHash,
		CheckpointHash: checkpointHash, NativeAELFinalSeq: aelHead.FinalSeq,
		NativeAELFinalHash: aelHead.FinalHash, NativeAELRecordCount: aelHead.RecordCount,
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
