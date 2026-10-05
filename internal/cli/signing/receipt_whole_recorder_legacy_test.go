// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

// This file keeps the whole-recorder verifier as it was before verification
// streamed: it reads every entry into memory and then walks the slices. It is
// the oracle for the streaming verifier's parity tests and must not change
// except to follow a deliberate verdict change in both implementations.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// legacyVerifyWholeRecorderFromFile verifies every entry of one recorder file. name
// is the filename the operator gave, which may differ from the base of the
// resolved path when the operator named a symlink.
func legacyVerifyWholeRecorderFromFile(out io.Writer, name, path string, trustedKeys []string, opts verifyReceiptOptions) error {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("reading recorder file: %w", err)
	}
	defer func() { _ = file.Close() }()
	// Stream the handle so the reader's bounded-read limits apply before the
	// whole file is held in memory.
	entries, err := recorder.ReadEntriesFromReader(file)
	if err != nil {
		return fmt.Errorf("whole-recorder verification failed: not a recorder file or recorder integrity error: %w", err)
	}
	// A file named for a session holds only that session's entries.
	if session, _, ok := recorder.ParseEvidenceFilename(name); ok {
		if err := recorder.CheckEntrySessions(entries, session); err != nil {
			_, _ = fmt.Fprintf(out, "CHAIN BROKEN: %s\n  Error:    %s: %v\n", path, name, err)
			return fmt.Errorf("whole-recorder verification failed: %s: %w", name, err)
		}
	}
	result, err := receipt.VerifyWholeRecorderEntries(entries)
	if err != nil {
		return fmt.Errorf("whole-recorder verification failed: not a recorder file or recorder integrity error: %w", err)
	}
	return legacyVerifyWholeRecorderDetailed(out, path, entries, result, trustedKeys, opts)
}

func legacyVerifyWholeRecorderFromResolvedSessionDir(out io.Writer, location recorder.EvidenceLocation, sessionID string, trustedKeys []string, opts verifyReceiptOptions) error {
	query, err := recorder.QuerySessionResolved(location, sessionID, nil)
	if err != nil {
		return fmt.Errorf("reading recorder session: %w", err)
	}
	if query.Truncated {
		_, _ = fmt.Fprintf(out, "INCOMPLETE: evidence session %s exceeded bounded read limits\n", sessionID)
		return fmt.Errorf("whole-recorder verification failed: evidence session %s exceeded bounded read limits", sessionID)
	}
	result, err := receipt.VerifyWholeRecorderEntries(query.Entries)
	if err != nil {
		return fmt.Errorf("whole-recorder verification failed: %w", err)
	}
	label := fmt.Sprintf("%s (session %s)", location.Dir, sessionID)
	return legacyVerifyWholeRecorderDetailed(out, label, query.Entries, result, trustedKeys, opts)
}

func legacyVerifyWholeRecorderDetailed(out io.Writer, label string, entries []recorder.Entry, whole receipt.WholeRecorderResult, trustedKeys []string, opts verifyReceiptOptions) error {
	_, _ = fmt.Fprintf(out, "WHOLE-RECORDER: %s\n", label)
	_, _ = fmt.Fprintf(out, "  Mode:      whole-recorder\n")
	_, _ = fmt.Fprintf(out, "  Entries:   %d recorder entries hash-chain-verified and in-taxonomy\n", whole.EntryCount)
	evidenceReceipts, err := contractreceipt.ExtractEvidenceReceiptsFromEntries(entries)
	if err != nil {
		_, _ = fmt.Fprintf(out, "  EVIDENCE CHAIN BROKEN: %v\n", err)
		return fmt.Errorf("evidence receipt chain: %w", err)
	}
	if len(whole.Receipts) == 0 && len(evidenceReceipts) > 0 {
		// Evidence receipts alone: verify them, but the transcript_root seal
		// covers an action receipt chain, so there is nothing it can seal.
		if err := verifyEvidenceChainDetailed(out, label, evidenceReceipts, trustedKeys, opts); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(out, "  INCOMPLETE: no action receipt chain, so no transcript_root seal covers this recorder")
		return errUnsealedRecorder
	}
	chain := verifiedChainResult(whole.Receipts, trustedKeys, opts)
	if !chain.Valid || (len(trustedKeys) == 0 && !opts.AllowUnpinned) {
		return verifyChainResultDetailed(out, label, whole.Receipts, chain, trustedKeys, opts)
	}
	// Both receipt chains are authenticated by their own signatures. A
	// checkpoint anchors only the entries that are not receipts, so a forged
	// EvidenceReceipt v2 must fail here even when the anchor is waived.
	var evidenceChain contractreceipt.ChainResult
	if len(evidenceReceipts) > 0 {
		evidenceChain = receipt.VerifyEvidenceChainTrusted(evidenceReceipts, trustedKeys, contractreceipt.ChainVerifyOptions{})
		if !evidenceChain.Valid {
			_, _ = fmt.Fprintf(out, "  EVIDENCE CHAIN BROKEN: %s\n", evidenceChain.Error)
			return fmt.Errorf("evidence receipt chain verification failed at seq %d: %s", evidenceChain.BrokenAtSeq, evidenceChain.Error)
		}
	}
	root, rootIndex, rootSessionID, found, err := legacyTranscriptRootFromEntries(entries)
	if err != nil {
		_, _ = fmt.Fprintf(out, "  SEAL MISMATCH: %v\n", err)
		return fmt.Errorf("seal verification failed: %w", err)
	}
	if !found {
		_, _ = fmt.Fprintln(out, "  INCOMPLETE: no transcript_root seal (recorder still running or tail truncated)")
		return errUnsealedRecorder
	}
	rootReceiptCount := legacyReceiptEntriesBefore(entries, rootIndex)
	if rootReceiptCount == 0 || rootReceiptCount > len(whole.Receipts) {
		_, _ = fmt.Fprintln(out, "  SEAL MISMATCH")
		return fmt.Errorf("seal verification failed: transcript_root has no matching receipt prefix")
	}
	rootChain := verifiedChainResult(whole.Receipts[:rootReceiptCount], trustedKeys, opts)
	if !rootChain.Valid || !transcriptRootMatchesChainSegment(root, rootSessionID, rootChain) {
		_, _ = fmt.Fprintln(out, "  SEAL MISMATCH")
		return fmt.Errorf("seal verification failed: transcript_root does not match its verified receipt-chain segment")
	}
	if unsealed, ok := legacyFirstUnsealedEntryAfter(entries, rootIndex); ok {
		_, _ = fmt.Fprintf(out, "  INCOMPLETE: transcript_root seal precedes later unsealed entries (first: %s at seq %d)\n", unsealed.Type, unsealed.Sequence)
		return fmt.Errorf("whole-recorder verification incomplete: transcript_root seal precedes later unsealed %s entry at seq %d", unsealed.Type, unsealed.Sequence)
	}
	// The receipt chain already verified every signer, including a successor
	// authorized by a rotation endorsement. A checkpoint must be signed by the
	// key that was active where it sits, so each one is checked against the
	// signer of the receipt segment it belongs to rather than the union of
	// every key that ever signed.
	anchor, err := legacyVerifyCheckpointAnchors(entries, whole.Receipts)
	if err != nil {
		_, _ = fmt.Fprintf(out, "  ANCHOR MISMATCH: %v\n", err)
		return fmt.Errorf("checkpoint anchor verification failed: %w", err)
	}
	// A signed checkpoint authenticates only the entries before it. The seal
	// is the last thing that matters, so the checkpoint that covers it must
	// come after it: with at most one entry allowed past the root, that is
	// the trailing checkpoint, signed. A recorder that signs checkpoints (the
	// default) can have that trailing checkpoint removed, or every signature
	// stripped, by whoever rewrites the file, and an older checkpoint would
	// still verify while everything after it was rewritten. So a seal not
	// covered by a signed checkpoint is refused unless the operator accepts
	// it explicitly. The writer can also legitimately end a session without a
	// trailing checkpoint when its last entry filled a shard, and a recorder
	// configured not to sign never has one; both states go through the same
	// explicit flag and are named in the output.
	if anchor.lastSignedIndex <= rootIndex && !opts.AllowUnanchoredSeal {
		_, _ = fmt.Fprintln(out, "  UNANCHORED: no signed checkpoint covers the transcript_root seal; recorder entries after the last signed checkpoint that are not receipts are hash-linked but not authenticated")
		return fmt.Errorf("whole-recorder verification unanchored: no signed checkpoint covers the transcript_root seal (checkpoints absent, unsigned, or none after the seal); pass --allow-unanchored-seal to accept hash linkage only for the non-receipt entries after the last anchor")
	}
	if err := verifyChainResultDetailed(out, label, whole.Receipts, chain, trustedKeys, opts); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "  Receipts:  %d receipts verified\n", chain.ReceiptCount)
	if len(evidenceReceipts) > 0 {
		_, _ = fmt.Fprintf(out, "  Evidence:  %d evidence receipts verified\n", evidenceChain.ReceiptCount)
	}
	_, _ = fmt.Fprintf(out, "  Seal:      sealed at seq %d\n", root.FinalSeq)
	switch {
	case anchor.lastSignedIndex > rootIndex && len(trustedKeys) == 0:
		// Unpinned: the signer came from the receipts in this same file, so it
		// says nothing about provenance. Do not call it trusted.
		_, _ = fmt.Fprintf(out, "  Anchor:    %d signed checkpoints verified against the file's own signer, which was NOT checked against a trusted key\n", anchor.signed)
	case anchor.lastSignedIndex > rootIndex:
		_, _ = fmt.Fprintf(out, "  Anchor:    %d signed checkpoints verified; every entry through the seal is committed by a trusted key\n", anchor.signed)
	case anchor.signed > 0:
		_, _ = fmt.Fprintf(out, "  Anchor:    %d signed checkpoints verified, none after the seal (accepted by --allow-unanchored-seal); recorder entries after seq %d that are not action or evidence receipts are hash-linked but not authenticated\n", anchor.signed, entries[anchor.lastSignedIndex].Sequence)
	default:
		_, _ = fmt.Fprintln(out, "  Anchor:    no signed checkpoint (accepted by --allow-unanchored-seal); recorder entries other than action and evidence receipts are hash-linked but not authenticated; both receipt chains were signature-verified")
	}
	_, _ = fmt.Fprintln(out, "  Limit:     the seal covers the final signing segment; only the recorder's trailing checkpoint may follow it, hash-chain-verified but not sealed")
	return nil
}

// legacyVerifyCheckpointAnchors checks every checkpoint entry's span and, when it
// carries a signature, verifies that signature against the key that was
// active where the checkpoint sits: the signer of the most recent receipt
// before it, or, for a checkpoint written in the gap between two signing
// segments, either that key or the signer of the next receipt, since a new
// writer instance can checkpoint before its first receipt. The receipts are
// the already-verified chain, so every signer in them is trusted or endorsed,
// and scoping to the segment means a retired key cannot re-sign checkpoints
// after its rotation and a successor cannot sign before its activation. A
// signed checkpoint commits the chain hash of every entry before it, so it
// is the only authenticated anchor for entries that are not receipts; an
// unsigned checkpoint proves nothing beyond hash linkage and is not an
// anchor. A session may legitimately mix the two when sign_checkpoints
// changed between restarts; that costs nothing, because a stripped earlier
// signature changes that entry's hash and breaks every later checkpoint's
// signature, and a stripped trailing signature leaves the seal uncovered.
// The span must match the checkpoint's position: it ends at the preceding
// entry, starts after the previous checkpoint, and counts exactly the
// entries between; it need not start right after the previous checkpoint,
// because a crash resume starts a new span at the first resumed entry, and
// the span is metadata the signature does not depend on. A checkpoint whose
// detail does not parse, whose span disagrees with its position, or whose
// signature does not verify under its segment's key fails closed. What this
// cannot catch: on a recorder that never signed, a rewritten trailing entry
// with a self-consistent span; the output reports that state as unanchored.
func legacyVerifyCheckpointAnchors(entries []recorder.Entry, receipts []receipt.Receipt) (checkpointAnchor, error) {
	anchor := checkpointAnchor{lastSignedIndex: -1}
	var prevCheckpoint *recorder.Entry
	seenReceipts := 0
	for i := range entries {
		entry := entries[i]
		if entry.Type == "action_receipt" {
			seenReceipts++
			continue
		}
		if entry.Type != "checkpoint" {
			continue
		}
		detailJSON, err := json.Marshal(entry.Detail)
		if err != nil {
			return anchor, fmt.Errorf("checkpoint at seq %d: encoding detail: %w", entry.Sequence, err)
		}
		var detail recorder.CheckpointDetail
		if err := json.Unmarshal(detailJSON, &detail); err != nil {
			return anchor, fmt.Errorf("checkpoint at seq %d: malformed detail: %w", entry.Sequence, err)
		}
		if i == 0 || detail.LastSeq != entries[i-1].Sequence {
			return anchor, fmt.Errorf("checkpoint at seq %d: span ends at seq %d but the preceding entry is seq %d", entry.Sequence, detail.LastSeq, legacyPrecedingSequence(entries, i))
		}
		// EntryCount-1 == LastSeq-FirstSeq avoids the +1 that would wrap at the
		// top of the sequence space; FirstSeq <= LastSeq is checked first so
		// the subtraction cannot wrap either.
		if detail.FirstSeq > detail.LastSeq || detail.EntryCount == 0 || detail.EntryCount-1 != detail.LastSeq-detail.FirstSeq {
			return anchor, fmt.Errorf("checkpoint at seq %d: span %d-%d does not hold %d entries", entry.Sequence, detail.FirstSeq, detail.LastSeq, detail.EntryCount)
		}
		if prevCheckpoint != nil && detail.FirstSeq <= prevCheckpoint.Sequence {
			return anchor, fmt.Errorf("checkpoint at seq %d: span starts at seq %d, inside the previous checkpoint at seq %d", entry.Sequence, detail.FirstSeq, prevCheckpoint.Sequence)
		}
		prevCheckpoint = &entries[i]
		if detail.Signature == "" {
			anchor.unsigned++
			continue
		}
		pubs, err := segmentSignerKeys(receipts, seenReceipts)
		if err != nil {
			return anchor, fmt.Errorf("checkpoint at seq %d: %w", entry.Sequence, err)
		}
		sig, err := hex.DecodeString(detail.Signature)
		if err != nil {
			return anchor, fmt.Errorf("checkpoint at seq %d: decoding signature: %w", entry.Sequence, err)
		}
		verified := false
		for _, pub := range pubs {
			if ed25519.Verify(pub, []byte(entry.PrevHash), sig) {
				verified = true
				break
			}
		}
		if !verified {
			return anchor, fmt.Errorf("checkpoint at seq %d: signature does not verify under the signer of its receipt segment", entry.Sequence)
		}
		anchor.signed++
		anchor.lastSignedIndex = i
	}
	return anchor, nil
}

func legacyPrecedingSequence(entries []recorder.Entry, i int) uint64 {
	if i == 0 {
		return 0
	}
	return entries[i-1].Sequence
}

// segmentSignerKeys returns the public keys that may sign a checkpoint with
// seenReceipts receipts before it: the signer of the last of those (or of
// the first receipt when none precede it), plus the signer of the next
// receipt when it differs, because a checkpoint in the gap between two
// signing segments can legitimately come from either writer instance.
func segmentSignerKeys(receipts []receipt.Receipt, seenReceipts int) ([]ed25519.PublicKey, error) {
	if len(receipts) == 0 {
		return nil, fmt.Errorf("signed checkpoint present but the recorder holds no receipts to name its signer")
	}
	prev := seenReceipts - 1
	if prev < 0 {
		prev = 0
	}
	if prev >= len(receipts) {
		prev = len(receipts) - 1
	}
	hexKeys := []string{receipts[prev].SignerKey}
	if next := seenReceipts; next < len(receipts) && next != prev && receipts[next].SignerKey != receipts[prev].SignerKey {
		hexKeys = append(hexKeys, receipts[next].SignerKey)
	}
	pubs := make([]ed25519.PublicKey, 0, len(hexKeys))
	for _, key := range hexKeys {
		raw, err := hex.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("decode segment signer key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("segment signer key length=%d want %d", len(raw), ed25519.PublicKeySize)
		}
		pubs = append(pubs, ed25519.PublicKey(raw))
	}
	return pubs, nil
}

func legacyTranscriptRootFromEntries(entries []recorder.Entry) (receipt.TranscriptRoot, int, string, bool, error) {
	var root receipt.TranscriptRoot
	rootIndex := -1
	var rootSessionID string
	found := false
	for index, entry := range entries {
		if entry.Type != "transcript_root" {
			continue
		}
		data := entry.RawDetail
		if len(data) == 0 {
			var err error
			data, err = json.Marshal(entry.Detail)
			if err != nil {
				return receipt.TranscriptRoot{}, -1, "", false, fmt.Errorf("marshal transcript_root detail: %w", err)
			}
		}
		if err := json.Unmarshal(data, &root); err != nil {
			return receipt.TranscriptRoot{}, -1, "", false, fmt.Errorf("parse transcript_root detail: %w", err)
		}
		rootIndex = index
		rootSessionID = entry.SessionID
		found = true
	}
	return root, rootIndex, rootSessionID, found, nil
}

func legacyReceiptEntriesBefore(entries []recorder.Entry, index int) int {
	count := 0
	for _, entry := range entries[:index] {
		if entry.Type == "action_receipt" {
			count++
		}
	}
	return count
}

// legacyFirstUnsealedEntryAfter returns the first entry after the transcript_root
// seal that the seal does not account for. The recorder writes exactly one
// checkpoint after the root on clean shutdown (either the threshold
// checkpoint the root itself triggers or the final one Close writes, never
// both), so a sealed recorder may carry at most one entry past the seal and
// it must be a checkpoint. Anything else there is evidence the seal never
// committed to, and the file is incomplete.
func legacyFirstUnsealedEntryAfter(entries []recorder.Entry, index int) (recorder.Entry, bool) {
	tail := entries[index+1:]
	if len(tail) == 0 {
		return recorder.Entry{}, false
	}
	if tail[0].Type != "checkpoint" {
		return tail[0], true
	}
	if len(tail) > 1 {
		return tail[1], true
	}
	return recorder.Entry{}, false
}

func legacyReceiptWindow(receipts []receipt.Receipt) (time.Time, time.Time) {
	if len(receipts) == 0 {
		return time.Time{}, time.Time{}
	}
	start := receipts[0].ActionRecord.Timestamp
	end := receipts[0].ActionRecord.Timestamp
	for _, r := range receipts[1:] {
		ts := r.ActionRecord.Timestamp
		if ts.Before(start) {
			start = ts
		}
		if ts.After(end) {
			end = ts
		}
	}
	return start, end
}

func legacyReceiptPostureBinding(receipts []receipt.Receipt) receiptPostureBindingInfo {
	for _, r := range receipts {
		if r.ActionRecord.SessionControl != nil && r.ActionRecord.SessionControl.Open != nil {
			open := r.ActionRecord.SessionControl.Open
			return receiptPostureBindingInfo{
				containedUID:         open.ContainedUID,
				postureCapsuleSHA256: open.PostureCapsuleSHA256,
				postureSignerKeyID:   open.PostureSignerKeyID,
			}
		}
	}
	return receiptPostureBindingInfo{}
}
