// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// SessionID identifies the immutable recorder session owned by this emitter.
func (e *Emitter) SessionID() string {
	if e == nil {
		return ""
	}
	return e.session
}

func (e *Emitter) observeTornTail(err error) {
	var torn *recorder.TornTailError
	if e == nil || !errors.As(err, &torn) {
		return
	}
	if sink, ok := e.metrics.(interface{ RecordEvidenceTornTail(string, int64) }); ok {
		sink.RecordEvidenceTornTail(torn.Path, torn.Offset)
	}
}

// CheckSessionTail refuses to adopt a damaged current session. Before reporting
// a torn write, it validates the complete prefix and any valid final JSON record:
// a bad signature or broken link must not be hidden by an incomplete write.
func CheckSessionTail(rec *recorder.Recorder, session string, signerKeys []string) error {
	if rec == nil || rec.IsNop() {
		return nil
	}
	return rec.InspectSession(session, func() error { return checkSessionTailLocked(rec, session, signerKeys) })
}

func checkSessionTailLocked(rec *recorder.Recorder, session string, signerKeys []string) error {
	files, err := recorderFiles(rec.Dir(), session)
	if err != nil {
		return err
	}
	var previous *recorder.Entry
	var priorReceipt *Receipt
	var priorV2 *contractreceipt.EvidenceReceipt
	for i, file := range files {
		err := recorder.ValidateEvidenceFile(file, func(next recorder.Entry) error {
			if err := validateTailEntry(next, session, signerKeys); err != nil {
				return err
			}
			if previous != nil && (next.Sequence != previous.Sequence+1 || next.PrevHash != previous.Hash) {
				return fmt.Errorf("recorder hash link mismatch at seq %d", next.Sequence)
			}
			previous = &next
			if next.Type == recorderEntryType {
				r, err := receiptFromEntry(next)
				if err != nil {
					return err
				}
				if priorReceipt != nil {
					hash, err := ReceiptHash(*priorReceipt)
					if err != nil {
						return err
					}
					if r.ActionRecord.ChainPrevHash != hash {
						return errors.New("receipt hash link mismatch before torn tail")
					}
					if r.ActionRecord.KeyTransition == nil && r.ActionRecord.ChainSeq != priorReceipt.ActionRecord.ChainSeq+1 {
						return errors.New("receipt sequence mismatch before torn tail")
					}
				}
				priorReceipt = r
			}
			if next.Type == "evidence_receipt" {
				raw, err := receiptBytesFromEntry(next)
				if err != nil {
					return err
				}
				var r contractreceipt.EvidenceReceipt
				if err := json.Unmarshal(raw, &r); err != nil {
					return err
				}
				if priorV2 != nil {
					hash, err := contractreceipt.ReceiptHash(*priorV2)
					if err != nil {
						return err
					}
					if r.ChainPrevHash != hash || r.ChainSeq != priorV2.ChainSeq+1 {
						return errors.New("v2 receipt chain mismatch before torn tail")
					}
				}
				priorV2 = &r
			}
			return nil
		})
		if err != nil {
			if i+1 < len(files) && errors.Is(err, recorder.ErrTornTail) {
				return fmt.Errorf("receipt group session has a torn segment: %s", filepath.Base(file))
			}
			return fmt.Errorf("validating evidence file %s: %w", file, err)
		}
	}
	return nil
}

func validateTailEntry(entry recorder.Entry, session string, signerKeys []string) error {
	if entry.SessionID != session || entry.Hash == "" || recorder.ComputeHash(entry) != entry.Hash {
		return fmt.Errorf("invalid recorder tail in session %q at seq %d", session, entry.Sequence)
	}
	return ValidateEvidenceEntry(entry, signerKeys)
}

// ValidateEvidenceEntry checks embedded receipt signatures before classifying
// an incomplete write. Nil signerKeys permits structural-only inspection;
// live recovery supplies the keys held by the process.
func ValidateEvidenceEntry(entry recorder.Entry, signerKeys []string) error {
	if entry.Type == "evidence_receipt" {
		raw, err := receiptBytesFromEntry(entry)
		if err != nil {
			return err
		}
		var r contractreceipt.EvidenceReceipt
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		keyID := r.Signature.SignerKeyID
		if signerKeys != nil && !slices.Contains(signerKeys, keyID) {
			return errors.New("tail receipt signer was not held by this process")
		}
		key, err := hex.DecodeString(keyID)
		if err != nil {
			return err
		}
		return contractreceipt.VerifyWithKey(r, ed25519.PublicKey(key), keyID)
	}
	if entry.Type != recorderEntryType {
		return nil
	}
	r, err := receiptFromEntry(entry)
	if err != nil {
		return err
	}
	if err := VerifyInternalConsistencyOnly(*r); err != nil {
		return fmt.Errorf("tail receipt signature invalid: %w", err)
	}
	if signerKeys != nil && !slices.Contains(signerKeys, r.SignerKey) {
		return errors.New("tail receipt signer was not held by this process")
	}
	return nil
}
