// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// groupPrefixHead is the last verified receipt of an unclosed predecessor.
// A torn tail remains damage, even when its complete prefix is signed.
type groupPrefixHead struct {
	seq  uint64
	hash string
	torn bool
}

func verifyGroupShardPrefix(dir string, open ReceiptGroupOpen, openHash string, index int) (groupPrefixHead, error) {
	if index < 0 || index >= len(open.Shards) {
		return groupPrefixHead{}, errors.New("receipt group prefix shard index is outside membership")
	}
	session := open.Shards[index].SessionID
	gone, err := recorder.EvidenceRunWriterGone(dir, session)
	if err != nil {
		return groupPrefixHead{}, fmt.Errorf("probe receipt group predecessor writer: %w", err)
	}
	if !gone {
		return groupPrefixHead{}, errors.New("receipt group predecessor writer still present")
	}
	binding := groupBinding(open, openHash, index)
	v, err := newRecoveryPrefixVerifier(session, []string{open.SignerKey}, false)
	if err != nil {
		return groupPrefixHead{}, err
	}
	v.groupBinding = &binding
	var head groupPrefixHead
	if err := recorder.WalkSessionHistory(dir, session, v.add); err == nil {
		if err := v.finish(); err != nil {
			return groupPrefixHead{}, err
		}
		head = groupPrefixHead{seq: v.lastReceiptSeq, hash: v.lastReceiptHash}
	} else {
		// Only a proven torn final shard may bypass the complete-line walker.
		// The observer independently replays the signed prefix and checks the same
		// gate and opening binding. Any other walk failure remains an error.
		observed, err := observeRecoveryWithOptions(dir, session, open.SignerKey, recoveryObservationOptions{
			trusted: []string{open.SignerKey}, groupBinding: &binding,
		})
		if err != nil {
			return groupPrefixHead{}, fmt.Errorf("verify receipt group predecessor prefix: %w", err)
		}
		head = groupPrefixHead{seq: observed.PredecessorTailSeq, hash: observed.PredecessorTailHash, torn: true}
	}
	if err := verifyGroupPrefixAEL(dir, session, open); err != nil {
		return groupPrefixHead{}, fmt.Errorf("verify receipt group predecessor native AEL: %w", err)
	}
	return head, nil
}

func verifyGroupPrefixAEL(dir, session string, open ReceiptGroupOpen) error {
	var run string
	var completed bool
	err := indexAELClaimsForSession(dir, session, open.GroupID, open.PreviousGroupID, []string{open.SignerKey}, func(claim, owner, groupID, signer string, closed bool) error {
		if owner != session || groupID != open.GroupID || signer != open.SignerKey {
			return errors.New("predecessor native AEL owner differs from signed group opening")
		}
		run, completed = claim, closed
		return nil
	})
	if err != nil {
		return err
	}
	if run == "" {
		return errors.New("predecessor has no signed native AEL run")
	}
	info, err := os.Lstat(filepath.Join(filepath.Clean(dir), "ael", run))
	if err != nil || !info.IsDir() {
		return fmt.Errorf("predecessor native AEL run %q is missing or not a real directory", run)
	}
	if completed {
		if _, err := ael.VerifyRun(dir, run, open.SignerKey); err != nil {
			return fmt.Errorf("predecessor native AEL run %q invalid: %w", run, err)
		}
	} else if _, err := ael.VerifyPresentRun(dir, run, open.SignerKey); err != nil {
		return fmt.Errorf("predecessor native AEL run %q invalid: %w", run, err)
	}
	return nil
}
