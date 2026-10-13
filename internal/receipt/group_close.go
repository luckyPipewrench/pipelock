// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type verifiedGroupFile struct {
	info   os.FileInfo
	digest [sha256.Size]byte
}

// groupCloseVerifier authenticates each sealed segment once while the recorder
// retains group ownership. Close re-reads every byte without re-decoding
// verified records.
// Digests and file identities bind the retained verifier state to disk, so
// even same-size edits of an earlier segment refuse the signed group close.
type groupCloseVerifier struct {
	chain  *groupShardVerifier
	files  map[string]verifiedGroupFile
	native *ael.RunVerifier
	err    error
}

func (v *groupCloseVerifier) seal(dir, path string) error {
	if v.err != nil {
		return v.err
	}
	v.err = v.verifySegment(dir, path)
	return v.err
}

func (v *groupCloseVerifier) verifySegment(dir, path string) error {
	name := filepath.Base(path)
	if _, exists := v.files[name]; exists {
		return errors.New("receipt group segment was already sealed")
	}
	digest := sha256.New()
	info, err := recorder.WalkEvidenceFile(path, digest, v.chain.add)
	if err != nil {
		return fmt.Errorf("verify receipt group segment: %w", err)
	}
	var sum [sha256.Size]byte
	copy(sum[:], digest.Sum(nil))
	v.files[name] = verifiedGroupFile{info: info, digest: sum}
	if v.chain.opened {
		if v.native == nil {
			v.native, err = ael.NewRunVerifier(dir, v.chain.run, v.chain.open.SignerKey)
			if err != nil {
				return err
			}
		}
		if _, err := v.native.Advance(false); err != nil {
			return err
		}
	}
	return nil
}

func (v *groupCloseVerifier) head(dir string) (ReceiptGroupShardHead, error) {
	if v.err != nil {
		return ReceiptGroupShardHead{}, v.err
	}
	head, err := v.chain.head()
	if err != nil {
		return ReceiptGroupShardHead{}, err
	}
	location, err := recorder.ResolveEvidenceLocation(dir, "")
	if err != nil {
		return ReceiptGroupShardHead{}, err
	}
	seen := 0
	err = recorder.WalkSessionHistoryFiles(location, v.chain.shard.SessionID, func(shard recorder.SessionHistoryShard, input io.Reader) error {
		if err := v.checkFile(shard, input); err != nil {
			return err
		}
		seen++
		return nil
	})
	if err != nil {
		return ReceiptGroupShardHead{}, err
	}
	if seen != len(v.files) {
		return ReceiptGroupShardHead{}, errors.New("receipt group verified segment is missing")
	}
	if v.native == nil {
		return ReceiptGroupShardHead{}, errors.New("receipt group native AEL verifier is missing")
	}
	native, err := v.native.Advance(true)
	if err != nil {
		return ReceiptGroupShardHead{}, err
	}
	if err := v.native.VerifyUnchanged(); err != nil {
		return ReceiptGroupShardHead{}, err
	}
	head.NativeAELFinalSeq, head.NativeAELFinalHash, head.NativeAELRecordCount = native.FinalSeq, native.FinalHash, native.RecordCount
	return head, nil
}

func (v *groupCloseVerifier) checkFile(shard recorder.SessionHistoryShard, input io.Reader) error {
	expected, ok := v.files[shard.Name]
	if !ok || shard.Info == nil || !os.SameFile(expected.info, shard.Info) {
		return errors.New("receipt group segment was added or replaced after verification")
	}
	digest := sha256.New()
	n, err := io.Copy(digest, input)
	if err != nil {
		return fmt.Errorf("hash verified receipt group segment: %w", err)
	}
	var sum [sha256.Size]byte
	copy(sum[:], digest.Sum(nil))
	if n != expected.info.Size() || sum != expected.digest {
		return errors.New("receipt group segment bytes changed after verification")
	}

	return nil
}
