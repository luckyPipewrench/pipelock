// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

type ReceiptGroupVerdict string

const (
	GroupValid      ReceiptGroupVerdict = "GROUP_VALID"
	GroupIncomplete ReceiptGroupVerdict = "GROUP_INCOMPLETE"
	GroupInvalid    ReceiptGroupVerdict = "GROUP_INVALID"
)

// ReceiptGroupResult reports whether a whole named group, rather than one
// surviving shard, is complete. An unpinned signer cannot earn GROUP_VALID.
type ReceiptGroupResult struct {
	GroupID          string              `json:"group_id"`
	BaseSession      string              `json:"base_session,omitempty"`
	Verdict          ReceiptGroupVerdict `json:"verdict"`
	OpenManifestSHA  string              `json:"open_manifest_sha256,omitempty"`
	CloseManifestSHA string              `json:"close_manifest_sha256,omitempty"`
	ShardCount       int                 `json:"shard_count"`
	Error            string              `json:"error,omitempty"`
}

// VerifyReceiptGroup checks the exact published manifests and every claimed
// closed shard with bounded per-shard memory. It returns a verdict rather than
// making an incomplete group look like a valid single session.
func VerifyReceiptGroup(dir, groupID string, trusted []string) ReceiptGroupResult {
	result := ReceiptGroupResult{GroupID: groupID, Verdict: GroupInvalid}
	if len(trusted) == 0 {
		result.Error = "receipt group verification requires a trusted signer key"
		return result
	}
	rootInfo, aelInfo, err := receiptGroupDirectoryIdentity(dir)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	before, err := fingerprintGroupDirectory(dir)
	if err != nil {
		result.Error = fmt.Sprintf("inventory receipt group directory: %v", err)
		return result
	}
	openName, err := ReceiptGroupFileName(groupID, "open")
	if err != nil {
		result.Error = err.Error()
		return result
	}
	openBytes, err := readBoundedGroupFile(dir, openName)
	if err != nil {
		result.Error = fmt.Sprintf("read receipt group opening: %v", err)
		return result
	}
	open, err := UnmarshalReceiptGroupOpen(openBytes, trusted)
	if err != nil || open.GroupID != groupID {
		result.Error = fmt.Sprintf("invalid receipt group opening: %v", err)
		return result
	}
	result.BaseSession = open.BaseSession
	openSum := sha256.Sum256(openBytes)
	result.OpenManifestSHA = hex.EncodeToString(openSum[:])
	result.ShardCount = len(open.Shards)
	closeName, _ := ReceiptGroupFileName(groupID, "close")
	closeBytes, err := readBoundedGroupFile(dir, closeName)
	if errors.Is(err, os.ErrNotExist) {
		// An incomplete predecessor remains incomplete, but any successor
		// transition already on disk must still validate its frozen heads and
		// recovery seals. Otherwise a forged or deleted seal could hide behind
		// this early verdict.
		if err := verifyGroupSessionInventory(dir, open); err != nil {
			result.Error = err.Error()
			return result
		}
		if err := verifyGroupTransitionInventory(dir, result.OpenManifestSHA, "", trusted); err != nil {
			result.Error = err.Error()
			return result
		}
		if err := verifyGroupAELInventoryMode(dir, open, trusted, true); err != nil && !errors.Is(err, errGroupAELOpenTail) && !errors.Is(err, errGroupAELNeighborOpenTail) {
			result.Error = err.Error()
			return result
		}
		if after, err := fingerprintGroupDirectory(dir); err != nil || after != before {
			result.Error = "receipt group directory changed during verification"
			return result
		}
		endRoot, endAEL, err := receiptGroupDirectoryIdentity(dir)
		if err != nil || !os.SameFile(rootInfo, endRoot) || !os.SameFile(aelInfo, endAEL) {
			result.Error = "receipt group directory identity changed during verification"
			return result
		}
		result.Verdict = GroupIncomplete
		result.Error = "receipt group has no signed close manifest"
		return result
	}
	if err != nil {
		result.Error = fmt.Sprintf("read receipt group close: %v", err)
		return result
	}
	closed, err := UnmarshalReceiptGroupClose(closeBytes, open, result.OpenManifestSHA, trusted)
	if err != nil {
		result.Error = fmt.Sprintf("invalid receipt group close: %v", err)
		return result
	}
	closeSum := sha256.Sum256(closeBytes)
	result.CloseManifestSHA = hex.EncodeToString(closeSum[:])
	for i, claimed := range closed.Shards {
		actual, err := VerifyGroupShardHead(dir, open, result.OpenManifestSHA, i)
		if err != nil {
			result.Error = fmt.Sprintf("receipt group shard %d invalid: %v", i, err)
			return result
		}
		if claimed != actual {
			result.Error = fmt.Sprintf("receipt group shard %d head differs from signed close", i)
			return result
		}
	}
	// A successor is not valid merely because its own shards are closed. Its
	// signed predecessor binding and transition must also be present.
	if open.PreviousGroupID != "" {
		if err := verifyReceiptGroupTransition(dir, open, result.OpenManifestSHA, trusted); err != nil {
			result.Error = err.Error()
			return result
		}
	}
	if err := verifyGroupSessionInventory(dir, open); err != nil {
		result.Error = err.Error()
		return result
	}
	if err := verifyGroupTransitionInventory(dir, result.OpenManifestSHA, result.CloseManifestSHA, trusted); err != nil {
		result.Error = err.Error()
		return result
	}
	aelErr := verifyGroupAELInventory(dir, open, trusted)
	if aelErr != nil && !errors.Is(aelErr, errGroupAELOpenTail) && !errors.Is(aelErr, errGroupAELNeighborOpenTail) {
		result.Error = aelErr.Error()
		return result
	}
	for _, item := range []struct {
		name string
		want []byte
	}{{openName, openBytes}, {closeName, closeBytes}} {
		again, err := readBoundedGroupFile(dir, item.name)
		if err != nil || string(again) != string(item.want) {
			result.Error = "receipt group manifest changed during verification"
			return result
		}
	}
	predecessorIncomplete := false
	if open.PreviousGroupID != "" {
		previousClose, _ := ReceiptGroupFileName(open.PreviousGroupID, "close")
		if _, err := os.Lstat(filepath.Join(filepath.Clean(dir), previousClose)); errors.Is(err, os.ErrNotExist) {
			predecessorIncomplete = true
		} else if err != nil {
			result.Error = fmt.Sprintf("inspect predecessor group close: %v", err)
			return result
		}
	}
	after, err := fingerprintGroupDirectory(dir)
	if err != nil || after != before {
		result.Error = "receipt group directory changed during verification"
		return result
	}
	endRoot, endAEL, err := receiptGroupDirectoryIdentity(dir)
	if err != nil || !os.SameFile(rootInfo, endRoot) || !os.SameFile(aelInfo, endAEL) {
		result.Error = "receipt group directory identity changed during verification"
		return result
	}
	if errors.Is(aelErr, errGroupAELOpenTail) {
		result.Verdict = GroupIncomplete
		result.Error = aelErr.Error()
		return result
	}
	if errors.Is(aelErr, errGroupAELNeighborOpenTail) {
		result.Error = aelErr.Error()
	}
	if predecessorIncomplete {
		result.Error = "predecessor group is GROUP_INCOMPLETE: no signed close manifest"
	}
	result.Verdict = GroupValid
	return result
}

// ReceiptGroupInventoryResult summarizes a streamed directory verification.
// It deliberately contains counts instead of retaining group IDs or reports,
// so historical directories do not require memory proportional to group
// history.
type ReceiptGroupInventoryResult struct {
	Groups     uint64
	Incomplete uint64
	Invalid    uint64
}

// VerifyReceiptGroups verifies every published group in dir and calls visit
// once per group. Unknown artifacts, orphan group gates, and a changed
// directory fail the inventory. Reports are delivered as they are verified;
// callers must not present an earlier GROUP_VALID as an overall pass if this
// function returns an error or a non-valid group count.
func VerifyReceiptGroups(dir string, trusted []string, visit func(ReceiptGroupResult) error) (ReceiptGroupInventoryResult, error) {
	var summary ReceiptGroupInventoryResult
	hasGroupEvidence, err := ReceiptGroupEvidencePresent(dir, 0)
	if err != nil {
		return summary, err
	}
	if !hasGroupEvidence {
		return summary, nil
	}
	before, err := fingerprintGroupDirectory(dir)
	if err != nil {
		return summary, fmt.Errorf("inventory receipt groups: %w", err)
	}
	// Validate every artifact name and reject close/transition records that
	// have no opening. Do not accumulate IDs: a second pass verifies openings.
	err = walkInventoryNames(dir, func(name string) error {
		if !strings.HasPrefix(name, "receipt-group-") {
			return nil
		}
		if err := validateGroupArtifactFileName(name); err != nil {
			return err
		}
		if strings.HasSuffix(name, "-open.json") {
			return nil
		}
		id := name[len("receipt-group-") : len("receipt-group-")+32]
		openName, _ := ReceiptGroupFileName(id, "open")
		if _, err := os.Lstat(filepath.Join(filepath.Clean(dir), openName)); errors.Is(err, os.ErrNotExist) {
			result := ReceiptGroupResult{GroupID: id, Verdict: GroupInvalid, Error: "receipt group artifact has no opening manifest"}
			if visit != nil {
				if visitErr := visit(result); visitErr != nil {
					return visitErr
				}
			}
			summary.Groups++
			summary.Invalid++
		} else if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return summary, err
	}
	// A gated session without any matching opening is still group evidence and
	// cannot fall back to the legacy single-shard verifier.
	err = walkInventoryNames(dir, func(name string) error {
		session, start, ok := evidencename.Parse(name)
		if !ok || start != 0 {
			return nil
		}
		path := filepath.Join(filepath.Clean(dir), name)
		first, seen, firstErr := firstGroupEvidenceEntry(path)
		if firstErr != nil {
			return firstErr
		}
		if !seen {
			// Let the ordinary session verifier classify malformed or empty
			// legacy files. A gate is only recognized from a parsed first entry.
			return nil
		}
		gate, gated, gateErr := groupGateFromFirstEntry(first)
		if !gated {
			return nil
		}
		if gateErr == nil {
			openName, _ := ReceiptGroupFileName(gate.GroupID, "open")
			_, gateErr = os.Lstat(filepath.Join(filepath.Clean(dir), openName))
		}
		if gateErr == nil {
			return nil
		}
		result := ReceiptGroupResult{GroupID: gate.GroupID, Verdict: GroupInvalid, Error: fmt.Sprintf("gated session %q: %v", session, gateErr)}
		if visit != nil {
			if visitErr := visit(result); visitErr != nil {
				return visitErr
			}
		}
		summary.Groups++
		summary.Invalid++
		return nil
	})
	if err != nil {
		return summary, err
	}
	err = walkInventoryNames(dir, func(name string) error {
		if !strings.HasPrefix(name, "receipt-group-") || !strings.HasSuffix(name, "-open.json") {
			return nil
		}
		id := name[len("receipt-group-") : len("receipt-group-")+32]
		result := VerifyReceiptGroup(dir, id, trusted)
		if visit != nil {
			if visitErr := visit(result); visitErr != nil {
				return visitErr
			}
		}
		summary.Groups++
		switch result.Verdict {
		case GroupValid:
		case GroupIncomplete:
			summary.Incomplete++
		default:
			summary.Invalid++
		}
		return nil
	})
	if err != nil {
		return summary, err
	}
	after, err := fingerprintGroupDirectory(dir)
	if err != nil || after != before {
		return summary, errors.New("receipt group directory changed during verification")
	}
	return summary, nil
}

func receiptGroupDirectoryIdentity(dir string) (os.FileInfo, os.FileInfo, error) {
	root, err := os.Lstat(filepath.Clean(dir))
	if err != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("receipt group evidence path is not a real directory")
	}
	ael, err := os.Lstat(filepath.Join(filepath.Clean(dir), "ael"))
	if err != nil || !ael.IsDir() || ael.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("receipt group AEL path is not a real directory")
	}
	return root, ael, nil
}

func verifyReceiptGroupTransition(dir string, successor ReceiptGroupOpen, newHash string, trusted []string) error {
	oldName, _ := ReceiptGroupFileName(successor.PreviousGroupID, "open")
	oldBytes, err := readBoundedGroupFile(dir, oldName)
	if err != nil {
		return fmt.Errorf("receipt group predecessor opening missing: %w", err)
	}
	oldSum := sha256.Sum256(oldBytes)
	oldHash := hex.EncodeToString(oldSum[:])
	if oldHash != successor.PreviousOpenManifestSHA256 {
		return errors.New("receipt group predecessor opening digest differs")
	}
	predecessor, err := UnmarshalReceiptGroupOpen(oldBytes, trusted)
	if err != nil || predecessor.GroupID != successor.PreviousGroupID {
		return errors.New("receipt group predecessor opening invalid")
	}
	oldCloseName, _ := ReceiptGroupFileName(predecessor.GroupID, "close")
	oldCloseHash := ""
	if oldCloseBytes, err := readBoundedGroupFile(dir, oldCloseName); err == nil {
		if _, err := UnmarshalReceiptGroupClose(oldCloseBytes, predecessor, oldHash, trusted); err != nil {
			return err
		}
		digest := sha256.Sum256(oldCloseBytes)
		oldCloseHash = hex.EncodeToString(digest[:])
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	transitionName, _ := ReceiptGroupFileName(successor.GroupID, "transition")
	transitionBytes, err := readBoundedGroupFile(dir, transitionName)
	if err != nil {
		return fmt.Errorf("receipt group transition missing: %w", err)
	}
	transition, err := UnmarshalReceiptGroupTransition(transitionBytes, successor, predecessor, newHash, oldHash, oldCloseHash, trusted)
	if err != nil {
		return err
	}
	if err := verifyGroupTransitionInventoryLinks(dir, oldHash, oldCloseHash, trusted, false); err != nil {
		return err
	}
	for i, claim := range transition.Predecessors {
		if oldCloseHash != "" {
			head, err := VerifyGroupShardHead(dir, predecessor, oldHash, i)
			if err != nil || claim.ShardIndex != i || claim.SessionID != head.SessionID || claim.FinalChainSeq != head.FinalChainSeq || claim.FinalChainHash != head.FinalChainHash || claim.RecoverySealSHA256 != "" {
				return fmt.Errorf("receipt group predecessor shard %d differs from transition", i)
			}
			continue
		}
		head, err := verifyGroupShardPrefix(dir, predecessor, oldHash, i)
		if err != nil {
			return fmt.Errorf("verify receipt group incomplete predecessor shard %d: %w", i, err)
		}
		if claim.ShardIndex != i || claim.SessionID != predecessor.Shards[i].SessionID || claim.FinalChainSeq != head.seq || claim.FinalChainHash != head.hash {
			return fmt.Errorf("receipt group incomplete predecessor shard %d differs from transition", i)
		}
		if !head.torn {
			if claim.RecoverySealSHA256 != "" {
				return fmt.Errorf("receipt group predecessor shard %d claims an unnecessary recovery seal", i)
			}
			continue
		}
		if claim.RecoverySealSHA256 == "" {
			return fmt.Errorf("receipt group predecessor shard %d lacks a recovery seal", i)
		}
		sealBytes, err := readClaimBytes(filepath.Join(filepath.Clean(dir), ChainLinkFileName(claim.SessionID)))
		if err != nil {
			return fmt.Errorf("receipt group predecessor shard %d recovery seal missing: %w", i, err)
		}
		digest := sha256.Sum256(sealBytes)
		if hex.EncodeToString(digest[:]) != claim.RecoverySealSHA256 {
			return fmt.Errorf("receipt group predecessor shard %d recovery seal digest differs", i)
		}
		seal, err := UnmarshalRecoverySeal(sealBytes)
		if err != nil {
			return fmt.Errorf("decode receipt group predecessor shard %d recovery seal: %w", i, err)
		}
		if seal.PredecessorSession != claim.SessionID || seal.SuccessorSession != successor.Shards[i%len(successor.Shards)].SessionID {
			return fmt.Errorf("receipt group predecessor shard %d recovery seal binding differs", i)
		}
		if err := VerifyRecoveryBinding(dir, seal, trusted); err != nil {
			return fmt.Errorf("receipt group predecessor shard %d recovery seal invalid: %w", i, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(filepath.Clean(dir), transitionName)); err != nil {
		return errors.New("receipt group transition changed during verification")
	}
	return nil
}
