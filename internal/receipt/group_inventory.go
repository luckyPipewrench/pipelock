// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// A signed run with no recorder close or transcript root is an open tail.
// Callers may report INCOMPLETE only after every other run has been checked.
var (
	errGroupAELOpenTail         = errors.New("native AEL run has an open recorder tail")
	errGroupAELNeighborOpenTail = errors.New("predecessor or neighboring group is GROUP_INCOMPLETE: native AEL run has an open recorder tail")
)

type groupInventoryFingerprint struct {
	root, ael, aelTree                [32]byte
	rootCount, aelCount, aelTreeCount uint64
}

// groupAELMembership checks the signed session owner of each native AEL claim.
// Group IDs and counts alone cannot establish that every opened shard is present.
type groupAELMembership struct {
	groupID string
	allowed map[string]struct{}
	seen    map[string]struct{}
}

func newGroupAELMembership(open ReceiptGroupOpen) groupAELMembership {
	m := groupAELMembership{groupID: open.GroupID, allowed: make(map[string]struct{}, len(open.Shards)), seen: make(map[string]struct{}, len(open.Shards))}
	for _, shard := range open.Shards {
		m.allowed[shard.SessionID] = struct{}{}
	}
	return m
}

func (m groupAELMembership) Add(session string) error {
	if _, ok := m.allowed[session]; !ok {
		return fmt.Errorf("receipt group native AEL claim session %q is outside signed shard membership", session)
	}
	if _, duplicate := m.seen[session]; duplicate {
		return fmt.Errorf("receipt group native AEL session %q has duplicate claims", session)
	}
	m.seen[session] = struct{}{}
	return nil
}

func (m groupAELMembership) Finish(incomplete bool) error {
	if len(m.seen) > len(m.allowed) || !incomplete && len(m.seen) != len(m.allowed) {
		return fmt.Errorf("receipt group native AEL claims = %d, want %d", len(m.seen), len(m.allowed))
	}
	return nil
}

// fingerprintGroupDirectory streams directory entries in fixed batches. The
// XOR accumulator is order-independent because Readdirnames has no stable
// order; each name, mode, size, and modification time is SHA-256 separated.
// A count distinguishes an added pair that might otherwise cancel itself.
func fingerprintGroupDirectory(dir string) (groupInventoryFingerprint, error) {
	var result groupInventoryFingerprint
	var err error
	result.root, result.rootCount, err = fingerprintDirectory(dir)
	if err != nil {
		return result, err
	}
	result.ael, result.aelCount, err = fingerprintDirectory(filepath.Join(dir, "ael"))
	if err != nil {
		return result, err
	}
	err = walkInventoryNames(filepath.Join(dir, "ael"), func(run string) error {
		if !groupHex(run, 32) {
			return fmt.Errorf("invalid native AEL run directory %q", run)
		}
		runDir := filepath.Join(dir, "ael", run)
		info, err := os.Lstat(runDir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("native AEL run %q is not a real directory", run)
		}
		h := sha256.New()
		_, _ = h.Write([]byte(run))
		for _, child := range []string{"", "keys", "recorders"} {
			part, count, err := fingerprintDirectory(filepath.Join(runDir, child))
			if errors.Is(err, os.ErrNotExist) && child != "" {
				_, _ = h.Write([]byte{0xff})
				continue
			}
			if err != nil {
				return err
			}
			_, _ = h.Write(part[:])
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], count)
			_, _ = h.Write(b[:])
		}
		sum := h.Sum(nil)
		for i := range result.aelTree {
			result.aelTree[i] ^= sum[i]
		}
		result.aelTreeCount++
		return nil
	})
	return result, err
}

func fingerprintDirectory(dir string) ([32]byte, uint64, error) {
	var fingerprint [32]byte
	info, err := os.Lstat(filepath.Clean(dir))
	if err != nil {
		return fingerprint, 0, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fingerprint, 0, errors.New("receipt group inventory path is not a real directory")
	}
	f, err := recorder.OpenEvidenceDirectory(dir)
	if err != nil {
		return fingerprint, 0, err
	}
	defer func() { _ = f.Close() }()
	return fingerprintOpenedDirectory(dir, f)
}

func fingerprintOpenedDirectory(dir string, f *os.File) ([32]byte, uint64, error) {
	var fingerprint [32]byte
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fingerprint, 0, err
	}
	defer func() { _ = root.Close() }()
	pinned, err := f.Stat()
	if err != nil {
		return fingerprint, 0, err
	}
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(pinned, rootInfo) {
		return fingerprint, 0, errors.New("receipt group inventory directory changed while opening")
	}
	var count uint64
	for {
		names, readErr := f.Readdirnames(128)
		for _, name := range names {
			info, err := root.Lstat(name)
			if err != nil {
				return fingerprint, count, err
			}
			var length [8]byte
			h := sha256.New()
			binary.BigEndian.PutUint64(length[:], uint64(len(name)))
			_, _ = h.Write(length[:])
			_, _ = h.Write([]byte(name))
			_, _ = fmt.Fprintf(h, "%v|%d|%d", info.Mode(), info.Size(), info.ModTime().UnixNano())
			sum := h.Sum(nil)
			for i := range fingerprint {
				fingerprint[i] ^= sum[i]
			}
			count++
		}
		if errors.Is(readErr, io.EOF) {
			return fingerprint, count, nil
		}
		if readErr != nil {
			return fingerprint, count, readErr
		}
	}
}

func verifyGroupSessionInventory(dir string, open ReceiptGroupOpen) error {
	f, err := recorder.OpenEvidenceDirectory(dir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	for {
		names, readErr := f.Readdirnames(128)
		for _, name := range names {
			if strings.HasPrefix(name, "receipt-group-") {
				if err := validateGroupArtifactFileName(name); err != nil {
					return err
				}
			}
			session, start, ok := evidencename.Parse(name)
			if !ok || start != 0 || !groupRunSession(open.BaseSession, session) {
				continue
			}
			listed := false
			for _, shard := range open.Shards {
				if shard.SessionID == session {
					listed = true
					break
				}
			}
			if listed {
				continue
			}
			var first recorder.Entry
			seen := false
			path := filepath.Join(filepath.Clean(dir), name)
			captureFirst := func(entry recorder.Entry) error {
				if !seen {
					first, seen = entry, true
				}
				return nil
			}
			_, err := recorder.WalkEvidenceFile(path, nil, captureFirst)
			var torn *recorder.TornTailError
			if errors.As(err, &torn) {
				files, listErr := recorderFiles(dir, session)
				if listErr != nil {
					return fmt.Errorf("list unlisted receipt run %q: %w", session, listErr)
				}
				if len(files) == 0 || files[len(files)-1] != path {
					return fmt.Errorf("receipt group session has a torn segment: %s", name)
				}
				// Classification uses only a terminated first entry. Recovery
				// validates complete JSON in the final fragment but must not
				// supply that fragment to a verifier as durable evidence.
				_, err = recorder.CaptureTornEvidence(path, recorder.MaxEvidenceReadFileBytes, nil, captureFirst)
			}
			if err != nil || !seen {
				return fmt.Errorf("unlisted receipt run %q cannot be classified: %w", session, err)
			}
			gate, gated, err := groupGateFromFirstEntry(first)
			if err != nil {
				return fmt.Errorf("unlisted receipt group gate %q is invalid: %w", session, err)
			}
			if !gated {
				continue // legacy run; its own verifier still owns its validity.
			}
			if gate.GroupID == open.GroupID {
				return fmt.Errorf("receipt group has unlisted gated session %q", session)
			}
			// A gate naming a different group is classified by that group's
			// manifest. This pass concerns only the requested group.
			if !groupHex(gate.GroupID, 32) || gate.SessionID != session {
				return fmt.Errorf("unlisted receipt group gate %q has invalid identity", session)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func validateGroupArtifactFileName(name string) error {
	const prefix = "receipt-group-"
	if len(name) < len(prefix)+32+len("-open.json") {
		return fmt.Errorf("unknown receipt group artifact %q", name)
	}
	id := name[len(prefix) : len(prefix)+32]
	for _, phase := range []string{"open", "close", "transition"} {
		want, err := ReceiptGroupFileName(id, phase)
		if err == nil && name == want {
			return nil
		}
	}
	return fmt.Errorf("unknown receipt group artifact %q", name)
}

func verifyGroupTransitionInventory(dir, openHash, closeHash string, trusted []string) error {
	return verifyGroupTransitionInventoryLinks(dir, openHash, closeHash, trusted, true)
}

func verifyGroupTransitionInventoryLinks(dir, openHash, closeHash string, trusted []string, verifyLink bool) error {
	count := 0
	successorID := ""
	returnErr := walkInventoryNames(dir, func(name string) error {
		if !strings.HasPrefix(name, "receipt-group-") || !strings.HasSuffix(name, "-transition.json") {
			return nil
		}
		if err := validateGroupArtifactFileName(name); err != nil {
			return err
		}
		raw, err := readBoundedGroupFile(dir, name)
		if err != nil {
			return err
		}
		tr, err := strictGroupArtifact[ReceiptGroupTransition](raw)
		if err != nil {
			return err
		}
		if tr.NewGroupID != name[len("receipt-group-"):len("receipt-group-")+32] {
			return errors.New("receipt group transition file identity differs")
		}
		sig := tr.Signature
		tr.Signature = ""
		checkKeys := trusted
		if tr.PreviousOpenManifestSHA256 != openHash {
			checkKeys = []string{tr.SignerKey}
		}
		if err := verifyGroupArtifact(groupTransitionDomain, tr, sig, tr.SignerKey, checkKeys); err != nil {
			return err
		}
		if tr.PreviousOpenManifestSHA256 != openHash {
			return nil
		}
		count++
		if count > 1 {
			return errors.New("multiple successor transitions name one receipt group")
		}
		if tr.PreviousCloseManifestSHA256 != closeHash {
			return errors.New("successor transition froze a different receipt group close state")
		}
		successorID = tr.NewGroupID
		return nil
	})
	if returnErr != nil || successorID == "" || !verifyLink {
		return returnErr
	}
	newName, _ := ReceiptGroupFileName(successorID, "open")
	newRaw, err := readBoundedGroupFile(dir, newName)
	if err != nil {
		return fmt.Errorf("receipt group successor opening missing: %w", err)
	}
	newOpen, err := UnmarshalReceiptGroupOpen(newRaw, trusted)
	if err != nil {
		return err
	}
	newDigest := sha256.Sum256(newRaw)
	return verifyReceiptGroupTransition(dir, newOpen, hex.EncodeToString(newDigest[:]), trusted)
}

func groupGateFromFirstEntry(entry recorder.Entry) (ReceiptGroupBinding, bool, error) {
	if entry.Type != recorder.GroupGateEntryType {
		return ReceiptGroupBinding{}, false, nil
	}
	var gate ReceiptGroupBinding
	if err := decodeGroupEntryDetail(entry.Detail, &gate); err != nil {
		return ReceiptGroupBinding{}, true, err
	}
	if gate.GroupID == "" {
		return ReceiptGroupBinding{}, true, errors.New("empty group gate ID")
	}
	return gate, true, nil
}

func walkInventoryNames(dir string, visit func(string) error) error {
	f, err := recorder.OpenEvidenceDirectory(dir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	for {
		names, readErr := f.Readdirnames(128)
		for _, name := range names {
			if err := visit(name); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

// ReceiptGroupEvidencePresent streams the directory to find either a group
// artifact or a signed group gate. A missing manifest cannot make a grouped
// shard look like ordinary single-session evidence. A positive maxEntries
// applies the same fail-closed directory bound used by read-only views.
func ReceiptGroupEvidencePresent(dir string, maxEntries int) (bool, error) {
	found := errors.New("receipt group evidence found")
	count := 0
	err := walkInventoryNames(dir, func(name string) error {
		count++
		if maxEntries > 0 && count > maxEntries {
			return fmt.Errorf("%w: evidence directory exceeds %d entries", recorder.ErrEvidenceReadLimitExceeded, maxEntries)
		}
		if strings.HasPrefix(name, "receipt-group-") {
			return found
		}
		_, start, ok := evidencename.Parse(name)
		if !ok || start != 0 {
			return nil
		}
		first, seen, firstErr := firstGroupEvidenceEntry(filepath.Join(filepath.Clean(dir), name))
		if firstErr != nil {
			return firstErr
		}
		// Malformed legacy evidence belongs to the caller's existing damage
		// report. This inventory check only identifies a readable group gate.
		if !seen {
			return nil
		}
		_, gated, gateErr := groupGateFromFirstEntry(first)
		if gated || gateErr != nil {
			return found
		}
		return nil
	})
	if errors.Is(err, found) {
		return true, nil
	}
	return false, err
}

// firstGroupEvidenceEntry reads a complete first line even when the final
// write in the same shard is torn. A normal walk checks the tail before it
// invokes the visitor, so a torn tail needs the validated complete prefix.
func firstGroupEvidenceEntry(path string) (recorder.Entry, bool, error) {
	var first recorder.Entry
	seen := false
	stop := errors.New("captured first recorder entry")
	_, err := recorder.WalkEvidenceFile(path, nil, func(entry recorder.Entry) error {
		first, seen = entry, true
		return stop
	})
	if errors.Is(err, stop) {
		return first, true, nil
	}
	var torn *recorder.TornTailError
	if errors.As(err, &torn) {
		_, err = recorder.CaptureTornEvidence(path, recorder.MaxEvidenceReadFileBytes, nil, func(entry recorder.Entry) error {
			if !seen {
				first, seen = entry, true
			}
			return nil
		})
		return first, seen, err
	}
	// Other malformed legacy evidence is classified by its normal verifier.
	return first, seen, nil
}

type groupBatchTorn struct {
	session string
	groupID string
	err     error
}

func indexAELClaimsForSession(dir, session, currentGroupID, predecessorGroupID string, trusted []string, addClaim func(run, session, groupID, signer string, completed bool) error) error {
	return indexAELClaimsForSessionBatch(dir, session, currentGroupID, predecessorGroupID, trusted, addClaim, nil)
}

func indexAELClaimsForSessionBatch(dir, session, currentGroupID, predecessorGroupID string, trusted []string, addClaim func(run, session, groupID, signer string, completed bool) error, onTorn func(groupBatchTorn)) error {
	var whole *WholeRecorderWalker
	v1 := NewChainWalker(trusted)
	var run, signer string
	completed := false
	signedOpenSeen := false
	var gate ReceiptGroupBinding
	groupID := ""
	first := true
	var err error
	err = recorder.WalkSessionEntries(dir, session, func(entry recorder.Entry) error {
		if entry.Type == transcriptRootEntryType {
			completed = true
		}
		if first {
			first = false
			var gated bool
			gate, gated, err = groupGateFromFirstEntry(entry)
			if err != nil {
				return err
			}
			if gated {
				groupID = gate.GroupID
				if err := verifyInventoryGate(dir, session, gate, trusted); err != nil {
					return err
				}
				whole = NewGroupRecorderWalker()
			} else {
				whole = new(WholeRecorderWalker)
			}
		}
		r, ok := whole.Add(entry)
		if err := whole.Err(); err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if groupID != "" && r.SignerKey != gate.SignerKey {
			return errors.New("group receipt signer differs from opening signer")
		}
		v1.Add(r)
		control := r.ActionRecord.SessionControl
		if control != nil && control.Kind == SessionControlClose {
			completed = true
		}
		if control == nil || control.Kind != SessionControlOpen || control.Open == nil {
			return nil
		}
		if groupID == "" && control.Open.GroupBinding != nil || groupID != "" && (control.Open.GroupBinding == nil || *control.Open.GroupBinding != gate) {
			return errors.New("signed session open disagrees with recorder group gate")
		}
		if signedOpenSeen {
			return errors.New("receipt session has multiple signed native AEL openings")
		}
		signedOpenSeen = true
		run = control.Open.RunNonce
		// Receipts predating native AEL have no run nonce. They make no AEL
		// claim; a group shard still requires a native run.
		if run == "" && groupID == "" {
			return nil
		}
		if !groupHex(run, 32) {
			return errors.New("signed session open has invalid native AEL run nonce")
		}
		signer = r.SignerKey
		return nil
	})
	var torn *recorder.TornTailError
	allowBatchTorn := onTorn != nil && groupID != ""
	if err != nil && ((groupID != predecessorGroupID && groupID != currentGroupID && groupID != "" && !allowBatchTorn) || !errors.As(err, &torn)) {
		return fmt.Errorf("inventory receipt session %q: %w", session, err)
	}
	if err != nil && allowBatchTorn {
		onTorn(groupBatchTorn{session: session, groupID: groupID, err: fmt.Errorf("inventory receipt session %q: %w", session, err)})
	}
	if first || whole.Err() != nil {
		return fmt.Errorf("inventory receipt session %q is empty or invalid", session)
	}
	if result := v1.Result(); !result.Valid {
		return fmt.Errorf("inventory receipt session %q chain invalid: %s", session, result.Error)
	}
	if run != "" {
		if err := addClaim(run, session, groupID, signer, completed); err != nil {
			return fmt.Errorf("duplicate signed native AEL run %q: %w", run, err)
		}
	}
	return nil
}

func verifyInventoryGate(dir, session string, gate ReceiptGroupBinding, trusted []string) error {
	name, err := ReceiptGroupFileName(gate.GroupID, "open")
	if err != nil {
		return err
	}
	raw, err := readBoundedGroupFile(dir, name)
	if err != nil {
		return err
	}
	open, err := UnmarshalReceiptGroupOpen(raw, trusted)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != gate.OpenManifestSHA256 || gate.ShardIndex < 0 || gate.ShardIndex >= len(open.Shards) || open.Shards[gate.ShardIndex].SessionID != session || gate != groupBinding(open, gate.OpenManifestSHA256, gate.ShardIndex) {
		return errors.New("receipt group gate is not owned by a signed opening")
	}
	return nil
}
