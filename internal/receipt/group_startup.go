// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

type startupShardProof struct {
	session    *startupSessionVerification
	head       ReceiptGroupShardHead
	prefix     groupPrefixHead
	err        error
	prefixMode bool
	openHash   string
}

// startupGroupVerification is a ceremony, never a persistent cache. Only the
// terminal and required transition memberships have retained shard proofs;
// historical neighbor claims remain streamed through the existing disk index.
type startupGroupVerification struct {
	owner         os.FileInfo
	manifests     map[string][]byte
	newSeals      map[string]string
	dir           string
	trusted       []string
	options       verification.Options
	proofs        map[string]*startupShardProof
	transitions   map[string]bool
	before        groupInventoryFingerprint
	root, aelRoot os.FileInfo
	inputs        startupInputFingerprint
	successor     *ReceiptShardSet
}

func newStartupGroupVerification(dir string, trusted []string, options verification.Options) (*startupGroupVerification, error) {
	if err := options.Check(); err != nil {
		return nil, err
	}
	root, aelRoot, err := receiptGroupDirectoryIdentity(dir)
	if err != nil {
		return nil, err
	}
	before, err := fingerprintGroupDirectory(dir)
	if err != nil {
		return nil, err
	}
	owner, ownerErr := os.Lstat(filepath.Join(dir, recorder.GroupOwnerLockFileName))
	if ownerErr != nil && !errors.Is(ownerErr, os.ErrNotExist) {
		return nil, ownerErr
	}
	inputs, err := fingerprintStartupInputs(dir, nil)
	if err != nil {
		return nil, err
	}
	return &startupGroupVerification{
		owner: owner, dir: dir, trusted: append([]string(nil), trusted...), options: options,
		manifests: make(map[string][]byte), newSeals: make(map[string]string), proofs: make(map[string]*startupShardProof), transitions: make(map[string]bool), before: before, root: root, aelRoot: aelRoot, inputs: inputs,
	}, nil
}

func (c *startupGroupVerification) check() error {
	for name, want := range c.newSeals {
		raw, err := readClaimBytes(filepath.Join(c.dir, name))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != want {
			return fmt.Errorf("%w: recovery seal changed before successor transition", recorder.ErrEvidenceChanged)
		}
	}
	if err := c.options.Check(); err != nil {
		return err
	}
	root, aelRoot, err := receiptGroupDirectoryIdentity(c.dir)
	if err != nil || !os.SameFile(root, c.root) || !os.SameFile(aelRoot, c.aelRoot) {
		return fmt.Errorf("%w: receipt group directory identity changed during verification", recorder.ErrEvidenceChanged)
	}
	if c.successor == nil {
		after, err := fingerprintGroupDirectory(c.dir)
		if err != nil || after != c.before {
			return fmt.Errorf("%w: receipt group directory changed during verification", recorder.ErrEvidenceChanged)
		}
	} else {
		if c.owner != nil {
			current, err := os.Lstat(filepath.Join(c.dir, recorder.GroupOwnerLockFileName))
			if err != nil || !os.SameFile(current, c.owner) || current.Size() != c.owner.Size() || !current.Mode().IsRegular() {
				return fmt.Errorf("%w: receipt group ownership file identity changed", recorder.ErrEvidenceChanged)
			}
		}
		after, err := fingerprintStartupInputs(c.dir, c.successor)
		if err != nil || after != c.inputs {
			return fmt.Errorf("%w: receipt group consumed inputs changed before successor transition", recorder.ErrEvidenceChanged)
		}
	}
	return nil
}

func (c *startupGroupVerification) shard(open ReceiptGroupOpen, hash string, index int, prefix bool) *startupShardProof {
	c.prepareShards(open, hash, prefix)
	session := open.Shards[index].SessionID
	if prior := c.proofs[session]; prior != nil {
		if prior.openHash != hash || prior.prefixMode != prefix {
			return &startupShardProof{err: errors.New("startup shard proof binding differs")}
		}
		return prior
	}
	return &startupShardProof{err: errors.New("startup shard proof unavailable")}
}

// prepareShards assigns walkers to independent shard workers. Membership is
// signed by the group opening; GOMAXPROCS is the runtime's CPU budget. No
// worker mutates the context maps or SQLite. Join every worker before any
// result is consumed, including on failure or cancellation.
func (c *startupGroupVerification) prepareShards(open ReceiptGroupOpen, hash string, prefix bool) {
	var pending []int
	for i, shard := range open.Shards {
		if c.proofs[shard.SessionID] != nil {
			continue
		}
		s := newStartupSessionVerification(c.dir, open, shard.SessionID, c.trusted, c.options)
		p := &startupShardProof{session: s, prefixMode: prefix, openHash: hash}
		c.proofs[shard.SessionID] = p
		if prefix {
			gone, err := recorder.EvidenceRunWriterGone(c.dir, shard.SessionID)
			if err != nil {
				p.err = fmt.Errorf("probe receipt group predecessor writer: %w", err)
				continue
			}
			if !gone {
				p.err = errors.New("receipt group predecessor writer still present")
				continue
			}
			s.writerGone = true
		}
		pending = append(pending, i)
	}
	workers := min(len(pending), runtime.GOMAXPROCS(0))
	jobs := make(chan int)
	var joined sync.WaitGroup
	for range workers {
		joined.Go(func() {
			for i := range jobs {
				p := c.proofs[open.Shards[i].SessionID]
				if prefix {
					p.prefix, p.err = verifyGroupShardPrefixWithSession(c.dir, open, hash, i, p.session)
				} else {
					p.head, p.err = verifyGroupShardHeadWithSession(c.dir, open, hash, i, p.session)
				}
			}
		})
	}
	for _, i := range pending {
		jobs <- i
	}
	close(jobs)
	joined.Wait()
}

func verifyGroupShardHeadUsing(dir string, open ReceiptGroupOpen, hash string, index int, c *startupGroupVerification) (ReceiptGroupShardHead, error) {
	if c == nil {
		return VerifyGroupShardHead(dir, open, hash, index)
	}
	if err := c.options.Check(); err != nil {
		return ReceiptGroupShardHead{}, err
	}
	p := c.shard(open, hash, index, false)
	return p.head, p.err
}

func verifyGroupShardPrefixUsing(dir string, open ReceiptGroupOpen, hash string, index int, c *startupGroupVerification) (groupPrefixHead, error) {
	if c == nil {
		return verifyGroupShardPrefix(dir, open, hash, index)
	}
	if err := c.options.Check(); err != nil {
		return groupPrefixHead{}, err
	}
	p := c.shard(open, hash, index, true)
	// A previously absent writer is not authority for a later publication.
	gone, err := recorder.EvidenceRunWriterGone(dir, open.Shards[index].SessionID)
	if err != nil {
		return groupPrefixHead{}, fmt.Errorf("probe receipt group predecessor writer: %w", err)
	}
	if !gone {
		return groupPrefixHead{}, errors.New("receipt group predecessor writer still present")
	}
	return p.prefix, p.err
}

func verifyGroupAELUsing(dir string, open ReceiptGroupOpen, trusted []string, incomplete bool, index groupAELBatchIndex, c *startupGroupVerification) error {
	if c == nil {
		return verifyGroupAELWithIndex(dir, open, trusted, incomplete, index)
	}
	return verifyGroupAELInventoryWithContext(dir, open, trusted, incomplete, c)
}

func (c *startupGroupVerification) indexSession(open ReceiptGroupOpen, incomplete bool, session string, add func(string, string, string, string, bool) error) error {
	p := c.proofs[session]
	if p == nil && incomplete {
		for i, shard := range open.Shards {
			if shard.SessionID == session {
				name, _ := ReceiptGroupFileName(open.GroupID, "open")
				raw, err := readBoundedGroupFile(c.dir, name)
				if err != nil {
					return err
				}
				sum := sha256.Sum256(raw)
				p = c.shard(open, hex.EncodeToString(sum[:]), i, true)
				break
			}
		}
	}
	if p != nil && p.session != nil && p.session.seen {
		if p.session.inventoryErr != nil {
			return p.session.inventoryErr
		}
		claim := p.session.claim
		if claim.run != "" {
			return add(claim.run, claim.session, claim.groupID, claim.signer, claim.completed)
		}
		return nil
	}
	current := ""
	if incomplete {
		current = open.GroupID
	}
	return indexAELClaimsForSessionWithWalk(c.dir, session, current, open.PreviousGroupID, c.trusted, add, nil, nil, func(visit func(recorder.Entry) error) error {
		return recorder.WalkSessionHistoryWithOptions(c.dir, session, c.options, func(e recorder.Entry) error {
			if err := visit(e); err != nil {
				return err
			}
			return c.options.Report(verification.Progress{Kind: "recorder_record", Session: session, Records: 1})
		})
	})
}

func (c *startupGroupVerification) verifyAEL(run, signer string, completed bool) (ael.VerifiedHead, error) {
	for _, p := range c.proofs {
		if p.session != nil && p.session.claim.run == run {
			return p.session.verifyAEL(run, signer, completed)
		}
	}
	return ael.VerifyRunWithOptions(c.dir, run, signer, completed, c.options)
}

// The inventory includes the same file identity, change time, size, mode and
// modification time contract as fingerprintGroupDirectory. During publication
// only this ceremony's generated successor artifacts are excluded. Their names
// come from the signed membership, emitter run nonces and lifecycle publisher;
// no older input is excluded. Parent directory identity is checked separately.
type startupInputFingerprint struct {
	sum   [32]byte
	count uint64
}

func fingerprintStartupInputs(dir string, successor *ReceiptShardSet) (startupInputFingerprint, error) {
	var out startupInputFingerprint
	sessions := make(map[string]bool)
	runs := make(map[string]bool)
	generated := make(map[string]bool)
	if successor != nil {
		name, _ := ReceiptGroupFileName(successor.open.GroupID, "open")
		generated[name] = true
		for i, shard := range successor.open.Shards {
			sessions[shard.SessionID] = true
			generated["writer-"+shard.SessionID+".lock"] = true
			if successor.emitters[i] != nil {
				runs[successor.emitters[i].runNonce] = true
			}
		}
		if successor.previous != nil && successor.previous.ceremony != nil {
			for name := range successor.previous.ceremony.newSeals {
				generated[name] = true
			}
		}
	}
	add := func(path, name string, info os.FileInfo) error {
		identity, err := recorder.EvidenceMetadataIdentity(path, info)
		if err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s|%s|%v|%d|%d", len(name), name, identity, info.Mode(), info.Size(), info.ModTime().UnixNano())))
		for i := range out.sum {
			out.sum[i] ^= sum[i]
		}
		out.count++
		return nil
	}
	if err := walkInventoryNames(dir, func(name string) error {
		if name == "ael" || name == recorder.GroupOwnerLockFileName || generated[name] {
			return nil
		}
		if session, _, ok := evidencename.Parse(name); ok && sessions[session] {
			return nil
		}
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		return add(filepath.Join(dir, name), name, info)
	}); err != nil {
		return out, err
	}
	err := walkInventoryNames(filepath.Join(dir, "ael"), func(run string) error {
		if runs[run] {
			return nil
		}
		if !groupHex(run, 32) {
			return errors.New("invalid native AEL run directory")
		}
		root := filepath.Join(dir, "ael", run)
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("native AEL run is not a real directory")
		}
		if err := add(root, "ael/"+run, info); err != nil {
			return err
		}
		for _, child := range []string{"", "keys", "recorders"} {
			childDir := filepath.Join(root, child)
			if err := walkInventoryNames(childDir, func(name string) error {
				path := filepath.Join(childDir, name)
				info, err := os.Lstat(path)
				if err != nil {
					return err
				}
				return add(path, strings.Join([]string{"ael", run, child, name}, "/"), info)
			}); err != nil {
				if errors.Is(err, os.ErrNotExist) && child != "" {
					continue
				}
				return err
			}
		}
		return nil
	})
	return out, err
}

func verifyRecoveryBindingUsing(dir string, seal RecoverySeal, trusted []string, c *startupGroupVerification) error {
	if c == nil {
		return VerifyRecoveryBinding(dir, seal, trusted)
	}
	// The recovery comparison below shares the exact torn-shard observation and
	// signed successor opening already authenticated by this ceremony.
	if err := VerifyRecoverySeal(seal); err != nil {
		return err
	}
	p := c.proofs[seal.PredecessorSession]
	if p == nil || p.session == nil || p.session.observation == nil {
		return errors.New("recovery predecessor observation unavailable")
	}
	s := p.session
	obs := s.observation
	if obs.Snapshot.Size < 0 || obs.Snapshot.Offset < 0 || obs.Snapshot.Offset > obs.Snapshot.Size {
		return errors.New("recovery predecessor observation has invalid byte boundaries")
	}
	if obs.Shard != seal.Shard || uint64(obs.Snapshot.Size) != seal.ShardSize || obs.Snapshot.SHA256 != seal.ShardSHA256 || uint64(obs.Snapshot.Offset) != seal.DamageOffset || s.durableOuterSeq != seal.LastGoodSeq || s.durableOuterHash != seal.LastGoodHash || s.durableSeq != seal.PredecessorTailSeq || s.durableHash != seal.PredecessorTailHash || s.durableSigner != seal.PredecessorSignerKey {
		return errors.New("recovery seal shard or prefix binding mismatch")
	}
	first, err := c.successorOpening(seal.SuccessorSession)
	if err != nil {
		return err
	}
	open := sessionOpen(first.ActionRecord.SessionControl)
	hash, err := ReceiptHash(*first)
	if err != nil {
		return err
	}
	if open == nil || open.RecorderSession != seal.SuccessorSession || first.ActionRecord.ChainSeq != 0 || first.ActionRecord.ChainPrevHash != ComputeSessionOpenGenesis(*open) || first.SignerKey != seal.SuccessorSignerKey || hash != seal.SuccessorOpenHash {
		return errors.New("recovery seal successor opening binding mismatch")
	}
	return c.check()
}

func (c *startupGroupVerification) successorOpening(session string) (*Receipt, error) {
	if p := c.proofs[session]; p != nil && p.session != nil {
		if p.err != nil {
			return nil, p.err
		}
		if p.session.firstReceipt == nil {
			return nil, errors.New("recovery successor opening receipt unavailable")
		}
		return p.session.firstReceipt, nil
	}
	if c.successor == nil {
		return nil, errors.New("recovery successor opening receipt unavailable")
	}
	var found bool
	for _, shard := range c.successor.open.Shards {
		if shard.SessionID == session {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("recovery successor is outside signed membership")
	}
	s := newStartupSessionVerification(c.dir, c.successor.open, session, c.trusted, c.options)
	s.prefix = true
	v, err := newRecoveryPrefixVerifier(session, c.trusted, false)
	if err != nil {
		return nil, err
	}
	v.startup = s
	err = s.walkWithInventory(v.add)
	if err == nil {
		err = v.finish()
	}
	p := &startupShardProof{session: s, err: err, prefixMode: true, openHash: c.successor.openHash}
	c.proofs[session] = p
	if err != nil {
		return nil, err
	}
	if s.firstReceipt == nil {
		return nil, errors.New("recovery successor opening receipt unavailable")
	}
	return s.firstReceipt, nil
}

func (c *startupGroupVerification) recoveryObservation(session, observerKey string) (RecoverySeal, error) {
	p := c.proofs[session]
	if p == nil || p.err != nil || p.session == nil || p.session.observation == nil {
		return RecoverySeal{}, errors.New("recovery predecessor observation unavailable")
	}
	if err := c.check(); err != nil {
		return RecoverySeal{}, err
	}
	s := p.session
	obs := s.observation
	if obs.Snapshot.Size < 0 || obs.Snapshot.Offset < 0 || obs.Snapshot.Offset > obs.Snapshot.Size {
		return RecoverySeal{}, errors.New("recovery predecessor observation has invalid byte boundaries")
	}
	signer := s.durableSigner
	if signer == "" {
		signer = observerKey
	}
	return RecoverySeal{
		PredecessorSession: session, PredecessorSignerKey: signer,
		Shard: obs.Shard, ShardSize: uint64(obs.Snapshot.Size), ShardSHA256: obs.Snapshot.SHA256, DamageOffset: uint64(obs.Snapshot.Offset), LastGoodSeq: s.durableOuterSeq, LastGoodHash: s.durableOuterHash,
		PredecessorTailSeq: s.durableSeq, PredecessorTailHash: s.durableHash,
	}, nil
}

func (c *startupGroupVerification) publishRecovery(req linkRequest, predecessor string) (*RecoverySeal, error) {
	key := hex.EncodeToString(req.privKey.Public().(ed25519.PublicKey))
	observation, err := c.recoveryObservation(predecessor, key)
	if err != nil {
		return nil, err
	}
	first, err := c.successorOpening(req.self)
	if err != nil {
		return nil, err
	}
	o := sessionOpen(first.ActionRecord.SessionControl)
	if o == nil || o.RecorderSession != req.self || first.ActionRecord.ChainSeq != 0 {
		return nil, errors.New("recovery requires a bound successor session_open")
	}
	if first.SignerKey != key {
		return nil, errors.New("recovery successor session_open was signed by a different key than the seal")
	}
	if first.ActionRecord.ChainPrevHash != ComputeSessionOpenGenesis(*o) {
		return nil, errors.New("recovery successor session_open does not start from its genesis")
	}
	observation.SuccessorOpenHash, err = ReceiptHash(*first)
	if err != nil {
		return nil, err
	}
	name := ChainLinkFileName(predecessor)
	_, priorErr := os.Lstat(filepath.Join(c.dir, name))
	if priorErr != nil && !errors.Is(priorErr, os.ErrNotExist) {
		return nil, priorErr
	}
	seal, err := publishRecoverySealObserved(req, predecessor, observation)
	if err != nil {
		return nil, err
	}
	raw, err := readClaimBytes(filepath.Join(c.dir, name))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if errors.Is(priorErr, os.ErrNotExist) {
		c.newSeals[name] = hex.EncodeToString(sum[:])
	}
	return seal, c.check()
}

func readBoundedGroupFileUsing(dir, name string, c *startupGroupVerification) ([]byte, error) {
	if c == nil {
		return readBoundedGroupFile(dir, name)
	}
	if err := c.options.Check(); err != nil {
		return nil, err
	}
	if raw, ok := c.manifests[name]; ok {
		return raw, nil
	}
	raw, err := readBoundedGroupFile(dir, name)
	if err != nil {
		return nil, err
	}
	c.manifests[name] = raw
	return raw, nil
}

// prepareIncoming schedules the exact predecessor role required by the loader's
// incoming transition. Errors stay attached to that role and aren't promoted
// to an earlier inventory refusal. The later transition remains authoritative.
func (c *startupGroupVerification) prepareIncoming(open ReceiptGroupOpen) {
	if open.PreviousGroupID == "" {
		return
	}
	name, _ := ReceiptGroupFileName(open.PreviousGroupID, "open")
	raw, err := readBoundedGroupFileUsing(c.dir, name, c)
	if err != nil {
		return
	}
	old, err := UnmarshalReceiptGroupOpen(raw, c.trusted)
	if err != nil {
		return
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	closeName, _ := ReceiptGroupFileName(old.GroupID, "close")
	closeBytes, err := readBoundedGroupFileUsing(c.dir, closeName, c)
	prefix := errors.Is(err, os.ErrNotExist)
	if err != nil && !prefix {
		return
	}
	if !prefix {
		if _, err := UnmarshalReceiptGroupClose(closeBytes, old, hash, c.trusted); err != nil {
			return
		}
	}
	for i := range old.Shards {
		c.shard(old, hash, i, prefix)
	}
}
