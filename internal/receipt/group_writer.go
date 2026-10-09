// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// ReceiptShardSet owns the fixed v1 emitters of one signed group. It is
// constructed before traffic and never grows a shard after publication.
type ReceiptShardSet struct {
	open     ReceiptGroupOpen
	openHash string
	emitters []*Emitter
	metrics  MetricsSink
	recorder *recorder.Recorder
	signer   ed25519.PrivateKey
	next     atomic.Uint64
	ready    atomic.Bool
	previous *receiptGroupPredecessor
}

// OpenInitialReceiptShardSet publishes an initial group's signed membership,
// durable gates and session opens. The caller owns rec and must close it if
// any startup step fails. Successor groups require a separate transition
// ceremony; this entry point refuses to pretend an existing group is initial.
func OpenInitialReceiptShardSet(template EmitterConfig, base string, count, processIndex int) (*ReceiptShardSet, error) {
	return openReceiptShardSet(template, base, count, processIndex, false, nil)
}

// PrepareInitialReceiptShardSet publishes membership and gates but defers the
// signed session opens until Activate. Guard uses this while it waits for the
// child enforcement proof that supplies the effective policy hash.
func PrepareInitialReceiptShardSet(template EmitterConfig, base string, count, processIndex int) (*ReceiptShardSet, error) {
	return openReceiptShardSet(template, base, count, processIndex, true, nil)
}

type receiptGroupPredecessor struct {
	open       ReceiptGroupOpen
	openHash   string
	closeHash  string
	heads      []ReceiptGroupPredecessor
	incomplete bool
}

// TrustedGroupSignerKeys is the signer set supplied by the running configuration.
func TrustedGroupSignerKeys(template EmitterConfig) ([]string, error) {
	if len(template.PrivKey) != ed25519.PrivateKeySize {
		return nil, errors.New("receipt group requires a signing key")
	}
	trusted := []string{hex.EncodeToString(template.PrivKey.Public().(ed25519.PublicKey))}
	for _, key := range template.PriorSignerKeys {
		if !groupSigner(key) {
			return nil, errors.New("receipt group prior signer key is invalid")
		}
		trusted = append(trusted, key)
	}
	return trusted, nil
}

// OpenSuccessorReceiptShardSet starts a new signed group after verifying the
// predecessor's complete close or its signed prefix. An incomplete predecessor
// remains incomplete, and its successor cannot admit traffic before the
// transition binds every verified prefix head and needed recovery seal.
func OpenSuccessorReceiptShardSet(template EmitterConfig, base string, count, processIndex int, previousGroupID string) (*ReceiptShardSet, error) {
	return prepareSuccessorReceiptShardSet(template, base, count, processIndex, previousGroupID, false)
}

// PrepareSuccessorReceiptShardSet publishes the successor binding before a
// Guard child supplies its enforcement policy hash. Activate opens the signed
// shard sessions after that proof is available.
func PrepareSuccessorReceiptShardSet(template EmitterConfig, base string, count, processIndex int, previousGroupID string) (*ReceiptShardSet, error) {
	return prepareSuccessorReceiptShardSet(template, base, count, processIndex, previousGroupID, true)
}

func prepareSuccessorReceiptShardSet(template EmitterConfig, base string, count, processIndex int, previousGroupID string, deferOpen bool) (*ReceiptShardSet, error) {
	if template.Recorder == nil {
		return nil, errors.New("receipt group successor requires a persistent recorder")
	}
	trusted, err := TrustedGroupSignerKeys(template)
	if err != nil {
		return nil, err
	}
	terminal, found, err := FindTerminalReceiptGroup(template.Recorder.Dir(), base, trusted)
	if err != nil {
		return nil, err
	}
	if !found || terminal != previousGroupID {
		return nil, errors.New("receipt group predecessor changed before successor publication")
	}
	previous, err := loadClosedGroupPredecessor(template.Recorder.Dir(), previousGroupID, trusted)
	if err != nil {
		return nil, err
	}
	return openReceiptShardSet(template, base, count, processIndex, deferOpen, previous)
}

func loadClosedGroupPredecessor(dir, groupID string, trusted []string) (*receiptGroupPredecessor, error) {
	name, err := ReceiptGroupFileName(groupID, "open")
	if err != nil {
		return nil, err
	}
	raw, err := readBoundedGroupFile(dir, name)
	if err != nil {
		return nil, err
	}
	open, err := UnmarshalReceiptGroupOpen(raw, trusted)
	if err != nil {
		return nil, err
	}
	if open.PreviousGroupID != "" {
		priorName, _ := ReceiptGroupFileName(open.PreviousGroupID, "open")
		priorRaw, err := readBoundedGroupFile(dir, priorName)
		if err != nil {
			return nil, err
		}
		if _, err := UnmarshalReceiptGroupOpen(priorRaw, trusted); err != nil {
			return nil, err
		}
	}
	verified := VerifyReceiptGroup(dir, groupID, trusted)
	if verified.Verdict != GroupValid && verified.Verdict != GroupIncomplete {
		return nil, fmt.Errorf("receipt group predecessor is not complete: %s", verified.Error)
	}
	// A predecessor that could not be read, or changed while it was read, has
	// not been shown to be a crashed group. Stop before publishing anything so
	// a transient read failure never becomes durable successor state.
	if verified.readIncomplete {
		return nil, fmt.Errorf("receipt group predecessor could not be verified; fix access to the evidence directory and restart: %s", verified.Error)
	}
	// An incomplete successor may have crashed after its shard opens but before
	// publishing its incoming transition. It cannot become a predecessor until
	// that signed link exists, even though its own close is legitimately absent.
	if open.PreviousGroupID != "" {
		if err := verifyReceiptGroupTransition(dir, open, verified.OpenManifestSHA, trusted); err != nil {
			return nil, fmt.Errorf("receipt group predecessor transition: %w", err)
		}
	}
	if verified.Verdict == GroupIncomplete {
		closeName, _ := ReceiptGroupFileName(groupID, "close")
		if _, err := os.Lstat(filepath.Join(filepath.Clean(dir), closeName)); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("receipt group predecessor has an invalid close manifest")
		}
	}
	if open.BaseSession == "" {
		return nil, errors.New("receipt group predecessor has no base session")
	}
	prev := &receiptGroupPredecessor{open: open, openHash: verified.OpenManifestSHA, closeHash: verified.CloseManifestSHA, incomplete: verified.Verdict == GroupIncomplete}
	prev.heads = make([]ReceiptGroupPredecessor, len(open.Shards))
	for i := range prev.heads {
		if prev.incomplete {
			continue // Verified after successor session opens, before transition.
		}
		head, err := VerifyGroupShardHead(dir, open, verified.OpenManifestSHA, i)
		if err != nil {
			return nil, err
		}
		prev.heads[i] = ReceiptGroupPredecessor{ShardIndex: i, SessionID: head.SessionID, FinalChainSeq: head.FinalChainSeq, FinalChainHash: head.FinalChainHash}
	}
	return prev, nil
}

func openReceiptShardSet(template EmitterConfig, base string, count, processIndex int, deferOpen bool, previous *receiptGroupPredecessor) (*ReceiptShardSet, error) {
	rec := template.Recorder
	if rec == nil || rec.IsNop() || rec.Dir() == "" || len(template.PrivKey) != ed25519.PrivateKeySize {
		return nil, errors.New("receipt group requires a persistent signed recorder")
	}
	if count < 2 || count > 32 || processIndex < 0 || processIndex >= count {
		return nil, errors.New("receipt group requires 2 to 32 shards and a valid process index")
	}
	if err := evidencename.ValidateOperatorSessionID(base); err != nil {
		return nil, fmt.Errorf("receipt group base session: %w", err)
	}
	signerKey := hex.EncodeToString(template.PrivKey.Public().(ed25519.PublicKey))
	if rec.SigningKeyHex() != signerKey {
		return nil, errors.New("receipt group signer differs from recorder checkpoint signer")
	}
	if previous == nil {
		files, err := os.ReadDir(rec.Dir())
		if err != nil {
			return nil, fmt.Errorf("inventory receipt groups: %w", err)
		}
		for _, file := range files {
			if strings.HasPrefix(file.Name(), "receipt-group-") {
				return nil, errors.New("existing receipt group requires successor transition")
			}
		}
	} else if previous.open.BaseSession != base {
		return nil, errors.New("receipt group successor base differs from predecessor")
	}
	var groupBytes [16]byte
	if _, err := rand.Read(groupBytes[:]); err != nil {
		return nil, fmt.Errorf("mint receipt group ID: %w", err)
	}
	groupID := hex.EncodeToString(groupBytes[:])
	sessions := make([]string, count)
	shards := make([]ReceiptGroupShard, count)
	for i := range sessions {
		session, err := recorder.NewRunSessionID(base)
		if err != nil {
			return nil, fmt.Errorf("mint receipt group session %d: %w", i, err)
		}
		sessions[i] = session
		shards[i] = ReceiptGroupShard{ShardIndex: i, SessionID: sessions[i]}
	}
	if err := rec.AcquireGroupSessions(sessions); err != nil {
		return nil, fmt.Errorf("acquire receipt group sessions: %w", err)
	}
	trusted, err := TrustedGroupSignerKeys(template)
	if err != nil {
		return nil, err
	}
	terminal, found, err := FindTerminalReceiptGroup(rec.Dir(), base, trusted)
	if err != nil {
		return nil, fmt.Errorf("recheck receipt group predecessor under ownership: %w", err)
	}
	if previous == nil && found || previous != nil && (!found || terminal != previous.open.GroupID) {
		return nil, errors.New("receipt group predecessor changed before successor publication")
	}
	opening := ReceiptGroupOpen{
		GroupID: groupID, BaseSession: base, ShardCount: count,
		ProcessShardIndex: processIndex, Shards: shards,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if previous != nil {
		opening.PreviousGroupID = previous.open.GroupID
		opening.PreviousOpenManifestSHA256 = previous.openHash
	}
	open, err := SignReceiptGroupOpen(opening, template.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("sign receipt group opening: %w", err)
	}
	name, err := ReceiptGroupFileName(groupID, "open")
	if err != nil {
		return nil, err
	}
	openHash, err := PublishReceiptGroupArtifact(rec.Dir(), name, open)
	if err != nil {
		return nil, fmt.Errorf("publish receipt group opening: %w", err)
	}
	set := &ReceiptShardSet{open: open, openHash: openHash, emitters: make([]*Emitter, count), metrics: template.Metrics, recorder: rec, signer: slices.Clone(template.PrivKey), previous: previous}
	for i, session := range sessions {
		binding := ptrGroupBinding(open, openHash, i)
		gateJSON, err := json.Marshal(binding)
		if err != nil {
			return nil, fmt.Errorf("marshal receipt group shard %d gate: %w", i, err)
		}
		// The gate is generated by this opener; only the shard session is
		// content. Validate-or-fail, never redacted.
		scan, err := rec.BindLifecycleContent(groupGateProducer, gateJSON)
		if err != nil {
			return nil, fmt.Errorf("validate receipt group shard %d gate: %w", i, err)
		}
		outer, _ := recorder.GroupGateOuter(gateJSON)
		gate := recorder.Entry{
			SessionID: session, Type: outer.Type,
			EventKind: outer.EventKind,
			Summary:   outer.Summary, Detail: json.RawMessage(gateJSON),
		}
		if err := rec.RecordGroupGateWithScan(gate, scan); err != nil {
			return nil, fmt.Errorf("record receipt group shard %d gate: %w", i, err)
		}
	}
	for i, session := range sessions {
		binding := ptrGroupBinding(open, openHash, i)
		cfg := template
		cfg.Session = session
		cfg.GroupBinding = binding
		cfg.PriorSignerKeys = nil
		emitter := NewEmitter(cfg)
		if emitter == nil || emitter.InitError() != nil {
			if emitter == nil {
				return nil, fmt.Errorf("initialize receipt group shard %d: no emitter", i)
			}
			return nil, fmt.Errorf("initialize receipt group shard %d: %w", i, emitter.InitError())
		}
		if !deferOpen {
			if err := emitter.EmitSessionOpen(); err != nil {
				return nil, fmt.Errorf("open receipt group shard %d: %w", i, err)
			}
		}
		set.emitters[i] = emitter
	}
	if !deferOpen {
		if err := set.publishTransition(); err != nil {
			return nil, err
		}
	}
	return set, nil
}

// Activate signs every prepared session open with a policy hash obtained after
// construction. A partial failure leaves an incomplete group on disk; callers
// must refuse traffic and cannot retry it as a fresh initial group.
func (s *ReceiptShardSet) Activate(configHash string) error {
	if s == nil {
		return errors.New("receipt group is nil")
	}
	// Every shard stamps the hash on every receipt. Validate it with each
	// shard's retained content before any shard opens, so a refusal writes no
	// partial group.
	for i, emitter := range s.emitters {
		if emitter == nil {
			return fmt.Errorf("receipt group shard %d has no emitter", i)
		}
		if err := emitter.ValidateConfigHash(configHash); err != nil {
			return fmt.Errorf("receipt group shard %d: %w", i, err)
		}
	}
	for i, emitter := range s.emitters {
		emitter.UpdateConfigHash(configHash)
		if err := emitter.EmitSessionOpen(); err != nil {
			return fmt.Errorf("open receipt group shard %d: %w", i, err)
		}
	}
	return s.publishTransition()
}

// publishTransition runs only after every successor opening is durable. No
// request can be admitted until this method succeeds and construction (or
// Activate for Guard) returns to the caller.
func (s *ReceiptShardSet) publishTransition() error {
	if s.previous == nil {
		s.ready.Store(true)
		return nil
	}
	previous := s.previous
	if previous.incomplete {
		for i, shard := range previous.open.Shards {
			head, err := verifyGroupShardPrefix(s.recorder.Dir(), previous.open, previous.openHash, i)
			if err != nil {
				return fmt.Errorf("verify predecessor shard %d: %w", i, err)
			}
			claim := ReceiptGroupPredecessor{ShardIndex: i, SessionID: shard.SessionID, FinalChainSeq: head.seq, FinalChainHash: head.hash}
			if head.torn {
				seal, err := publishRecoverySeal(linkRequest{dir: s.recorder.Dir(), self: s.open.Shards[i%len(s.open.Shards)].SessionID, privKey: s.signer, now: time.Now().UTC(), signerKeys: []string{previous.open.SignerKey, s.open.SignerKey}}, shard.SessionID)
				if err != nil {
					return fmt.Errorf("seal predecessor shard %d: %w", i, err)
				}
				if err := VerifyRecoveryBinding(s.recorder.Dir(), *seal, []string{previous.open.SignerKey, s.open.SignerKey}); err != nil {
					return fmt.Errorf("verify predecessor seal %d: %w", i, err)
				}
				raw, err := readClaimBytes(filepath.Join(s.recorder.Dir(), ChainLinkFileName(shard.SessionID)))
				if err != nil {
					return err
				}
				digest := sha256.Sum256(raw)
				claim.RecoverySealSHA256 = hex.EncodeToString(digest[:])
			}
			previous.heads[i] = claim
		}
	}
	transition, err := SignReceiptGroupTransition(ReceiptGroupTransition{
		NewGroupID: s.open.GroupID, NewOpenManifestSHA256: s.openHash,
		PreviousGroupID: previous.open.GroupID, PreviousOpenManifestSHA256: previous.openHash,
		PreviousCloseManifestSHA256: previous.closeHash, Predecessors: previous.heads,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}, s.open, previous.open, s.openHash, previous.openHash, previous.closeHash, s.signer)
	if err != nil {
		return fmt.Errorf("sign receipt group transition: %w", err)
	}
	name, _ := ReceiptGroupFileName(s.open.GroupID, "transition")
	if _, err := PublishReceiptGroupArtifact(s.recorder.Dir(), name, transition); err != nil {
		return fmt.Errorf("publish receipt group transition: %w", err)
	}
	s.ready.Store(true)
	return nil
}

// Opening returns a copy of the signed membership and its published digest.
func (s *ReceiptShardSet) Opening() (ReceiptGroupOpen, string) {
	if s == nil {
		return ReceiptGroupOpen{}, ""
	}
	copyOpen := s.open
	copyOpen.Shards = slices.Clone(s.open.Shards)
	return copyOpen, s.openHash
}

// ProcessEmitter is reserved for lifecycle records that are not associated
// with a request. It does not consume an admission slot.
func (s *ReceiptShardSet) ProcessEmitter() *Emitter {
	if s == nil || s.open.ProcessShardIndex < 0 || s.open.ProcessShardIndex >= len(s.emitters) {
		return nil
	}
	return s.emitters[s.open.ProcessShardIndex]
}

// Emitters returns the immutable shard order from the signed opening. Runtime
// lifecycle code uses it to heartbeat and seal every shard before closing the
// group, while process-only records still use ProcessEmitter.
func (s *ReceiptShardSet) Emitters() []*Emitter {
	if s == nil {
		return nil
	}
	return slices.Clone(s.emitters)
}

// PublishClose finalizes every owned recorder shard, verifies each sealed
// on-disk head, and durably publishes one complete group close. A failure
// leaves the opening without a close and must not be retried as complete.
// Callers first emit each shard's signed session_close and transcript root.
func (s *ReceiptShardSet) PublishClose() (string, error) {
	if s == nil || s.recorder == nil {
		return "", errors.New("receipt group has no owned recorder")
	}
	if err := s.recorder.FinalizeGroupSessions(); err != nil {
		return "", fmt.Errorf("finalize receipt group: %w", err)
	}
	heads := make([]ReceiptGroupShardHead, len(s.open.Shards))
	for i := range heads {
		head, err := VerifyGroupShardHead(s.recorder.Dir(), s.open, s.openHash, i)
		if err != nil {
			return "", fmt.Errorf("close receipt group shard %d: %w", i, err)
		}
		heads[i] = head
	}
	closed, err := SignReceiptGroupClose(ReceiptGroupClose{
		GroupID: s.open.GroupID, OpenManifestSHA256: s.openHash,
		Shards: heads, ClosedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}, s.open, s.openHash, s.signer)
	if err != nil {
		return "", err
	}
	name, err := ReceiptGroupFileName(s.open.GroupID, "close")
	if err != nil {
		return "", err
	}
	return PublishReceiptGroupArtifact(s.recorder.Dir(), name, closed)
}

// ShardCount returns the immutable number of writers in this group.
func (s *ReceiptShardSet) ShardCount() int {
	if s == nil {
		return 0
	}
	return len(s.emitters)
}

// MarkUnhealthy makes a shard failure visible to every admission path. A
// required group cannot keep writing to surviving shards as if complete.
func (s *ReceiptShardSet) MarkUnhealthy(err error) {
	if s == nil || err == nil {
		return
	}
	for _, emitter := range s.emitters {
		if emitter != nil {
			emitter.MarkUnhealthy(err)
		}
	}
}

// Admit selects a shard exactly once. Callers copy the returned options to
// outcome and failure paths rather than drawing again for the same action.
func (s *ReceiptShardSet) Admit(opts EmitOpts) EmitOpts {
	if s == nil || !s.ready.Load() || len(s.emitters) == 0 || opts.ShardSelected {
		return opts
	}
	opts.ShardIndex = s.open.Shards[(s.next.Add(1)-1)%uint64(len(s.emitters))].ShardIndex
	opts.ShardSelected = true
	return opts
}

func (s *ReceiptShardSet) selectedEmitter(opts EmitOpts) (*Emitter, error) {
	if s == nil || !s.ready.Load() {
		return nil, errors.New("receipt group transition is not ready for admission")
	}
	if !opts.ShardSelected || opts.ShardIndex < 0 || opts.ShardIndex >= len(s.emitters) || s.emitters[opts.ShardIndex] == nil {
		return nil, errors.New("receipt group shard was not selected at admission")
	}
	return s.emitters[opts.ShardIndex], nil
}

// SelectedEmitter returns the v1 writer for an admission-time shard choice.
// Paired v2 writers use the same index without copying the full shard slice
// on every decision.
func (s *ReceiptShardSet) SelectedEmitter(opts EmitOpts) (*Emitter, error) {
	return s.selectedEmitter(opts)
}

// Emit writes to the already selected shard and refuses absent selections.
func (s *ReceiptShardSet) Emit(opts EmitOpts) error {
	emitter, err := s.selectedEmitter(opts)
	if err != nil {
		s.recordSelectionFailure()
		return err
	}
	return emitter.Emit(opts)
}

// EmitDurable is the required-mode counterpart of Emit.
func (s *ReceiptShardSet) EmitDurable(opts EmitOpts) error {
	emitter, err := s.selectedEmitter(opts)
	if err != nil {
		s.recordSelectionFailure()
		return err
	}
	return emitter.EmitDurable(opts)
}

func (s *ReceiptShardSet) recordSelectionFailure() {
	if s != nil && s.metrics != nil {
		s.metrics.RecordEmitFailure(FailReasonUnavailable)
	}
}
