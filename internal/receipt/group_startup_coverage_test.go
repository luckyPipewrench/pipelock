// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func startupCoverageGroup(t *testing.T, closed bool) (*startupGroupVerification, ReceiptGroupOpen, string, ed25519.PrivateKey) {
	t.Helper()
	_, key := generateTestKey(t)
	dir := t.TempDir()
	r := startupTestRecorder(t, dir, key)
	set, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	startupTestClose(t, set, r, closed)
	open, hash := set.Opening()
	c, err := newStartupGroupVerification(dir, []string{open.SignerKey}, verification.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c, open, hash, key
}

func startupCoverageRecovery(t *testing.T) (*startupGroupVerification, RecoverySeal, ed25519.PrivateKey) {
	t.Helper()
	dir, seal, key := recoveryFixture(t)
	if err := os.Mkdir(filepath.Join(dir, "ael"), 0o750); err != nil {
		t.Fatal(err)
	}
	c, err := newStartupGroupVerification(dir, []string{seal.SuccessorSignerKey}, verification.Options{})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := recorder.WalkSessionHistoryObserved(dir, seal.PredecessorSession, verification.Options{}, func(recorder.Entry, bool) error { return nil })
	if err != nil || obs == nil {
		t.Fatalf("observation=%+v err=%v", obs, err)
	}
	receipts, err := ExtractReceiptsFromSessionDir(dir, seal.SuccessorSession)
	if err != nil || len(receipts) == 0 {
		t.Fatalf("successor receipts=%d err=%v", len(receipts), err)
	}
	s := &startupSessionVerification{observation: obs, durableOuterSeq: seal.LastGoodSeq, durableOuterHash: seal.LastGoodHash, durableSeq: seal.PredecessorTailSeq, durableHash: seal.PredecessorTailHash, durableSigner: seal.PredecessorSignerKey}
	c.proofs[seal.PredecessorSession] = &startupShardProof{session: s}
	c.proofs[seal.SuccessorSession] = &startupShardProof{session: &startupSessionVerification{firstReceipt: &receipts[0]}}
	if err := verifyRecoveryBindingUsing(dir, seal, c.trusted, c); err != nil {
		t.Fatalf("shared positive control: %v", err)
	}
	return c, seal, key
}

func TestStartupRecoveryObservedBindingRefusals(t *testing.T) {
	for _, mode := range []string{"signature", "missing_observation", "negative_size", "negative_offset", "offset_past_size", "shard", "size", "offset", "outer_seq", "outer_hash", "tail_seq", "tail_hash", "signer", "successor_missing", "successor_hash"} {
		t.Run(mode, func(t *testing.T) {
			c, seal, key := startupCoverageRecovery(t)
			s := c.proofs[seal.PredecessorSession].session
			want := "shard or prefix binding mismatch"
			switch mode {
			case "signature":
				seal.Signature = strings.Repeat("0", 128)
				want = "signature"
			case "missing_observation":
				s.observation = nil
				want = "observation unavailable"
			case "negative_size":
				s.observation.Snapshot.Size = -1
				want = "invalid byte boundaries"
			case "negative_offset":
				s.observation.Snapshot.Offset = -1
				want = "invalid byte boundaries"
			case "offset_past_size":
				s.observation.Snapshot.Offset = s.observation.Snapshot.Size + 1
				want = "invalid byte boundaries"
			case "shard":
				s.observation.Shard = "evidence-other-0.jsonl"
			case "size":
				s.observation.Snapshot.Size++
			case "offset":
				s.observation.Snapshot.Offset--
			case "outer_seq":
				s.durableOuterSeq++
			case "outer_hash":
				s.durableOuterHash = strings.Repeat("0", 64)
			case "tail_seq":
				s.durableSeq++
			case "tail_hash":
				s.durableHash = strings.Repeat("0", 64)
			case "signer":
				s.durableSigner = strings.Repeat("0", 64)
			case "successor_missing":
				delete(c.proofs, seal.SuccessorSession)
				want = "opening receipt unavailable"
			case "successor_hash":
				seal.SuccessorOpenHash = strings.Repeat("0", 64)
				var err error
				seal, err = SignRecoverySeal(seal, key)
				if err != nil {
					t.Fatal(err)
				}
				want = "successor opening binding mismatch"
			}
			if err := verifyRecoveryBindingUsing(c.dir, seal, c.trusted, c); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error=%v want=%q", err, want)
			}
		})
	}
}

func TestStartupRecoveryObservationRefusalsAndFallback(t *testing.T) {
	for _, mode := range []string{"missing", "proof_error", "cancel", "boundaries", "fallback"} {
		t.Run(mode, func(t *testing.T) {
			c, seal, _ := startupCoverageRecovery(t)
			s := c.proofs[seal.PredecessorSession].session
			switch mode {
			case "missing":
				delete(c.proofs, seal.PredecessorSession)
			case "proof_error":
				c.proofs[seal.PredecessorSession].err = errors.New("prefix failed")
			case "cancel":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				c.options.Context = ctx
			case "boundaries":
				s.observation.Snapshot.Size = -1
			case "fallback":
				s.durableSigner = ""
			}
			got, err := c.recoveryObservation(seal.PredecessorSession, seal.PredecessorSignerKey)
			if mode == "fallback" {
				if err != nil || got.PredecessorSignerKey != seal.PredecessorSignerKey || got.ShardSHA256 != seal.ShardSHA256 || got.PredecessorTailHash != seal.PredecessorTailHash {
					t.Fatalf("observation=%+v err=%v", got, err)
				}
			} else if err == nil || got != (RecoverySeal{}) {
				t.Fatalf("observation=%+v err=%v", got, err)
			}
		})
	}
}

func TestStartupRecoveryPublicationRefusals(t *testing.T) {
	for _, mode := range []string{"observation", "successor_error", "control", "session", "sequence", "signer", "genesis", "existing_directory"} {
		t.Run(mode, func(t *testing.T) {
			c, seal, key := startupCoverageRecovery(t)
			first := c.proofs[seal.SuccessorSession].session.firstReceipt
			want := "bound successor session_open"
			switch mode {
			case "observation":
				delete(c.proofs, seal.PredecessorSession)
				want = "observation unavailable"
			case "successor_error":
				c.proofs[seal.SuccessorSession].err = errors.New("successor failed")
				want = "successor failed"
			case "control":
				first.ActionRecord.SessionControl = nil
			case "session":
				first.ActionRecord.SessionControl.Open.RecorderSession = "other-session"
			case "sequence":
				first.ActionRecord.ChainSeq++
			case "signer":
				first.SignerKey = strings.Repeat("0", 64)
				want = "different key"
			case "genesis":
				first.ActionRecord.ChainPrevHash = strings.Repeat("0", 64)
				want = "genesis"
			case "existing_directory":
				path := filepath.Join(c.dir, ChainLinkFileName(seal.PredecessorSession))
				if err := os.Rename(path, filepath.Join(t.TempDir(), "old-seal")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatal(err)
				}
				c.before, _ = fingerprintGroupDirectory(c.dir)
				want = "regular"
			}
			got, err := c.publishRecovery(linkRequest{dir: c.dir, self: seal.SuccessorSession, privKey: key, now: time.Now().UTC(), signerKeys: c.trusted}, seal.PredecessorSession)
			if err == nil || got != nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("seal=%+v err=%v want=%q", got, err, want)
			}
		})
	}
}

func TestStartupSuccessorOpeningRefusals(t *testing.T) {
	for _, mode := range []string{"proof_error", "missing_first", "missing_successor", "membership", "invalid_trust", "empty_session", "corrupt_session"} {
		t.Run(mode, func(t *testing.T) {
			c, open, _, _ := startupCoverageGroup(t, false)
			session := open.Shards[0].SessionID
			want := "opening receipt unavailable"
			switch mode {
			case "proof_error":
				c.proofs[session] = &startupShardProof{session: &startupSessionVerification{}, err: errors.New("retained proof failed")}
				want = "retained proof failed"
			case "missing_first":
				c.proofs[session] = &startupShardProof{session: &startupSessionVerification{}}
			case "membership":
				c.successor = &ReceiptShardSet{open: open}
				session = "outside-membership"
				want = "outside signed membership"
			case "invalid_trust":
				c.successor = &ReceiptShardSet{open: open}
				c.trusted = []string{""}
				want = "key"
			case "corrupt_session":
				c.successor = &ReceiptShardSet{open: open}
				paths, err := filepath.Glob(filepath.Join(c.dir, "evidence-"+session+"-*.jsonl"))
				if err != nil || len(paths) == 0 {
					t.Fatalf("evidence=%v error=%v", paths, err)
				}
				if err := startupAppendFile(paths[0], "{}\n"); err != nil {
					t.Fatal(err)
				}
				want = "unsupported entry version"
			case "empty_session":
				c.successor = &ReceiptShardSet{open: open}
				paths, err := filepath.Glob(filepath.Join(c.dir, "evidence-"+session+"-*.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range paths {
					if err := os.Rename(path, filepath.Join(t.TempDir(), filepath.Base(path))); err != nil {
						t.Fatal(err)
					}
				}
			}
			first, err := c.successorOpening(session)
			if err == nil || first != nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("first=%+v err=%v want=%q", first, err, want)
			}
		})
	}
}

func TestStartupCachedReadsRespectCancellation(t *testing.T) {
	c, open, hash, _ := startupCoverageGroup(t, true)
	c.prepareShards(open, hash, false)
	name, _ := ReceiptGroupFileName(open.GroupID, "open")
	raw, err := readBoundedGroupFileUsing(c.dir, name, c)
	if err != nil || len(raw) == 0 {
		t.Fatalf("control read: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.options.Context = ctx
	for _, mode := range []string{"manifest", "head", "prefix", "transition"} {
		t.Run(mode, func(t *testing.T) {
			var err error
			switch mode {
			case "manifest":
				_, err = readBoundedGroupFileUsing(c.dir, name, c)
			case "head":
				_, err = verifyGroupShardHeadUsing(c.dir, open, hash, 0, c)
			case "prefix":
				_, err = verifyGroupShardPrefixUsing(c.dir, open, hash, 0, c)
			case "transition":
				err = verifyReceiptGroupTransitionWithContext(c.dir, open, hash, c.trusted, c)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cached %s admitted cancellation: %v", mode, err)
			}
		})
	}
}

func TestStartupIncomingDefersDamagedArtifacts(t *testing.T) {
	for _, mode := range []string{"missing_open", "bad_open", "redirected_close", "bad_close"} {
		t.Run(mode, func(t *testing.T) {
			c, open, _, _ := startupCoverageGroup(t, true)
			name, _ := ReceiptGroupFileName(open.GroupID, "open")
			closeName, _ := ReceiptGroupFileName(open.GroupID, "close")
			switch mode {
			case "missing_open":
				if err := os.Rename(filepath.Join(c.dir, name), filepath.Join(t.TempDir(), name)); err != nil {
					t.Fatal(err)
				}
			case "bad_open":
				open.Signature = "ed25519:" + strings.Repeat("0", 128)
				raw, err := json.Marshal(open)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(c.dir, name), raw, 0o600); err != nil {
					t.Fatal(err)
				}
			case "redirected_close":
				path := filepath.Join(c.dir, closeName)
				moved := filepath.Join(t.TempDir(), closeName)
				if err := os.Rename(path, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, path); err != nil {
					t.Fatal(err)
				}
			case "bad_close":
				raw, err := os.ReadFile(filepath.Clean(filepath.Join(c.dir, closeName)))
				if err != nil {
					t.Fatal(err)
				}
				var closed ReceiptGroupClose
				if err := json.Unmarshal(raw, &closed); err != nil {
					t.Fatal(err)
				}
				closed.Signature = "ed25519:" + strings.Repeat("0", 128)
				raw, err = json.Marshal(closed)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(c.dir, closeName), raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			c.prepareIncoming(ReceiptGroupOpen{PreviousGroupID: open.GroupID})
			if len(c.proofs) != 0 {
				t.Fatal("damaged incoming artifact created reusable shard proof")
			}
		})
	}
}

func TestStartupConstructionRejectsInvalidInventory(t *testing.T) {
	for _, mode := range []string{"missing_root", "missing_ael", "invalid_run", "run_symlink", "run_file", "missing_children"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if mode != "missing_ael" {
				if err := os.Mkdir(filepath.Join(dir, "ael"), 0o750); err != nil {
					t.Fatal(err)
				}
			}
			const run = "0123456789abcdef0123456789abcdef"
			root := filepath.Join(dir, "ael", run)
			switch mode {
			case "missing_root":
				dir = filepath.Join(dir, "absent")
			case "invalid_run":
				if err := os.Mkdir(filepath.Join(dir, "ael", "invalid"), 0o750); err != nil {
					t.Fatal(err)
				}
			case "run_symlink":
				if err := os.Symlink(t.TempDir(), root); err != nil {
					t.Fatal(err)
				}
			case "run_file":
				if err := os.WriteFile(root, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing_children":
				if err := os.Mkdir(root, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			c, err := newStartupGroupVerification(dir, nil, verification.Options{})
			if mode == "missing_children" {
				if err != nil || c == nil {
					t.Fatalf("unclaimed run with missing optional children: %v", err)
				}
				before := c.inputs
				after, err := fingerprintStartupInputs(dir, nil)
				if err != nil || before != after || before.count != 1 {
					t.Fatalf("stable optional-child fingerprint=%+v err=%v", after, err)
				}
			} else if err == nil || c != nil {
				t.Fatalf("invalid inventory admitted: c=%+v err=%v", c, err)
			}
		})
	}
}

func TestStartupRetainedInventoryClaims(t *testing.T) {
	for _, mode := range []string{"claim", "inventory_error", "no_claim", "fallback_error"} {
		t.Run(mode, func(t *testing.T) {
			c, open, hash, _ := startupCoverageGroup(t, true)
			c.prepareShards(open, hash, false)
			session := open.Shards[0].SessionID
			s := c.proofs[session].session
			failure := errors.New("retained inventory failed")
			switch mode {
			case "inventory_error":
				s.inventoryErr = failure
			case "no_claim":
				s.claim.run = ""
			case "fallback_error":
				delete(c.proofs, session)
				session = "\x00"
			}
			calls := 0
			err := c.indexSession(open, false, session, func(run, owner, group, signer string, closed bool) error {
				calls++
				if run != s.claim.run || owner != session || group != open.GroupID || signer != open.SignerKey || !closed {
					t.Fatal("retained claim changed")
				}
				return nil
			})
			switch mode {
			case "inventory_error":
				if !errors.Is(err, failure) || calls != 0 {
					t.Fatalf("calls=%d err=%v", calls, err)
				}
			case "fallback_error":
				if err == nil || calls != 0 {
					t.Fatalf("calls=%d err=%v", calls, err)
				}
			case "claim":
				if err != nil || calls != 1 {
					t.Fatalf("calls=%d err=%v", calls, err)
				}
			case "no_claim":
				if err != nil || calls != 0 {
					t.Fatalf("calls=%d err=%v", calls, err)
				}
			}
		})
	}
}

func TestStartupPrefixErrorClassification(t *testing.T) {
	for _, mode := range []string{"invalid_signer", "inventory_role", "native_damage", "missing_open_receipt"} {
		t.Run(mode, func(t *testing.T) {
			c, open, hash, key := startupCoverageGroup(t, false)
			session := open.Shards[0].SessionID
			shared := newStartupSessionVerification(c.dir, open, session, c.trusted, verification.Options{})
			want := "native AEL"
			switch mode {
			case "invalid_signer":
				open.SignerKey = ""
				want = "key"
			case "inventory_role":
				shared.trusted = []string{strings.Repeat("0", 64)}
				want = "inventory"
			case "native_damage":
				if err := shared.walkWithInventory(func(e recorder.Entry) error { shared.authenticate(e); return nil }); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(c.dir, "ael", shared.claim.run, "recorders", "pipelock.jsonl")
				if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				shared = newStartupSessionVerification(c.dir, open, session, c.trusted, verification.Options{})
			case "missing_open_receipt":
				dir := t.TempDir()
				r := startupTestRecorder(t, dir, key)
				set, err := PrepareInitialReceiptShardSet(EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0)
				if err != nil {
					t.Fatal(err)
				}
				startupTestClose(t, set, r, false)
				open, hash = set.Opening()
				session = open.Shards[0].SessionID
				c.dir = dir
				shared = newStartupSessionVerification(dir, open, session, []string{open.SignerKey}, verification.Options{})
				want = "durable signed opening"
			}
			head, err := verifyGroupShardPrefixWithSession(c.dir, open, hash, 0, shared)
			if err == nil || head != (groupPrefixHead{}) || !strings.Contains(err.Error(), want) {
				t.Fatalf("head=%+v err=%v want=%q", head, err, want)
			}
		})
	}
}

func TestStartupDirectoryAndSealReadRefusals(t *testing.T) {
	for _, mode := range []string{"seal_missing", "pin_missing", "pin_symlink", "refresh_identity", "refresh_fingerprint", "unpublished"} {
		t.Run(mode, func(t *testing.T) {
			prepared, r, _, open := startupPreparedWindow(t, true)
			c := prepared.previous.ceremony
			var err error
			switch mode {
			case "seal_missing":
				c.newSeals[ChainLinkFileName(open.Shards[0].SessionID)] = strings.Repeat("0", 64)
				err = c.checkIdentity()
			case "pin_missing", "pin_symlink":
				path := filepath.Join(r.Dir(), "ael", c.proofs[open.Shards[0].SessionID].session.claim.run, "keys")
				moved := filepath.Join(t.TempDir(), "keys")
				if e := os.Rename(path, moved); e != nil {
					t.Fatal(e)
				}
				if mode == "pin_symlink" {
					if e := os.Symlink(moved, path); e != nil {
						t.Fatal(e)
					}
				}
				err = c.pinPublicationDirectories(prepared.previous)
			case "refresh_identity":
				c.root = nil
				err = c.refreshIncomplete(prepared.previous)
			case "refresh_fingerprint":
				name, _ := ReceiptGroupFileName(open.GroupID, "open")
				path := filepath.Join(r.Dir(), name)
				moved := filepath.Join(t.TempDir(), name)
				if e := os.Rename(path, moved); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(moved, path); e != nil {
					t.Fatal(e)
				}
				err = c.refreshIncomplete(prepared.previous)
			case "unpublished":
				c.published = false
				err = c.refreshIncomplete(prepared.previous)
			}
			if mode == "unpublished" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unusable input admitted")
			}
		})
	}
}

func TestStartupFingerprintExcludesUnconsumedNativeFiles(t *testing.T) {
	prepared, r, _, open := startupPreparedWindow(t, true)
	c := prepared.previous.ceremony
	before, err := fingerprintPublicationInputs(r.Dir(), prepared, false)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(r.Dir(), "ael", c.proofs[open.Shards[0].SessionID].session.claim.run)
	for _, path := range []string{filepath.Join(root, "recorders", "unconsumed.jsonl"), filepath.Join(root, "keys", "unconsumed.pub")} {
		if err := os.WriteFile(path, []byte("unconsumed"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	after, err := fingerprintPublicationInputs(r.Dir(), prepared, false)
	// The directory metadata changes, but these files must not contribute their
	// own identities. Rewriting their content cannot alter the consumed set.
	if err != nil || after == before {
		t.Fatalf("directory changes disappeared: %v", err)
	}
	for _, path := range []string{filepath.Join(root, "recorders", "unconsumed.jsonl"), filepath.Join(root, "keys", "unconsumed.pub")} {
		if err := os.WriteFile(path, []byte("different ignored bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	final, err := fingerprintPublicationInputs(r.Dir(), prepared, false)
	if err != nil || final != after {
		t.Fatalf("unconsumed content changed predecessor fingerprint: %v", err)
	}
}

func TestStartupWriterCancellationAtPublicationBoundaries(t *testing.T) {
	run := func(t *testing.T, at int64) int64 {
		t.Helper()
		c, open, _, key := startupCoverageGroup(t, true)
		previous, err := loadClosedGroupPredecessor(c.dir, open.GroupID, c.trusted)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		boundary := &startupCancellationContext{Context: ctx, cancel: cancel, at: at}
		previous.ceremony.options.Context = boundary
		r := startupTestRecorder(t, c.dir, key)
		set, err := openReceiptShardSet(EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0, true, previous)
		if err == nil {
			err = set.Activate(testConfigHash)
		}
		if at == 0 {
			if err != nil || !set.Admit(EmitOpts{}).ShardSelected {
				t.Fatalf("control activation: %v", err)
			}
		} else {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation boundary %d returned %v", at, err)
			}
			if set != nil && set.Admit(EmitOpts{}).ShardSelected {
				t.Fatal("canceled publication admitted traffic")
			}
			paths, globErr := filepath.Glob(filepath.Join(c.dir, "receipt-group-*-transition.json"))
			if globErr != nil || len(paths) != 0 {
				t.Fatalf("canceled publication wrote transition: %v %v", paths, globErr)
			}
		}
		return boundary.calls.Load()
	}
	total := run(t, 0)
	if total == 0 {
		t.Fatal("publication made no cancellation checks")
	}
	for at := int64(1); at <= total; at++ {
		t.Run(fmt.Sprintf("check_%d", at), func(t *testing.T) { run(t, at) })
	}
}

type startupCancellationContext struct {
	context.Context
	cancel  context.CancelFunc
	calls   atomic.Int64
	at      int64
	onCheck func(int64)
}

func (c *startupCancellationContext) Err() error {
	n := c.calls.Add(1)
	if c.onCheck != nil {
		c.onCheck(n)
	}
	if c.at > 0 && n >= c.at {
		c.cancel()
	}
	return c.Context.Err()
}

func TestStartupLoaderRejectsUnavailableInventory(t *testing.T) {
	for _, mode := range []string{"missing_ael", "bad_run", "permission"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "permission" && os.Geteuid() == 0 {
				t.Skip("root can enumerate the unreadable directory")
			}
			c, open, _, _ := startupCoverageGroup(t, true)
			path := filepath.Join(c.dir, "ael")
			switch mode {
			case "missing_ael":
				if err := os.Rename(path, filepath.Join(t.TempDir(), "ael")); err != nil {
					t.Fatal(err)
				}
			case "bad_run":
				if err := os.Mkdir(filepath.Join(path, "invalid"), 0o750); err != nil {
					t.Fatal(err)
				}
			case "permission":
				if err := os.Chmod(path, 0o100); err != nil { // #nosec G302 -- deliberate directory read denial in an isolated non-root test.
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(path, 0o750) }) // #nosec G302 -- restore the directory mode for cleanup.
			}
			prev, err := loadClosedGroupPredecessor(c.dir, open.GroupID, c.trusted)
			want := "not complete"
			if mode == "permission" {
				want = "fix access"
			}
			if err == nil || prev != nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("predecessor=%+v err=%v want=%q", prev, err, want)
			}
		})
	}
}

func TestStartupSuccessorPreparationRejectsRetainedState(t *testing.T) {
	for _, mode := range []string{"missing_native_claim", "invalid_retained_signer"} {
		t.Run(mode, func(t *testing.T) {
			c, open, _, key := startupCoverageGroup(t, true)
			previous, err := loadClosedGroupPredecessor(c.dir, open.GroupID, c.trusted)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing_native_claim" {
				previous.ceremony.proofs[open.Shards[0].SessionID].session.claim.run = "missing-run"
			} else {
				previous.open.SignerKey = "invalid"
			}
			r := startupTestRecorder(t, c.dir, key)
			set, err := openReceiptShardSet(EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0, true, previous)
			if err == nil || set != nil {
				t.Fatalf("invalid retained state admitted: %v", err)
			}
			paths, globErr := filepath.Glob(filepath.Join(c.dir, "receipt-group-*-open.json"))
			if globErr != nil || len(paths) != 1 {
				t.Fatalf("invalid retained state published successor: %v %v", paths, globErr)
			}
		})
	}
}

func TestStartupFingerprintRejectsInvalidRunLayout(t *testing.T) {
	const run = "0123456789abcdef0123456789abcdef"
	for _, mode := range []string{"invalid_name", "file", "symlink", "child_file"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "ael"), 0o750); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "ael", run)
			switch mode {
			case "invalid_name":
				path = filepath.Join(dir, "ael", "invalid")
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(t.TempDir(), path); err != nil {
					t.Fatal(err)
				}
			case "child_file":
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "keys"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := fingerprintStartupInputs(dir, nil); err == nil {
				t.Fatal("invalid native run layout produced reusable fingerprint")
			}
		})
	}
}

func TestStartupFallbackNativeVerificationAndEmptyPins(t *testing.T) {
	c, open, hash, _ := startupCoverageGroup(t, true)
	c.prepareShards(open, hash, false)
	proof := c.proofs[open.Shards[0].SessionID]
	run, signer := proof.session.claim.run, proof.session.claim.signer
	want := proof.session.aelHead
	retained := c.proofs
	c.proofs = make(map[string]*startupShardProof)
	got, err := c.verifyAEL(run, signer, true)
	if err != nil || got != want {
		t.Fatalf("fallback native head=%+v err=%v want=%+v", got, err, want)
	}
	c.proofs = retained
	delete(c.proofs, open.Shards[0].SessionID)
	previous := &receiptGroupPredecessor{open: open}
	if err := c.pinPublicationDirectories(previous); err != nil {
		t.Fatal(err)
	}
	if len(c.publicationDirectories) != 3 {
		t.Fatalf("absent proof pinned a native run: %d", len(c.publicationDirectories))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if next, err := newStartupGroupVerification(c.dir, c.trusted, verification.Options{Context: ctx}); next != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled construction=%+v/%v", next, err)
	}
}

func TestStartupRecoveryWithoutCeremony(t *testing.T) {
	c, open, _, key := startupCoverageGroup(t, false)
	paths, err := filepath.Glob(filepath.Join(c.dir, "evidence-"+open.Shards[0].SessionID+"-*.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("evidence=%v err=%v", paths, err)
	}
	if err := startupAppendFile(paths[0], `{"torn":`); err != nil {
		t.Fatal(err)
	}
	previous, err := loadClosedGroupPredecessor(c.dir, open.GroupID, c.trusted)
	if err != nil {
		t.Fatal(err)
	}
	previous.ceremony = nil
	r := startupTestRecorder(t, c.dir, key)
	set, err := openReceiptShardSet(EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0, false, previous)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Admit(EmitOpts{}).ShardSelected {
		t.Fatal("valid uncached recovery did not admit traffic")
	}
	raw, err := readClaimBytes(filepath.Join(c.dir, ChainLinkFileName(open.Shards[0].SessionID)))
	if err != nil {
		t.Fatal(err)
	}
	seal, err := UnmarshalRecoverySeal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRecoveryBinding(c.dir, seal, c.trusted); err != nil {
		t.Fatalf("uncached recovery binding: %v", err)
	}
}

func TestStartupLoaderCancellationAndFinalStability(t *testing.T) {
	for _, mode := range []string{"canceled", "final_change"} {
		t.Run(mode, func(t *testing.T) {
			c, open, _, _ := startupCoverageGroup(t, true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			probe := &startupCancellationContext{Context: ctx}
			if _, err := loadClosedGroupPredecessorWithOptions(c.dir, open.GroupID, c.trusted, verification.Options{Context: probe}); err != nil {
				t.Fatalf("control load: %v", err)
			}
			finalCheck := probe.calls.Load()
			if finalCheck == 0 {
				t.Fatal("loader made no cancellation checks")
			}
			boundary := &startupCancellationContext{Context: ctx}
			if mode == "canceled" {
				cancel()
			} else {
				boundary.onCheck = func(n int64) {
					if n == finalCheck {
						if err := os.WriteFile(filepath.Join(c.dir, "changed-input.txt"), []byte("changed"), 0o600); err != nil {
							t.Error(err)
						}
					}
				}
			}
			previous, err := loadClosedGroupPredecessorWithOptions(c.dir, open.GroupID, c.trusted, verification.Options{Context: boundary})
			want := context.Canceled
			if mode == "final_change" {
				want = recorder.ErrEvidenceChanged
			}
			if previous != nil || !errors.Is(err, want) {
				t.Fatalf("predecessor=%+v error=%v want=%v", previous, err, want)
			}
		})
	}
}

func TestStartupIndexRefusesMissingIncompleteOpening(t *testing.T) {
	c, open, _, _ := startupCoverageGroup(t, false)
	name, _ := ReceiptGroupFileName(open.GroupID, "open")
	if err := os.Rename(filepath.Join(c.dir, name), filepath.Join(t.TempDir(), name)); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := c.indexSession(open, true, open.Shards[0].SessionID, func(string, string, string, string, bool) error { calls++; return nil })
	if !errors.Is(err, os.ErrNotExist) || calls != 0 {
		t.Fatalf("claims=%d err=%v", calls, err)
	}
}

func TestStartupInventoryFallbackRefusesCorruptEntry(t *testing.T) {
	c, open, _, _ := startupCoverageGroup(t, true)
	session := open.Shards[0].SessionID
	entries, err := startupCoverageEntries(c.dir, session)
	if err != nil || len(entries) == 0 {
		t.Fatalf("entries=%d err=%v", len(entries), err)
	}
	entries[0].Hash = strings.Repeat("0", 64)
	path := filepath.Join(c.dir, "evidence-"+session+"-0.jsonl")
	writeRecoveryStreamEntries(t, path, entries, nil)
	calls := 0
	err = c.indexSession(open, false, session, func(string, string, string, string, bool) error { calls++; return nil })
	if err == nil || calls != 0 || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("claims=%d err=%v", calls, err)
	}
}
