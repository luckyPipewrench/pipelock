// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

// Tail categories come from CaptureTornEvidence and the shared recovery-tail
// corpus. Compare the existing prefix verifier with the startup ceremony.
func TestStartupRecoveryPrefixParity(t *testing.T) {
	for _, tail := range []string{"intact", "fragment", "nul_padding", "sparse_nul_padding", "missing_newline", "embedded_nul", "bad_complete_record"} {
		t.Run(tail, func(t *testing.T) {
			_, key := generateTestKey(t)
			dir := t.TempDir()
			r := startupTestRecorder(t, dir, key)
			set, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0)
			if err != nil {
				t.Fatal(err)
			}
			startupTestClose(t, set, r, false)
			open, hash := set.Opening()
			paths, _ := filepath.Glob(filepath.Join(dir, "evidence-"+open.Shards[0].SessionID+"-*.jsonl"))
			raw, err := os.ReadFile(paths[0])
			if err != nil {
				t.Fatal(err)
			}
			switch tail {
			case "fragment":
				raw = append(raw, []byte(`{"torn":`)...)
			case "nul_padding":
				raw = append(raw, 0, 0)
			case "sparse_nul_padding":
				raw = append(raw, make([]byte, recorder.MaxEntryLineBytes+1)...)
			case "missing_newline":
				raw = raw[:len(raw)-1]
			case "embedded_nul":
				raw = append(raw, []byte("{\x00\"torn\":")...)
			case "bad_complete_record":
				raw = append(raw, []byte("{}\n")...)
			}
			if err = os.WriteFile(paths[0], raw, 0o600); err != nil {
				t.Fatal(err)
			}
			want, wantErr := verifyGroupShardPrefix(dir, open, hash, 0)
			c, err := newStartupGroupVerification(dir, []string{open.SignerKey}, verification.Options{})
			if err != nil {
				t.Fatal(err)
			}
			got, gotErr := verifyGroupShardPrefixUsing(dir, open, hash, 0, c)
			if (wantErr == nil) != (gotErr == nil) || wantErr == nil && want != got {
				t.Fatalf("baseline=%+v/%v shared=%+v/%v", want, wantErr, got, gotErr)
			}
		})
	}
}

func TestStartupProofBindingAndPublicationGuards(t *testing.T) {
	for _, guard := range []string{"incoming_transition", "owner_identity", "root_identity", "native_root_identity", "publication_directory", "consumed_input", "generated_seal", "cancellation", "role_binding", "native_binding"} {
		t.Run(guard, func(t *testing.T) {
			_, key := generateTestKey(t)
			dir := t.TempDir()
			r := startupTestRecorder(t, dir, key)
			set, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0)
			if err != nil {
				t.Fatal(err)
			}
			startupTestClose(t, set, r, true)
			open, hash := set.Opening()
			previous, err := loadClosedGroupPredecessor(dir, open.GroupID, []string{open.SignerKey})
			if err != nil {
				t.Fatal(err)
			}
			c := previous.ceremony
			if guard == "incoming_transition" {
				previous.incomingTransitionProved = false
				r = startupTestRecorder(t, dir, key)
				if _, err = openReceiptShardSet(EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0, false, previous); err == nil {
					t.Fatal("unproved incoming transition admitted")
				}
				return
			}
			// Publication excludes only this ceremony's new artifact names. The
			// tests exercise each independent check before any result is reused.
			c.successor = &ReceiptShardSet{open: ReceiptGroupOpen{GroupID: NewActionID()}}
			switch guard {
			case "owner_identity":
				path := filepath.Join(dir, recorder.GroupOwnerLockFileName)
				if err = os.Rename(path, filepath.Join(t.TempDir(), "old-owner")); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "root_identity":
				c.root = nil
			case "native_root_identity":
				c.aelRoot = nil
			case "publication_directory":
				c.publicationDirectories = map[string]os.FileInfo{filepath.Join(dir, "ael"): c.root}
			case "consumed_input":
				paths, _ := filepath.Glob(filepath.Join(dir, "evidence-"+open.Shards[0].SessionID+"-*.jsonl"))
				if err = os.Chmod(paths[0], 0o400); err != nil {
					t.Fatal(err)
				}
			case "generated_seal":
				name := ChainLinkFileName(open.Shards[0].SessionID)
				original := []byte("original")
				if err = os.WriteFile(filepath.Join(dir, name), []byte("modified"), 0o600); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(original)
				c.newSeals[name] = hex.EncodeToString(sum[:])
				c.inputs, err = fingerprintStartupInputs(dir, c.successor)
				if err != nil {
					t.Fatal(err)
				}
			case "cancellation":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				c.options.Context = ctx
			case "role_binding":
				if p := c.shard(open, hash+"0", 0, false); p.err == nil {
					t.Fatal("different role binding reused")
				}
				return
			case "native_binding":
				p := c.proofs[open.Shards[0].SessionID]
				if _, err := p.session.verifyAEL(p.session.aelRun, p.session.aelSigner, !p.session.aelClose); err == nil {
					t.Fatal("different native completion binding reused")
				}
				return
			}
			if err := c.check(); err == nil {
				t.Fatal("publication guard admitted changed proof inputs")
			}
		})
	}
}

func TestStartupConsumedInputRefusesBeforeReuse(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	r := startupTestRecorder(t, dir, key)
	set, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	startupTestClose(t, set, r, true)
	open, _ := set.Opening()
	previous, err := loadClosedGroupPredecessor(dir, open.GroupID, []string{open.SignerKey})
	if err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "evidence-"+open.Shards[0].SessionID+"-*.jsonl"))
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(paths[0], append(raw, []byte("{}\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	r = startupTestRecorder(t, dir, key)
	if _, err = openReceiptShardSet(EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0, false, previous); err == nil {
		t.Fatal("changed consumed input reused for successor")
	}
	files, err := filepath.Glob(filepath.Join(dir, "receipt-group-*-open.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("successor published: %v %v", files, err)
	}
}

// An unterminated record belongs to recovery validation, never the durable
// inventory chain. CaptureTornEvidence and indexAELClaimsForSession define the
// two consumers' existing complete-line boundary.
func TestStartupInventoryStopsAtDurableBoundary(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	r := startupTestRecorder(t, dir, key)
	set, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	startupTestClose(t, set, r, true)
	open, hash := set.Opening()
	path := filepath.Join(dir, "evidence-"+open.Shards[0].SessionID+"-0.jsonl")
	entries, err := recorder.ReadHistoryEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	var fragment recorder.Entry
	for _, entry := range entries {
		if entry.Type == recorderEntryType {
			fragment = entry
		}
	}
	fragment.Sequence = entries[len(entries)-1].Sequence + 1
	fragment.PrevHash = entries[len(entries)-1].Hash
	fragment.RawDetail = nil
	fragment.Hash = recorder.ComputeHash(fragment)
	wire, err := json.Marshal(fragment)
	if err != nil {
		t.Fatal(err)
	}
	writeRecoveryStreamEntries(t, path, entries, wire)
	shared := newStartupSessionVerification(dir, open, open.Shards[0].SessionID, []string{open.SignerKey}, verification.Options{})
	if _, err := verifyGroupShardPrefixWithSession(dir, open, hash, 0, shared); err == nil {
		t.Fatal("duplicate unterminated receipt admitted by recovery")
	}
	if shared.inventoryErr != nil {
		t.Fatalf("recovery-only fragment changed durable inventory proof: %v", shared.inventoryErr)
	}
}
