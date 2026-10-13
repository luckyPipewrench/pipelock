// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func TestStartupRecoveryAuthenticationFailures(t *testing.T) {
	for _, mode := range []string{"outer_hash", "progress"} {
		t.Run(mode, func(t *testing.T) {
			c, open, _, _ := startupCoverageGroup(t, false)
			session := open.Shards[0].SessionID
			entries, err := startupCoverageEntries(c.dir, session)
			if err != nil || len(entries) == 0 {
				t.Fatalf("entries=%d err=%v", len(entries), err)
			}
			failure := errors.New("authenticated progress failed")
			options := verification.Options{}
			if mode == "progress" {
				options.Progress = func(verification.Progress) error { return failure }
			} else {
				entries[0].Hash = strings.Repeat("0", 64)
			}
			shared := newStartupSessionVerification(c.dir, open, session, c.trusted, options)
			v, err := newRecoveryPrefixVerifier(session, c.trusted, false)
			if err != nil {
				t.Fatal(err)
			}
			v.startup = shared
			err = v.add(entries[0])
			if err == nil || mode == "progress" && !errors.Is(err, failure) || mode == "outer_hash" && !strings.Contains(err.Error(), "hash") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestStartupRecoveryEvidenceReceiptIntegrity(t *testing.T) {
	for _, mode := range []string{"valid", "foreign_signer", "bad_signature"} {
		t.Run(mode, func(t *testing.T) {
			dir := copyRunChainFixture(t)
			const session = fixtureRun1
			entries, err := startupCoverageEntries(dir, session)
			if err != nil {
				t.Fatal(err)
			}
			var entry recorder.Entry
			var evidence []contractreceipt.EvidenceReceipt
			for _, candidate := range entries {
				extracted, extractErr := contractreceipt.ExtractEvidenceReceiptsFromEntries([]recorder.Entry{candidate})
				if extractErr != nil {
					t.Fatal(extractErr)
				}
				if len(extracted) > 0 {
					entry, evidence = candidate, extracted
					break
				}
			}
			if len(evidence) != 1 {
				t.Fatal("fixture contains no evidence receipt")
			}
			entry.Sequence, entry.PrevHash = 0, recorder.GenesisHash
			entry.Hash = recorder.ComputeHash(entry)
			signer := evidence[0].Signature.SignerKeyID
			shared := newStartupSessionVerification(dir, ReceiptGroupOpen{SignerKey: signer}, session, []string{signer}, verification.Options{})
			shared.whole = &WholeRecorderWalker{}
			v, err := newRecoveryPrefixVerifier(session, []string{signer}, false)
			if err != nil {
				t.Fatal(err)
			}
			v.startup = shared
			if mode == "foreign_signer" {
				v.trusted = []string{strings.Repeat("0", 64)}
			}
			if mode == "bad_signature" {
				evidence[0].Signature.Signature = "ed25519:" + strings.Repeat("0", 128)
				raw, err := json.Marshal(evidence[0])
				if err != nil {
					t.Fatal(err)
				}
				entry.Detail, entry.RawDetail = json.RawMessage(raw), nil
				entry.Hash = recorder.ComputeHash(entry)
			}
			err = v.add(entry)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if err = v.finish(); err != nil {
					t.Fatal(err)
				}
				if shared.v2.Count() != 1 || !shared.v2.Result().Valid {
					t.Fatal("valid v2 prefix did not retain authenticated proof")
				}
			} else {
				want := "recovery v2 prefix"
				if mode == "foreign_signer" {
					want = "not held by this process"
				}
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("error=%v want=%q", err, want)
				}
				if mode == "bad_signature" {
					if err = v.finish(); err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("damaged v2 finish=%v", err)
					}
				}
			}
		})
	}
}

func startupCoverageEntries(dir, session string) ([]recorder.Entry, error) {
	var entries []recorder.Entry
	err := recorder.WalkSessionHistory(dir, session, func(e recorder.Entry) error { entries = append(entries, e); return nil })
	return entries, err
}
