// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestRecoverySealValidationEdges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*RecoverySeal)
		want   string
	}{
		{"blank_session", func(s *RecoverySeal) { s.PredecessorSession = " \t" }, "invalid recovery seal session"},
		{"slash_session", func(s *RecoverySeal) { s.SuccessorSession = "proxy/run" }, "invalid recovery seal session"},
		{"invalid_utf8_session", func(s *RecoverySeal) { s.PredecessorSession = string([]byte{0xff}) }, "invalid recovery seal session"},
		{"different_base", func(s *RecoverySeal) { s.SuccessorSession = "other.run.00000000000000000000000000000000" }, "one base"},
		{"same_session", func(s *RecoverySeal) { s.SuccessorSession = s.PredecessorSession }, "one base"},
		{"bad_shard", func(s *RecoverySeal) { s.Shard = "not-an-evidence-shard.jsonl" }, "shard identity mismatch"},
		{"slash_shard", func(s *RecoverySeal) { s.Shard = "nested/" + s.Shard }, "shard identity mismatch"},
		{"zero_size", func(s *RecoverySeal) { s.ShardSize = 0 }, "damage offset"},
		{"offset_at_end", func(s *RecoverySeal) { s.DamageOffset = s.ShardSize }, "damage offset"},
		{"unsafe_shard_size", func(s *RecoverySeal) { s.ShardSize = maxRecoveryInteger + 1 }, "safe range"},
		{"unsafe_tail_seq", func(s *RecoverySeal) { s.PredecessorTailSeq = maxRecoveryInteger + 1 }, "safe range"},
		{"bad_shard_hash", func(s *RecoverySeal) { s.ShardSHA256 = "xyz" }, "recovery seal hash"},
		{"bad_open_hash", func(s *RecoverySeal) { s.SuccessorOpenHash = "xyz" }, "recovery seal hash"},
		{"bad_last_head", func(s *RecoverySeal) { s.LastGoodHash = "xyz" }, "recovery seal head"},
		{"bad_tail_head", func(s *RecoverySeal) { s.PredecessorTailHash = "xyz" }, "recovery seal head"},
		{"bad_predecessor_key", func(s *RecoverySeal) { s.PredecessorSignerKey = "xyz" }, "signer key"},
		{"invalid_timestamp", func(s *RecoverySeal) { s.ObservedAt = "tomorrow" }, "observed_at"},
		{"noncanonical_timestamp", func(s *RecoverySeal) { s.ObservedAt = "2026-10-01T12:00:00-04:00" }, "observed_at"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, seal, key := recoveryFixture(t)
			tc.mutate(&seal)
			_, err := SignRecoverySeal(seal, key)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SignRecoverySeal error = %v, want %q", err, tc.want)
			}
		})
	}

	t.Run("unsupported_kind", func(t *testing.T) {
		_, seal, _ := recoveryFixture(t)
		seal.Kind = "other"
		if err := VerifyRecoverySeal(seal); err == nil || !strings.Contains(err.Error(), "unsupported recovery seal") {
			t.Fatalf("VerifyRecoverySeal error = %v", err)
		}
	})
	t.Run("bad_successor_key", func(t *testing.T) {
		_, seal, _ := recoveryFixture(t)
		seal.SuccessorSignerKey = "xyz"
		if err := VerifyRecoverySeal(seal); err == nil || !strings.Contains(err.Error(), "signer key") {
			t.Fatalf("VerifyRecoverySeal error = %v", err)
		}
	})
	t.Run("unsupported_version", func(t *testing.T) {
		_, seal, _ := recoveryFixture(t)
		seal.Version++
		if err := VerifyRecoverySeal(seal); err == nil || !strings.Contains(err.Error(), "unsupported recovery seal") {
			t.Fatalf("VerifyRecoverySeal error = %v", err)
		}
	})
	t.Run("bad_signature_format", func(t *testing.T) {
		_, seal, _ := recoveryFixture(t)
		seal.Signature = "not-a-signature"
		if err := VerifyRecoverySeal(seal); err == nil || !strings.Contains(err.Error(), "signature format") {
			t.Fatalf("VerifyRecoverySeal error = %v", err)
		}
	})
	t.Run("uppercase_signature", func(t *testing.T) {
		_, seal, _ := recoveryFixture(t)
		seal.Signature = strings.ToUpper(seal.Signature)
		if err := VerifyRecoverySeal(seal); err == nil || !strings.Contains(err.Error(), "signature format") {
			t.Fatalf("VerifyRecoverySeal error = %v", err)
		}
	})
	t.Run("tampered_signature", func(t *testing.T) {
		_, seal, _ := recoveryFixture(t)
		seal.Signature = signaturePrefix + strings.Repeat("0", ed25519.SignatureSize*2)
		if err := VerifyRecoverySeal(seal); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
			t.Fatalf("VerifyRecoverySeal error = %v", err)
		}
	})
}

func TestUnmarshalRecoverySealMalformedBytes(t *testing.T) {
	_, seal, _ := recoveryFixture(t)
	raw, err := json.Marshal(seal)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"invalid_utf8", append(bytes.Clone(raw), 0xff), "not UTF-8"},
		{"invalid_json", []byte(`{"kind":`), "EOF"},
		{"second_document", append(bytes.Clone(raw), []byte(` {}`)...), "after top-level value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := UnmarshalRecoverySeal(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) || got != (RecoverySeal{}) {
				t.Fatalf("malformed seal returned %+v / %v, want %q and no seal", got, err, tc.want)
			}
		})
	}
}

func TestObserveRecoveryRejectsMissingAndOversizeShards(t *testing.T) {
	_, seal, _ := recoveryFixture(t)
	t.Run("missing", func(t *testing.T) {
		if _, err := observeRecovery(t.TempDir(), seal.PredecessorSession, seal.SuccessorSignerKey, nil, 0); err == nil {
			t.Fatal("missing predecessor accepted")
		}
	})
	t.Run("per_shard_limit", func(t *testing.T) {
		dir, s, _ := recoveryFixture(t)
		_, err := observeRecovery(dir, s.PredecessorSession, s.SuccessorSignerKey, []string{s.SuccessorSignerKey}, 1)
		if err == nil || !strings.Contains(err.Error(), "evidence read limit exceeded") {
			t.Fatalf("bounded recovery error = %v", err)
		}
	})
	t.Run("missing_successor", func(t *testing.T) {
		dir, s, key := recoveryFixture(t)
		_, err := publishRecoverySeal(linkRequest{dir: dir, self: "proxy.run.00000000000000000000000000000000", privKey: key, now: time.Now().UTC()}, s.PredecessorSession)
		if err == nil || !strings.Contains(err.Error(), "successor session_open before sealing") {
			t.Fatalf("missing successor error = %v", err)
		}
	})
}

func TestVerifyRecoveryBindingRejectsUnreadableEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*testing.T, string, RecoverySeal)
	}{
		{name: "predecessor", edit: func(t *testing.T, dir string, seal RecoverySeal) {
			files := mustRecorderFiles(t, dir, seal.PredecessorSession)
			if err := os.WriteFile(filepath.Clean(files[0]), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "successor", edit: func(t *testing.T, dir string, seal RecoverySeal) {
			files := mustRecorderFiles(t, dir, seal.SuccessorSession)
			if err := os.WriteFile(filepath.Clean(files[0]), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, seal, _ := recoveryFixture(t)
			tc.edit(t, dir, seal)
			if err := VerifyRecoveryBinding(dir, seal, []string{seal.SuccessorSignerKey}); err == nil {
				t.Fatal("unreadable evidence accepted")
			}
		})
	}
}

func TestVerifyRecoveryBindingRejectsInvalidSealAndOpeningBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *RecoverySeal, ed25519.PrivateKey)
		want   string
	}{
		{name: "invalid_signature", mutate: func(_ *testing.T, seal *RecoverySeal, _ ed25519.PrivateKey) {
			seal.Signature = "invalid"
		}, want: "signature format"},
		{name: "wrong_successor_open_hash", mutate: func(t *testing.T, seal *RecoverySeal, key ed25519.PrivateKey) {
			seal.SuccessorOpenHash = strings.Repeat("0", 64)
			signed, err := SignRecoverySeal(*seal, key)
			if err != nil {
				t.Fatal(err)
			}
			*seal = signed
		}, want: "successor opening binding mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, seal, key := recoveryFixture(t)
			tc.mutate(t, &seal, key)
			err := VerifyRecoveryBinding(dir, seal, []string{seal.SuccessorSignerKey})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VerifyRecoveryBinding error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRecoveryBindingAndPublicationSkipPrecedingNonReceiptEntries(t *testing.T) {
	dir, seal, key := recoveryFixture(t)
	file := mustRecorderFiles(t, dir, seal.SuccessorSession)[0]
	raw, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 3 || entries[0].Type != recorderEntryType || entries[2].Type == recorderEntryType {
		t.Fatalf("fixture lacks a non-receipt entry after the opening: %+v", entries)
	}
	// Put the existing checkpoint first while preserving a valid outer chain.
	// Both consumers must skip it to find the bound opening receipt.
	entries = []recorder.Entry{entries[2], entries[0], entries[1]}
	previous := recorder.GenesisHash
	for i := range entries {
		entries[i].Sequence = uint64(i)
		entries[i].PrevHash = previous
		entries[i].Hash = recorder.ComputeHash(entries[i])
		previous = entries[i].Hash
	}
	writeRecoveryStreamEntries(t, file, entries, nil)
	if err := VerifyRecoveryBinding(dir, seal, []string{seal.SuccessorSignerKey}); err != nil {
		t.Fatalf("binding rejected checkpoint before opening: %v", err)
	}
	now, err := time.Parse(time.RFC3339Nano, seal.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := publishRecoverySeal(linkRequest{dir: dir, self: seal.SuccessorSession, privKey: key, now: now}, seal.PredecessorSession)
	if err != nil || got == nil {
		t.Fatalf("publication rejected checkpoint before opening: seal=%v err=%v", got, err)
	}
}

func TestRecoveryClaimRejectsUnavailableAndUntrustedSuccessor(t *testing.T) {
	for _, mode := range []string{"unavailable", "untrusted"} {
		t.Run(mode, func(t *testing.T) {
			dir, seal, _ := recoveryFixture(t)
			claimPath := filepath.Join(dir, ChainLinkFileName(seal.PredecessorSession))
			switch mode {
			case "unavailable":
				for _, f := range mustRecorderFiles(t, dir, seal.SuccessorSession) {
					if err := os.Remove(f); err != nil {
						t.Fatal(err)
					}
				}
			case "untrusted":
				_, otherKey := generateTestKey(t)
				seal, err := SignRecoverySeal(seal, otherKey)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(seal)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(claimPath, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			report, err := VerifyBase(dir, "proxy", BaseVerifyOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if report.Healthy() {
				t.Fatalf("%s recovery failure reported healthy", mode)
			}
			for _, chain := range report.Chains {
				if chain.RecoverySeal != nil {
					t.Fatalf("%s claim attached to an unverified successor", mode)
				}
			}
			if !slices.ContainsFunc(report.Findings, func(f BaseFinding) bool { return f.Kind == FindingInvalidRecoverySeal }) {
				t.Fatalf("%s claim failure not reported: %+v", mode, report.Findings)
			}
		})
	}
}

func TestPublishRecoverySealClaimOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		prepare     func(*testing.T, string, RecoverySeal)
		wantError   string
		wantFailure bool
	}{
		{name: "same_claim_retry"},
		{name: "different_claim", prepare: func(t *testing.T, dir string, s RecoverySeal) {
			// Another run already won the slot with its own valid seal.
			_, otherKey := generateTestKey(t)
			other := s
			other.SuccessorSession = "proxy.run." + strings.Repeat("f", 32)
			signed, err := SignRecoverySeal(other, otherKey)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(signed)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, ChainLinkFileName(s.PredecessorSession)), append(body, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantError: "already claimed by different evidence"},
		{name: "unreadable_claim", prepare: func(t *testing.T, dir string, s RecoverySeal) {
			path := filepath.Join(dir, ChainLinkFileName(s.PredecessorSession))
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o750); err != nil {
				t.Fatal(err)
			}
		}, wantError: "not a regular file"},
		{name: "malformed_claim", prepare: func(t *testing.T, dir string, s RecoverySeal) {
			if err := os.WriteFile(filepath.Join(dir, ChainLinkFileName(s.PredecessorSession)), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, seal, key := recoveryFixture(t)
			if tc.prepare != nil {
				tc.prepare(t, dir, seal)
			}
			priv := key
			now, err := time.Parse(time.RFC3339Nano, seal.ObservedAt)
			if err != nil {
				t.Fatal(err)
			}
			got, err := publishRecoverySeal(linkRequest{dir: dir, self: seal.SuccessorSession, privKey: priv, now: now}, seal.PredecessorSession)
			if tc.wantError != "" || tc.wantFailure {
				if err == nil || (tc.wantError != "" && !strings.Contains(err.Error(), tc.wantError)) {
					t.Fatalf("publishRecoverySeal error = %v, want %q", err, tc.wantError)
				}
				if got != nil {
					t.Fatalf("failed publication returned a seal: %+v", got)
				}
				return
			}
			if err != nil || got == nil {
				t.Fatalf("same claim retry failed: seal=%v err=%v", got, err)
			}
		})
	}
}

func TestPublishRecoverySealRequiresBoundOpening(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*testing.T, string, RecoverySeal)
	}{
		{name: "no_receipts", edit: func(t *testing.T, dir string, seal RecoverySeal) {
			for _, f := range mustRecorderFiles(t, dir, seal.SuccessorSession) {
				if err := os.Remove(f); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{name: "not_open", edit: func(t *testing.T, dir string, seal RecoverySeal) {
			files := mustRecorderFiles(t, dir, seal.SuccessorSession)
			raw, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) < 2 {
				t.Fatalf("fixture has only %d successor entries", len(entries))
			}
			writeRecoveryStreamEntries(t, files[0], entries[1:], nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, seal, key := recoveryFixture(t)
			tc.edit(t, dir, seal)
			got, err := publishRecoverySeal(linkRequest{dir: dir, self: seal.SuccessorSession, privKey: key, now: time.Now().UTC()}, seal.PredecessorSession)
			want := "successor session_open before sealing"
			if tc.name == "not_open" {
				want = "bound successor session_open"
			}
			if err == nil || !strings.Contains(err.Error(), want) || got != nil {
				t.Fatalf("unbound opening returned seal=%+v, err=%v, want %q", got, err, want)
			}
		})
	}
}

func TestPublishRecoverySealRejectsMalformedSuccessorReceipt(t *testing.T) {
	dir, seal, key := recoveryFixture(t)
	files := mustRecorderFiles(t, dir, seal.SuccessorSession)
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || entries[0].Type != recorderEntryType {
		t.Fatalf("unexpected fixture successor entries: %+v", entries)
	}
	entries[0].RawDetail = nil
	entries[0].Detail = []any{}
	entries[0].Hash = recorder.ComputeHash(entries[0])
	writeRecoveryStreamEntries(t, files[0], entries, nil)
	_, err = publishRecoverySeal(linkRequest{dir: dir, self: seal.SuccessorSession, privKey: key, now: time.Now().UTC()}, seal.PredecessorSession)
	if err == nil || !strings.Contains(err.Error(), "cannot unmarshal array") {
		t.Fatalf("malformed successor receipt error = %v", err)
	}
}

func TestPublishRecoverySealRejectsUnreadableSuccessorShard(t *testing.T) {
	dir, seal, key := recoveryFixture(t)
	file := mustRecorderFiles(t, dir, seal.SuccessorSession)[0]
	if err := os.WriteFile(filepath.Clean(file), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := publishRecoverySeal(linkRequest{dir: dir, self: seal.SuccessorSession, privKey: key, now: time.Now().UTC()}, seal.PredecessorSession)
	if err == nil || !strings.Contains(err.Error(), "reading") {
		t.Fatalf("unreadable successor error = %v", err)
	}
}

func mustRecorderFiles(t *testing.T, dir, session string) []string {
	t.Helper()
	files, err := recorderFiles(dir, session)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestPublishPredecessorLinkReportsUnavailableSeal(t *testing.T) {
	dir := t.TempDir()
	_, key := generateTestKey(t)
	first := startRun(t, dir, key)
	first.openAndEmit(t, 1)
	first.close(t)
	files := mustRecorderFiles(t, dir, first.session)
	raw, err := os.ReadFile(files[len(files)-1])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Clean(files[len(files)-1]), append(raw, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := first.rec.Close(); err != nil {
		t.Fatal(err)
	}
	// Ask to publish a seal before the successor evidence exists. The old
	// candidate is structurally torn, so link discovery reports the precise
	// reason it could not attest the discontinuity and leaves it unlinked.
	var notice bytes.Buffer
	_, err = publishPredecessorLink(linkRequest{dir: dir, base: "proxy", self: "proxy.run.00000000000000000000000000000000", privKey: key, now: time.Now().UTC(), notice: &notice}, func(error) {})
	if err != nil {
		t.Fatalf("best-effort predecessor scan became fatal: %v", err)
	}
	if !strings.Contains(notice.String(), "recovery seal unavailable") {
		t.Fatalf("failed recovery seal was not explained: %q", notice.String())
	}
}

func TestEmitterConstructorReportsPendingRecoveryWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	_, key := generateTestKey(t)
	first := startRun(t, dir, key)
	defer first.close(t)
	first.openAndEmit(t, 1)
	files := mustRecorderFiles(t, dir, first.session)
	raw, err := os.ReadFile(files[len(files)-1])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Clean(files[len(files)-1]), append(raw, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	next, err := first.rec.RecoverTornRunSession("proxy")
	if err != nil {
		t.Fatal(err)
	}
	originalLink := linkFile
	linkFile = func(string, string) error { return errors.New("publication fault") }
	t.Cleanup(func() { linkFile = originalLink })
	var notices bytes.Buffer
	initial := NewEmitter(EmitterConfig{Recorder: first.rec, PrivKey: key, Session: next, Notices: &notices})
	if err := initial.EmitSessionOpen(); err != nil || initial.HealthError() != nil {
		t.Fatalf("failed seal publication blocked the first emitter: %v", err)
	}
	// The durable opening remains usable while construction retries the seal.
	reloaded := NewEmitter(EmitterConfig{Recorder: first.rec, PrivKey: key, Session: next, Notices: &notices})
	if err := reloaded.InitError(); err != nil {
		t.Fatalf("pending seal publication blocked replacement emitter: %v", err)
	}
	if reloaded.recoverySeal != nil || first.rec.RecoveryPredecessor() == "" || !strings.Contains(notices.String(), "recovery seal unavailable") || !strings.Contains(notices.String(), "starts unlinked") {
		t.Fatalf("pending unsealed recovery was not reported: %q", notices.String())
	}
	linkFile = originalLink
	finished := NewEmitter(EmitterConfig{Recorder: first.rec, PrivKey: key, Session: next})
	if err := finished.InitError(); err != nil {
		t.Fatalf("recovery publication retry failed: %v", err)
	}
	if finished.recoverySeal == nil || first.rec.RecoveryPredecessor() != "" {
		t.Fatal("successful retry did not attach and acknowledge the recovery seal")
	}
}
