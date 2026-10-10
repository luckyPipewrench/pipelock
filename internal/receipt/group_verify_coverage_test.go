// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type coverageGroupIndex struct {
	check func(ReceiptGroupOpen, bool) error
}

func (i coverageGroupIndex) Check(open ReceiptGroupOpen, incomplete bool) error {
	return i.check(open, incomplete)
}

func (coverageGroupIndex) Close() error { return nil }

func newCoverageGroup(t *testing.T, closed bool) (string, ReceiptGroupOpen) {
	t.Helper()
	_, key := generateTestKey(t)
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	set, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := set.Opening()
	if closed {
		for _, emitter := range set.Emitters() {
			if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
				t.Fatal(err)
			}
			if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := set.PublishClose(); err != nil {
			t.Fatal(err)
		}
	}
	return dir, open
}

func TestReceiptGroupVerificationClassifiesNativeAELTail(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want ReceiptGroupVerdict
	}{
		{"own open tail", errGroupAELOpenTail, GroupIncomplete},
		{"neighbor open tail", errGroupAELNeighborOpenTail, GroupValid},
		{"other index failure", errors.New("index unavailable"), GroupInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, open := newCoverageGroup(t, true)
			result := verifyReceiptGroupWithIndex(dir, open.GroupID, []string{open.SignerKey}, coverageGroupIndex{check: func(_ ReceiptGroupOpen, incomplete bool) error {
				if incomplete {
					t.Fatal("closed group checked as incomplete")
				}
				return tc.err
			}})
			if result.Verdict != tc.want || !strings.Contains(result.Error, tc.err.Error()) {
				t.Fatalf("tail verdict=%+v, want %s and %q", result, tc.want, tc.err)
			}
		})
	}
}

func TestReceiptGroupVerificationDetectsManifestAndDirectoryChanges(t *testing.T) {
	for _, tc := range []struct {
		name, target, want string
		closed             bool
	}{
		{"closed open manifest", "open", "manifest changed", true},
		{"closed close manifest", "close", "manifest changed", true},
		{"closed directory", "extra", "directory changed", true},
		{"incomplete directory", "extra", "directory changed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, open := newCoverageGroup(t, tc.closed)
			result := verifyReceiptGroupWithIndex(dir, open.GroupID, []string{open.SignerKey}, coverageGroupIndex{check: func(_ ReceiptGroupOpen, incomplete bool) error {
				if incomplete != !tc.closed {
					t.Fatalf("index called with incomplete=%t", incomplete)
				}
				var path string
				if tc.target == "extra" {
					path = filepath.Join(dir, "unexpected-artifact")
				} else {
					name, err := ReceiptGroupFileName(open.GroupID, tc.target)
					if err != nil {
						return err
					}
					path = filepath.Join(dir, name)
				}
				return os.WriteFile(path, []byte("changed"), 0o600)
			}})
			// Evidence that changes mid-verification yields no verdict: it is
			// incomplete and retryable, not proof of corruption.
			if result.Verdict != GroupIncomplete || !strings.Contains(result.Error, "no verdict reached") {
				t.Fatalf("changed evidence verdict=%+v, want incomplete with no verdict (%s)", result, tc.want)
			}
		})
	}
}

func TestReceiptGroupInventoryReportsOrphanArtifactsAndStopsOnVisitorFailure(t *testing.T) {
	dir := t.TempDir()
	id := strings.Repeat("a", 32)
	if err := os.Mkdir(filepath.Join(dir, "ael"), 0o750); err != nil {
		t.Fatal(err)
	}
	closeName, err := ReceiptGroupFileName(id, "close")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, closeName), []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	var visited []ReceiptGroupResult
	summary, err := VerifyReceiptGroups(dir, []string{strings.Repeat("0", 64)}, func(result ReceiptGroupResult) error {
		visited = append(visited, result)
		return nil
	})
	if err != nil || summary.Groups != 1 || summary.Invalid != 1 || len(visited) != 1 || visited[0].Verdict != GroupInvalid || !strings.Contains(visited[0].Error, "no opening manifest") {
		t.Fatalf("orphan inventory summary=%+v visited=%+v err=%v", summary, visited, err)
	}
	want := errors.New("visitor stopped")
	summary, err = VerifyReceiptGroups(dir, []string{strings.Repeat("0", 64)}, func(ReceiptGroupResult) error { return want })
	if !errors.Is(err, want) || summary.Groups != 0 {
		t.Fatalf("visitor failure summary=%+v err=%v", summary, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "receipt-group-unrecognized"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if summary, err := VerifyReceiptGroups(dir, []string{strings.Repeat("0", 64)}, nil); err == nil || !strings.Contains(err.Error(), "unknown receipt group artifact") || summary.Groups != summary.Invalid+summary.Incomplete {
		t.Fatalf("unknown artifact summary=%+v err=%v", summary, err)
	}
}

func TestReceiptGroupInventoryRejectsOrphanGateBeforeReportingSuccess(t *testing.T) {
	if summary, err := VerifyReceiptGroups(t.TempDir(), nil, nil); err != nil || summary != (ReceiptGroupInventoryResult{}) {
		t.Fatalf("empty inventory summary=%+v err=%v", summary, err)
	}
	source, open := newCoverageGroup(t, false)
	paths, err := filepath.Glob(filepath.Join(source, "evidence-"+open.Shards[0].SessionID+"-*.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("group gate files=%v err=%v", paths, err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "ael"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.Base(paths[0])), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	visitorErr := errors.New("reject orphan gate report")
	summary, err := VerifyReceiptGroups(dir, []string{open.SignerKey}, func(result ReceiptGroupResult) error {
		if result.Verdict != GroupInvalid || !strings.Contains(result.Error, "no such file") {
			t.Fatalf("orphan gate result=%+v", result)
		}
		return visitorErr
	})
	if !errors.Is(err, visitorErr) || summary.Groups != 0 {
		t.Fatalf("orphan visitor failure summary=%+v err=%v", summary, err)
	}
	summary, err = VerifyReceiptGroups(dir, []string{open.SignerKey}, nil)
	if err != nil || summary.Groups != 1 || summary.Invalid != 1 {
		t.Fatalf("orphan gate summary=%+v err=%v", summary, err)
	}
}
