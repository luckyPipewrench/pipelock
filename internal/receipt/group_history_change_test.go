// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type changingGroupIndex struct{ change func() error }

func (c changingGroupIndex) Check(ReceiptGroupOpen, bool) error { return c.change() }
func (c changingGroupIndex) Close() error                       { return nil }

func TestGroupChangingEvidenceIsIncomplete(t *testing.T) {
	f := newGroupScaleFixture(t)
	id := f.run(t, 0, "", 1, 100)
	if got := VerifyReceiptGroup(f.dir, id, f.trusted); got.Verdict != GroupValid {
		t.Fatalf("producer control: %+v", got)
	}
	got := verifyReceiptGroupWithIndex(f.dir, id, f.trusted, changingGroupIndex{change: func() error {
		if err := os.WriteFile(filepath.Join(f.dir, "evidence-active-0.jsonl"), []byte("{active\n"), 0o600); err != nil {
			return err
		}
		return errors.New("read failed while writer changed history")
	}})
	if got.Verdict != GroupIncomplete || !strings.Contains(got.Error, "no verdict reached") {
		t.Fatalf("changed evidence: %+v", got)
	}
}

func TestGroupInventoryDetectsRestoredMetadataRewrite(t *testing.T) {
	f := newGroupScaleFixture(t)
	id := f.run(t, 0, "", 1, 100)
	var target string
	location := recorder.EvidenceLocation{Root: f.dir, Dir: f.dir}
	if err := recorder.WalkHistorySessions(f.dir, func(session string) error {
		return recorder.WalkSessionHistoryFiles(location, session, func(shard recorder.SessionHistoryShard, _ io.Reader) error {
			target = filepath.Join(f.dir, shard.Name)
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if target == "" {
		t.Fatal("no producer shard")
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		t.Fatal(err)
	}
	got := verifyReceiptGroupWithIndex(f.dir, id, f.trusted, changingGroupIndex{change: func() error {
		if err := os.WriteFile(target, raw, 0o600); err != nil {
			return err
		}
		return os.Chtimes(target, before.ModTime(), before.ModTime())
	}})
	if got.Verdict != GroupIncomplete {
		t.Fatalf("rewritten consumed shard accepted: %+v", got)
	}
}

func TestGroupChangedReadErrorIsIncomplete(t *testing.T) {
	f := newGroupScaleFixture(t)
	id := f.run(t, 0, "", 1, 100)
	got := verifyReceiptGroupWithIndex(f.dir, id, f.trusted, failedGroupAELBatchIndex{err: recorder.ErrEvidenceChanged})
	if got.Verdict != GroupIncomplete {
		t.Fatalf("changed read: %+v", got)
	}
	got = verifyReceiptGroupWithIndex(f.dir, id, f.trusted, failedGroupAELBatchIndex{err: errors.New("stable integrity failure")})
	if got.Verdict != GroupInvalid {
		t.Fatalf("stable invalid control: %+v", got)
	}
}
