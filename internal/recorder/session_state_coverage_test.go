// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGroupSessionOwnershipRejectsMissingAndInvalidMembers(t *testing.T) {
	var absent *Recorder
	if err := absent.AcquireGroupSessions([]string{"a", "b"}); err == nil || !strings.Contains(err.Error(), "persistent recorder") {
		t.Fatalf("nil group recorder acquisition: %v", err)
	}
	if err := absent.RecordGroupGate(Entry{}); err == nil || !strings.Contains(err.Error(), "invalid group gate") {
		t.Fatalf("nil group gate: %v", err)
	}
	if err := absent.FinalizeGroupSessions(); err == nil || !strings.Contains(err.Error(), "persistent group") {
		t.Fatalf("nil group finalization: %v", err)
	}
	for _, suffix := range []string{strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("0", 31), strings.Repeat("0", 32) + ".run." + strings.Repeat("0", 32)} {
		if validGroupRunSession("proxy.run." + suffix) {
			t.Fatalf("invalid group session suffix %q accepted", suffix)
		}
	}
	r, _, _ := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 2)
	if err := r.RecordGroupGate(Entry{SessionID: sessions[0], Type: GroupGateEntryType, Detail: map[string]any{"group_id": "group"}}); err == nil || !strings.Contains(err.Error(), "not an acquired group member") {
		t.Fatalf("unacquired group gate: %v", err)
	}
	if err := r.FinalizeGroupSessions(); err == nil || !strings.Contains(err.Error(), "no open group") {
		t.Fatalf("unacquired group finalization: %v", err)
	}
}

func TestGroupGatePreflightFailureWritesNoEntry(t *testing.T) {
	r, _, dir := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 2)
	if err := r.AcquireGroupSessions(sessions); err != nil {
		t.Fatal(err)
	}
	err := r.RecordGroupGate(Entry{SessionID: sessions[0], Type: GroupGateEntryType, Detail: func() {}})
	if err == nil || !strings.Contains(err.Error(), "preflight group gate") {
		t.Fatalf("unsafe group gate result: %v", err)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "evidence-"+sessions[0]) {
			t.Fatalf("failed preflight wrote evidence %q", file.Name())
		}
	}
}

func TestGroupFinalizationRejectsRepeatWithoutChangingState(t *testing.T) {
	r, _, _ := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 2)
	if err := r.AcquireGroupSessions(sessions); err != nil {
		t.Fatal(err)
	}
	if err := r.FinalizeGroupSessions(); err != nil {
		t.Fatal(err)
	}
	if err := r.FinalizeGroupSessions(); err == nil || !strings.Contains(err.Error(), "already closing") {
		t.Fatalf("second group finalization: %v", err)
	}
	if err := r.RecordGroupGate(Entry{SessionID: sessions[0], Type: GroupGateEntryType, Detail: map[string]any{"group_id": "group"}}); err == nil || !strings.Contains(err.Error(), "fresh signed shard") {
		t.Fatalf("closed group accepted gate: %v", err)
	}
}

func TestGroupOwnerAcquisitionDoesNotAcceptMissingDirectory(t *testing.T) {
	_, err := acquireGroupOwner(filepath.Join(t.TempDir(), "missing"))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing owner directory: %v", err)
	}
}
