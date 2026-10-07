// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyReceiptGroupRefusesMissingTrustAndOpening(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "ael"), 0o750); err != nil {
		t.Fatal(err)
	}
	groupID := strings.Repeat("a", 32)
	name, _ := ReceiptGroupFileName(groupID, "open")
	for _, tc := range []struct {
		name    string
		dir     string
		id      string
		trusted []string
		want    string
	}{
		{name: "untrusted", dir: dir, id: groupID, want: "trusted signer key"},
		{name: "missing directory", dir: filepath.Join(dir, "absent"), id: groupID, trusted: []string{"key"}, want: "not a real directory"},
		{name: "invalid ID", dir: dir, id: "bad", trusted: []string{"key"}, want: "invalid receipt group ID"},
		{name: "missing opening", dir: dir, id: groupID, trusted: []string{"key"}, want: "read receipt group opening"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := VerifyReceiptGroup(tc.dir, tc.id, tc.trusted)
			if got.Verdict != GroupInvalid || !strings.Contains(got.Error, tc.want) {
				t.Fatalf("verdict = %+v, want %q", got, tc.want)
			}
		})
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := VerifyReceiptGroup(dir, groupID, []string{"key"}); got.Verdict != GroupInvalid || !strings.Contains(got.Error, "invalid receipt group opening") {
		t.Fatalf("malformed signed opening accepted: %+v", got)
	}
}

func TestVerifyReceiptGroupsPropagatesInventoryAndVisitorFailures(t *testing.T) {
	key := testGroupKey(t)
	open, _, _ := testGroupOpen(t, key)
	name, _ := ReceiptGroupFileName(open.GroupID, "open")
	for _, tc := range []struct {
		name  string
		make  func(t *testing.T, dir string)
		visit func(ReceiptGroupResult) error
		want  string
	}{
		{name: "missing directory", make: func(t *testing.T, dir string) {}, want: "no such file"},
		{name: "unsafe AEL", make: func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Symlink(t.TempDir(), filepath.Join(dir, "ael")); err != nil {
				t.Fatal(err)
			}
			if _, err := PublishReceiptGroupArtifact(dir, name, open); err != nil {
				t.Fatal(err)
			}
		}, want: "inventory receipt groups"},
		{name: "visitor refuses incomplete group", make: func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Mkdir(filepath.Join(dir, "ael"), 0o750); err != nil {
				t.Fatal(err)
			}
			if _, err := PublishReceiptGroupArtifact(dir, name, open); err != nil {
				t.Fatal(err)
			}
		}, visit: func(result ReceiptGroupResult) error {
			if result.Verdict != GroupIncomplete {
				return errors.New("unexpected group verdict")
			}
			return errors.New("visitor refused group")
		}, want: "visitor refused group"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.name == "missing directory" {
				dir = filepath.Join(dir, "missing")
			} else {
				tc.make(t, dir)
			}
			summary, err := VerifyReceiptGroups(dir, []string{open.SignerKey}, tc.visit)
			if err == nil || !strings.Contains(err.Error(), tc.want) || summary.Groups != 0 {
				t.Fatalf("inventory incorrectly completed: summary=%+v err=%v", summary, err)
			}
		})
	}
}

func TestVerifyReceiptGroupRejectsUnsafeAELInventory(t *testing.T) {
	groupID := strings.Repeat("a", 32)
	for _, tc := range []struct {
		name string
		make func(t *testing.T, dir string)
		want string
	}{
		{name: "ael symlink", make: func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Symlink(t.TempDir(), filepath.Join(dir, "ael")); err != nil {
				t.Fatal(err)
			}
		}, want: "AEL path is not a real directory"},
		{name: "invalid run name", make: func(t *testing.T, dir string) {
			t.Helper()
			if err := os.MkdirAll(filepath.Join(dir, "ael", "bad"), 0o750); err != nil {
				t.Fatal(err)
			}
		}, want: "invalid native AEL run directory"},
		{name: "run symlink", make: func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Mkdir(filepath.Join(dir, "ael"), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), filepath.Join(dir, "ael", strings.Repeat("b", 32))); err != nil {
				t.Fatal(err)
			}
		}, want: "is not a real directory"},
		{name: "run child is file", make: func(t *testing.T, dir string) {
			t.Helper()
			run := filepath.Join(dir, "ael", strings.Repeat("b", 32))
			if err := os.MkdirAll(run, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(run, "keys"), []byte("not a directory"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "inventory path is not a real directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.make(t, dir)
			got := VerifyReceiptGroup(dir, groupID, []string{"key"})
			if got.Verdict != GroupInvalid || !strings.Contains(got.Error, tc.want) {
				t.Fatalf("unsafe AEL inventory = %+v, want %q", got, tc.want)
			}
		})
	}
}

func TestVerifyReceiptGroupsReportsOrphanAndUnknownArtifacts(t *testing.T) {
	groupID := strings.Repeat("a", 32)
	for _, phase := range []string{"close", "transition"} {
		t.Run("orphan "+phase, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "ael"), 0o750); err != nil {
				t.Fatal(err)
			}
			name, _ := ReceiptGroupFileName(groupID, phase)
			if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			var reports []ReceiptGroupResult
			summary, err := VerifyReceiptGroups(dir, []string{"key"}, func(result ReceiptGroupResult) error {
				reports = append(reports, result)
				return nil
			})
			if err != nil || summary.Groups != 1 || summary.Invalid != 1 || len(reports) != 1 || reports[0].Verdict != GroupInvalid {
				t.Fatalf("orphan %s accepted: summary=%+v reports=%+v err=%v", phase, summary, reports, err)
			}
		})
	}
	t.Run("unknown artifact", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "ael"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "receipt-group-unknown.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyReceiptGroups(dir, []string{"key"}, nil); err == nil || !strings.Contains(err.Error(), "unknown receipt group artifact") {
			t.Fatalf("unknown artifact accepted: %v", err)
		}
	})
}

func TestReadBoundedGroupFileRejectsUnsafeArtifact(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "valid.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readBoundedGroupFile(dir, "valid.json"); err != nil || string(raw) != "{}" {
		t.Fatalf("regular bounded file = %q, %v", raw, err)
	}
	if err := os.Symlink("valid.json", filepath.Join(dir, "symlink.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "directory.json"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oversize.json"), []byte(strings.Repeat("x", maxGroupFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"symlink.json", "directory.json", "oversize.json"} {
		t.Run(name, func(t *testing.T) {
			if _, err := readBoundedGroupFile(dir, name); err == nil || !strings.Contains(err.Error(), "bounded regular file") {
				t.Fatalf("unsafe group artifact %q accepted: %v", name, err)
			}
		})
	}
}
