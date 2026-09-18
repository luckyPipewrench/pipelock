// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func TestDefaultBudgetMatchesContainCLIDoc(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "contain-cli.md"))
	if err != nil {
		t.Fatalf("read contain CLI documentation: %v", err)
	}
	matches := regexp.MustCompile(`currently ([0-9,]+) entries or ([0-9]+) MiB of path bytes`).FindStringSubmatch(string(data))
	if matches == nil {
		t.Fatal("contain CLI documentation does not state the workspace snapshot budget")
	}
	docEntries, err := strconv.Atoi(strings.ReplaceAll(matches[1], ",", ""))
	if err != nil {
		t.Fatalf("parse documented entry budget %q: %v", matches[1], err)
	}
	docPathMiB, err := strconv.ParseInt(matches[2], 10, 64)
	if err != nil {
		t.Fatalf("parse documented path budget %q: %v", matches[2], err)
	}
	budget := DefaultBudget()
	if docEntries != budget.MaxEntries {
		t.Fatalf("documented entry budget = %d, code = %d", docEntries, budget.MaxEntries)
	}
	if docPathMiB != budget.MaxTotalPathBytes>>20 {
		t.Fatalf("documented path budget = %d MiB, code = %d MiB", docPathMiB, budget.MaxTotalPathBytes>>20)
	}
}

func TestDiff_DeviceOnlyBoundaryCheckMarksStatementIncomplete(t *testing.T) {
	before := Manifest{
		Root:          "/granted",
		CapBytes:      1,
		Entries:       map[string]Entry{},
		BoundaryCheck: BoundaryCheckDeviceOnly,
	}
	after := Manifest{
		Root:          "/granted",
		CapBytes:      1,
		Entries:       map[string]Entry{},
		BoundaryCheck: BoundaryCheckMountID,
	}
	statement, err := Diff(before, after, testNow)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if statement.BoundaryCheck != BoundaryCheckDeviceOnly {
		t.Fatalf("boundary_check = %q, want %q", statement.BoundaryCheck, BoundaryCheckDeviceOnly)
	}
	if !statement.Incomplete {
		t.Fatal("device-only mount boundary checking must mark the statement incomplete")
	}
	if statement.IncompleteReason != "mount boundary check unavailable on this kernel" {
		t.Fatalf("incomplete_reason = %q", statement.IncompleteReason)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestDiff_AddedRemovedModified(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "keep.txt"), "same")
	writeFile(t, filepath.Join(root, "change.txt"), "before")
	writeFile(t, filepath.Join(root, "gone.txt"), "bye")

	before, err := Snapshot(root, 1<<20, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}

	if err := os.Remove(filepath.Join(root, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "change.txt"), "after")
	writeFile(t, filepath.Join(root, "new.txt"), "hello")

	after, err := Snapshot(root, 1<<20, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}

	st, err := Diff(before, after, testNow)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if st.Incomplete {
		t.Fatalf("did not expect incomplete: %+v", st)
	}
	assertPaths(t, "added", st.Added, filepath.Join(root, "new.txt"))
	assertPaths(t, "removed", st.Removed, filepath.Join(root, "gone.txt"))
	assertPaths(t, "modified", st.Modified, filepath.Join(root, "change.txt"))
	if st.Counts.Added != 1 || st.Counts.Removed != 1 || st.Counts.Modified != 1 {
		t.Fatalf("counts = %+v", st.Counts)
	}
	// keep.txt must not appear anywhere: unchanged content, unchanged digest.
	for _, p := range append(append(append([]string{}, st.Added...), st.Removed...), st.Modified...) {
		if filepath.Base(p) == "keep.txt" {
			t.Fatalf("unchanged file reported as changed: %s", p)
		}
	}
}

func assertPaths(t *testing.T, label string, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("%s[%d] = %s, want %s", label, i, got[i], w)
		}
	}
}

func TestDiff_Symlink_NotFollowed_TargetChangeIsModified(t *testing.T) {
	root := t.TempDir()
	targetA := filepath.Join(root, "a.txt")
	targetB := filepath.Join(root, "b.txt")
	writeFile(t, targetA, "a")
	writeFile(t, targetB, "b")
	link := filepath.Join(root, "link")
	if err := os.Symlink(targetA, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	before, err := Snapshot(root, 1<<20, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	if e, ok := before.Entries[link]; !ok || e.Kind != KindSymlink || e.Digest != "" {
		t.Fatalf("symlink entry wrong: %+v ok=%v", e, ok)
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetB, link); err != nil {
		t.Fatal(err)
	}
	after, err := Snapshot(root, 1<<20, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}

	st, err := Diff(before, after, testNow)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	assertPaths(t, "modified", st.Modified, link)
}

func TestDiff_OversizeCap_NoDigestButSizeChangeDetected(t *testing.T) {
	root := t.TempDir()
	big := filepath.Join(root, "big.bin")
	writeFile(t, big, "0123456789") // 10 bytes

	capBytes := int64(4) // force oversize
	before, err := Snapshot(root, capBytes, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	e := before.Entries[big]
	if !e.Oversize || e.Digest != "" {
		t.Fatalf("expected oversize with no digest, got %+v", e)
	}

	// Sleep-free mtime bump: change size, which oversize comparison covers
	// even without content hashing.
	writeFile(t, big, "01234567890123456789")
	after, err := Snapshot(root, capBytes, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}
	st, err := Diff(before, after, testNow)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	assertPaths(t, "modified", st.Modified, big)
	if !st.Incomplete || !strings.Contains(st.IncompleteReason, "content-digest cap") {
		t.Fatalf("oversize statement = %+v, want incomplete evidence", st)
	}
}

func TestDiff_OversizeCap_SameMetadataIsIncomplete(t *testing.T) {
	root := t.TempDir()
	big := filepath.Join(root, "big.bin")
	writeFile(t, big, "0123456789")

	before, err := Snapshot(root, 4, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	if err := os.WriteFile(big, []byte("abcdefghij"), 0o600); err != nil {
		t.Fatalf("replace oversize content: %v", err)
	}
	mtime := before.Entries[big].ModTime
	if err := os.Chtimes(big, mtime, mtime); err != nil {
		t.Fatalf("restore modification time: %v", err)
	}
	after, err := Snapshot(root, 4, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}
	statement, err := Diff(before, after, testNow)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if !statement.Incomplete || !strings.Contains(statement.IncompleteReason, "content-digest cap") {
		t.Fatalf("statement = %+v, want incomplete oversize evidence", statement)
	}
}

func TestDiff_UnreadableDirectory_RecordedNeverSilentlySkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission denial does not hold on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("root can read anything; permission-denial case does not apply")
	}
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	if err := os.Mkdir(blocked, 0o000); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	defer func() { _ = os.Chmod(blocked, 0o750) }() // let TempDir cleanup succeed

	before, err := Snapshot(root, 1<<20, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	found := false
	for _, e := range before.Unreadable {
		if e.Path == blocked {
			found = true
			if e.Reason == "" {
				t.Fatalf("unreadable entry has no reason: %+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("expected %s in Unreadable, got %v", blocked, before.Unreadable)
	}

	after, err := Snapshot(root, 1<<20, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	st, err := Diff(before, after, testNow)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if st.Counts.Unreadable == 0 {
		t.Fatalf("expected unreadable count > 0, got %+v", st.Counts)
	}
	if !st.Incomplete {
		t.Fatalf("expected Incomplete=true whenever an unreadable entry exists, got %+v", st)
	}
	for _, changed := range [][]string{st.Added, st.Removed, st.Modified} {
		if len(changed) != 0 {
			t.Fatalf("unreadable directory must not be reported as changed: %+v", st)
		}
	}
}

// TestDiff_UnreadableSubtree_DescendantsNotReportedAsRemoved is M4: a file
// that exists in BOTH snapshots, but sits under a directory that became
// unreadable between them, must never be reported as removed just because
// the walk could not re-enter that directory the second time. Without the
// exclusion-by-prefix fix, "old" disappears from after.Entries (the walk
// never re-enters "blocked"), and the naive before/after set-diff reports it
// as Removed even though it may still exist.
func TestDiff_UnreadableSubtree_DescendantsNotReportedAsRemoved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission denial does not hold on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("root can read anything; permission-denial case does not apply")
	}
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	if err := os.Mkdir(blocked, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	oldFile := filepath.Join(blocked, "old")
	writeFile(t, oldFile, "still here")

	before, err := Snapshot(root, 1<<20, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	if _, ok := before.Entries[oldFile]; !ok {
		t.Fatalf("expected %s recorded while readable", oldFile)
	}

	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer func() { _ = os.Chmod(blocked, 0o750) }()

	after, err := Snapshot(root, 1<<20, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}

	st, err := Diff(before, after, testNow)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	for _, p := range st.Removed {
		if p == oldFile {
			t.Fatalf("a file that merely became unreadable must not be reported as removed: %+v", st)
		}
	}
	if len(st.Removed) != 0 {
		t.Fatalf("expected no removals, only exclusion, got %v", st.Removed)
	}
	if !st.Incomplete {
		t.Fatalf("expected Incomplete=true when a subtree became unreadable")
	}
}

func TestDiff_RootDisappearsMidSession_FailsClosedNotEmpty(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "f.txt"), "x")
	before, err := Snapshot(root, 1<<20, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	after, err := Snapshot(root, 1<<20, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}
	if !after.RootMissing {
		t.Fatalf("expected RootMissing after removal")
	}
	st, err := Diff(before, after, testNow)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if !st.Incomplete {
		t.Fatalf("expected Incomplete=true when root vanished, got %+v", st)
	}
	if st.IncompleteReason == "" {
		t.Fatalf("expected a non-empty IncompleteReason")
	}
	if len(st.Added) != 0 || len(st.Removed) != 0 || len(st.Modified) != 0 {
		t.Fatalf("a vanished root must not report an empty-looking diff as if nothing changed: %+v", st)
	}
}

func TestSnapshot_RootNeverExisted(t *testing.T) {
	root := filepath.Join(t.TempDir(), "does-not-exist")
	m, err := Snapshot(root, 1<<20, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !m.RootMissing {
		t.Fatalf("expected RootMissing for a never-existing root")
	}
	st, err := Diff(m, m, testNow)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if !st.Incomplete {
		t.Fatalf("expected Incomplete=true when root never existed")
	}
}

func TestSignAndVerify_RoundTripAndBinding(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	st := Statement{Root: "/granted", CapBytes: 1024, GeneratedAt: testNow, Added: []string{"/granted/new.txt"}, Counts: Counts{Added: 1}}
	signed, err := Sign([]Statement{st}, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signed.SchemaVersion != SchemaVersionV1 {
		t.Fatalf("schema version = %q", signed.SchemaVersion)
	}
	if signed.PostureCapsuleSHA256 != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("binding not preserved: %q", signed.PostureCapsuleSHA256)
	}
	if err := Verify(signed, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Tamper with the bound capsule digest: signature must now fail. This is
	// the session-binding proof: the signature covers the binding field, so
	// re-pointing the statement at a different session's capsule is detected.
	tampered := signed
	tampered.PostureCapsuleSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := Verify(tampered, pub); err == nil {
		t.Fatalf("expected verification failure after re-binding to a different capsule digest")
	}

	// Tamper with statement content: signature must fail.
	tampered2 := signed
	tampered2.Statements = []Statement{{Root: "/other"}}
	if err := Verify(tampered2, pub); err == nil {
		t.Fatalf("expected verification failure after statement content tamper")
	}

	// GeneratedAt on its own. The content tamper above also moves Root, which
	// is signed independently, so it would still fail if a regression dropped
	// GeneratedAt from signablePayload. Moving only the timestamp is what
	// proves that field is covered: a statement re-dated to look like it came
	// from a different run must not verify.
	tampered3 := signed
	redated := st
	redated.GeneratedAt = testNow.Add(time.Hour)
	tampered3.Statements = []Statement{redated}
	if err := Verify(tampered3, pub); err == nil {
		t.Fatalf("expected verification failure after generated_at tamper")
	}
}

func TestSign_RejectsMissingBinding(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	if _, err := Sign([]Statement{{}}, "", priv); err == nil {
		t.Fatalf("expected error for empty capsuleSHA256 binding")
	}
}

func TestSign_RejectsBadKeyLength(t *testing.T) {
	if _, err := Sign([]Statement{{}}, "abc", ed25519.PrivateKey([]byte{1, 2, 3})); err == nil {
		t.Fatalf("expected error for invalid key length")
	}
}

func TestSignRejectsInvalidCapsuleDigest(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign([]Statement{{Root: "/workspace"}}, "cafebabe", priv); err == nil || !strings.Contains(err.Error(), "64-hex-char") {
		t.Fatalf("Sign invalid digest error = %v, want digest-shape rejection", err)
	}
}

func TestWriteJSON_PermsAndRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub
	signed, err := Sign([]Statement{{Root: "/g"}}, strings.Repeat("a", sha256.Size*2), priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "posture")
	path, err := WriteJSON(dir, signed)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file perm = %o, want 0600", perm)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	// The requested mode is 0o750; the resulting mode is that request masked
	// by the process umask (proven separately by inspecting the MkdirAll call
	// site), so assert only that it carries no group/other WRITE bit and no
	// world-read/execute bit, rather than an exact value the test's own
	// umask could legitimately narrow further.
	if perm := dirInfo.Mode().Perm(); perm&0o027 != 0 {
		t.Fatalf("dir perm = %o, must not exceed owner-rwx + group-rx (0750)", perm)
	}
}

// TestWriteJSON_ReplacesExistingLoosePermissionFile is L7: a pre-existing
// destination file with a loose mode (0644, world-readable) must not survive
// with that mode after WriteJSON. Without the atomic-temp-then-rename fix,
// os.WriteFile only sets the mode when CREATING the file and otherwise
// leaves an existing file's mode untouched, so a 0644 file previously left
// at this path (however that happened) would stay 0644 forever.
func TestWriteJSON_ReplacesExistingLoosePermissionFile(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	signed, err := Sign([]Statement{{Root: "/g"}}, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	existing := filepath.Join(dir, "workspace-change-statement.json")
	if err := os.WriteFile(existing, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, err := WriteJSON(dir, signed)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm after overwriting a 0644 file = %o, want 0600", perm)
	}
}

func TestVerifyBinding_MatchedPairPasses(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	capsulePath := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(capsulePath, []byte("this session's exact capsule bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	capsuleHash, err := HashFileSHA256(capsulePath)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign([]Statement{{Root: "/g"}}, capsuleHash, priv)
	if err != nil {
		t.Fatal(err)
	}
	capsuleBytes, err := os.ReadFile(capsulePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBindingBytes(signed, capsuleBytes, pub); err != nil {
		t.Fatalf("expected matched pair to verify, got %v", err)
	}
}

// TestVerifyBinding_MismatchedSessionsRejected is H1: two individually
// VALID artifacts (a real capsule and a real, correctly-signed statement)
// from DIFFERENT sessions must be rejected as a pair. Verify() alone (the
// pre-fix surface) checks only the statement's own signature and passes
// here, which is exactly the gap: nothing then stopped a mismatched pair
// from being treated as coherent evidence.
func TestVerifyBinding_MismatchedSessionsRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	capsuleA := filepath.Join(t.TempDir(), "a.json")
	capsuleB := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(capsuleA, []byte("session A capsule"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(capsuleB, []byte("session B capsule, totally different"), 0o600); err != nil {
		t.Fatal(err)
	}
	hashA, err := HashFileSHA256(capsuleA)
	if err != nil {
		t.Fatal(err)
	}
	// A statement genuinely signed and bound to session A's capsule.
	statementForA, err := Sign([]Statement{{Root: "/g"}}, hashA, priv)
	if err != nil {
		t.Fatal(err)
	}

	// The statement's OWN signature verifies fine on its own: it was never
	// tampered with. The defect is pairing it with capsule B.
	if err := Verify(statementForA, pub); err != nil {
		t.Fatalf("statement's own signature should verify: %v", err)
	}
	capsuleBBytes, err := os.ReadFile(capsuleB)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBindingBytes(statementForA, capsuleBBytes, pub); err == nil {
		t.Fatalf("expected VerifyBindingBytes to reject session A's statement paired with session B's capsule")
	} else if !errors.Is(err, ErrCapsuleDigestMismatch) {
		t.Fatalf("expected ErrCapsuleDigestMismatch, got %v", err)
	}
}

func TestVerifyBinding_TamperedCapsuleBytesRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	capsulePath := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(capsulePath, []byte("original capsule bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := HashFileSHA256(capsulePath)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign([]Statement{{Root: "/g"}}, hash, priv)
	if err != nil {
		t.Fatal(err)
	}
	// Capsule bytes on disk change after the statement was bound (e.g. a
	// different capsule was written to the same path).
	if err := os.WriteFile(capsulePath, []byte("tampered capsule bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	tamperedBytes, err := os.ReadFile(capsulePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBindingBytes(signed, tamperedBytes, pub); err == nil {
		t.Fatalf("expected rejection of a statement bound to now-tampered capsule bytes")
	}
}

// TestVerifyBindingBytes_TOCTOU_RejectsBytesAuthenticatedElsewhere is H1: the
// caller must bind against the EXACT bytes it already authenticated
// (Verify/VerifyCapsule), never bytes re-read from the capsule's path after
// that authentication. This proves VerifyBindingBytes takes bytes directly
// (there is no path-taking VerifyBinding left to reproduce the gap): binding
// against bytes from capsule B, even though a caller "authenticated" capsule
// A moments earlier by some other means, is correctly rejected -- the API
// makes the caller's own bytes the only thing that can ever be checked.
func TestVerifyBindingBytes_TOCTOU_RejectsBytesAuthenticatedElsewhere(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	authenticatedBytes := []byte("bytes the caller actually authenticated (capsule A)")
	swappedBytes := []byte("different bytes now sitting at the same path (capsule B)")

	sum := sha256.Sum256(authenticatedBytes)
	signed, err := Sign([]Statement{{Root: "/g"}}, hex.EncodeToString(sum[:]), priv)
	if err != nil {
		t.Fatal(err)
	}

	// Binding against the bytes actually authenticated passes.
	if err := VerifyBindingBytes(signed, authenticatedBytes, pub); err != nil {
		t.Fatalf("expected binding against the authenticated bytes to pass, got %v", err)
	}
	// Binding against a swapped buffer -- simulating a caller that mistakenly
	// re-reads the path instead of reusing the authenticated bytes -- fails
	// closed instead of silently verifying the wrong capsule.
	if err := VerifyBindingBytes(signed, swappedBytes, pub); err == nil {
		t.Fatalf("expected rejection when bound bytes differ from the authenticated bytes")
	} else if !errors.Is(err, ErrCapsuleDigestMismatch) {
		t.Fatalf("expected ErrCapsuleDigestMismatch, got %v", err)
	}
}

func TestValidateSchema_RejectsBadShapeAndVersion(t *testing.T) {
	valid := SignedStatement{SchemaVersion: SchemaVersionV1, Statements: []Statement{{Root: "/workspace"}}, PostureCapsuleSHA256: strings.Repeat("a", 64)}
	if err := ValidateSchema(valid); err != nil {
		t.Fatalf("expected valid shape to pass: %v", err)
	}
	badVersion := valid
	badVersion.SchemaVersion = "workspace-change-statement/v99"
	if err := ValidateSchema(badVersion); err == nil {
		t.Fatalf("expected rejection of unknown schema version")
	}
	badDigest := valid
	badDigest.PostureCapsuleSHA256 = "not-hex-and-wrong-length"
	if err := ValidateSchema(badDigest); err == nil {
		t.Fatalf("expected rejection of a non-digest-shaped binding")
	}
	emptyStatements := valid
	emptyStatements.Statements = nil
	if err := ValidateSchema(emptyStatements); err == nil {
		t.Fatal("expected rejection of an empty workspace statement")
	}
}

func TestVerifyRejectsInvalidTrustedKeyLength(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign([]Statement{{Root: "/workspace"}}, strings.Repeat("a", sha256.Size*2), priv)
	if err != nil {
		t.Fatalf("sign statement: %v", err)
	}
	for _, key := range []ed25519.PublicKey{pub[:ed25519.PublicKeySize-1], append(append(ed25519.PublicKey(nil), pub...), 0)} {
		signed.SignerKeyID = hex.EncodeToString(key)
		if err := Verify(signed, key); err == nil || !strings.Contains(err.Error(), "invalid trusted key length") {
			t.Fatalf("Verify(%d-byte key) error = %v, want invalid length", len(key), err)
		}
	}
}

// TestCrossedMount_Table is H3's core unit test: the comparison primitive
// crossedMount, exercised over a table of (rootMnt, entryMnt, rootOK,
// entryOK) so the "same mount", "different mount" (the actual bind-mount
// signal st_dev cannot see), and "mount id unavailable -> fall back, don't
// guess" cases are all pinned down without needing root/CAP_SYS_ADMIN to set
// up a real bind mount in CI.
func TestCrossedMount_Table(t *testing.T) {
	tests := []struct {
		name              string
		rootMnt, entryMnt uint64
		rootOK, entryOK   bool
		want              bool
	}{
		{name: "same mount id", rootMnt: 7, entryMnt: 7, rootOK: true, entryOK: true, want: false},
		{
			name:    "different mount id, same could-be device (the actual bind-mount case)",
			rootMnt: 7, entryMnt: 9, rootOK: true, entryOK: true, want: true,
		},
		{name: "root mount id unavailable", rootMnt: 0, entryMnt: 9, rootOK: false, entryOK: true, want: false},
		{name: "entry mount id unavailable", rootMnt: 7, entryMnt: 0, rootOK: true, entryOK: false, want: false},
		{name: "neither available", rootMnt: 0, entryMnt: 0, rootOK: false, entryOK: false, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := crossedMount(tt.rootMnt, tt.entryMnt, tt.rootOK, tt.entryOK); got != tt.want {
				t.Fatalf("crossedMount(%d, %d, %v, %v) = %v, want %v", tt.rootMnt, tt.entryMnt, tt.rootOK, tt.entryOK, got, tt.want)
			}
		})
	}
}

// TestSnapshot_MountBoundary_NoRealBindMount_SameMountIDByDefault documents
// the same limitation the old device-only test carried, now correctly
// scoped: it does NOT and CANNOT prove mount-boundary exclusion (that needs
// a real bind mount, root/CAP_SYS_ADMIN, unavailable in unprivileged CI --
// see docs/contain-cli.md for the manual reproduction). What it proves is
// the mount-id primitive itself: two ordinary files under the same tmpdir,
// with no bind mount involved, report the SAME mount id (or both report
// "unavailable" on a platform/kernel without STATX_MNT_ID), so crossedMount
// correctly returns false for the common, non-bind-mounted case in the same
// walk this package actually runs.
func TestSnapshot_MountBoundary_NoRealBindMount_SameMountIDByDefault(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a")
	fileB := filepath.Join(dir, "b")
	writeFile(t, fileA, "a")
	writeFile(t, fileB, "b")

	mntA, okA := mountID(fileA)
	mntB, okB := mountID(fileB)
	if okA != okB {
		t.Fatalf("mountID availability disagreed between two files in the same tmpdir: okA=%v okB=%v", okA, okB)
	}
	if !okA {
		t.Skip("mountID (STATX_MNT_ID) unavailable on this platform/kernel; falls back to statIDs, covered elsewhere")
	}
	if crossedMount(mntA, mntB, okA, okB) {
		t.Fatalf("two ordinary files in the same tmpdir with no bind mount reported crossedMount=true (mntA=%d, mntB=%d)", mntA, mntB)
	}
}

// TestSnapshot_TOCTOU_PathReplacedBySymlinkBetweenWalkAndOpen is M3: if a
// regular file is replaced by a symlink to something outside the workspace
// after the walk observed it as a regular file but before the content is
// hashed, the walk must record it unreadable (never dereference the
// symlink and hash the OUTSIDE target). This is simulated by racing a
// goroutine against the walk: since the race is inherently non-deterministic
// in a unit test, the assertion instead exercises hashFileSafe directly
// with an identity mismatch, which is the exact check the walk relies on.
func TestSnapshot_TOCTOU_IdentityMismatchRefusesToHash(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real")
	writeFile(t, realPath, "original content")
	info, err := os.Lstat(realPath)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino, ok := statIDs(info)
	if !ok {
		t.Skip("statIDs unavailable on this platform")
	}

	// Create the replacement while the original still exists, so the two
	// distinct live files must have different device/inode identities. A
	// delete-then-recreate sequence can immediately reuse the inode on a
	// filesystem whose allocator permits it, making the simulated swap
	// indistinguishable from the walked file.
	replacementPath := filepath.Join(dir, "replacement")
	writeFile(t, replacementPath, "swapped-in content")
	replacementInfo, err := os.Lstat(replacementPath)
	if err != nil {
		t.Fatal(err)
	}
	replacementDev, replacementIno, replacementOK := statIDs(replacementInfo)
	if !replacementOK {
		t.Fatal("statIDs unavailable for replacement file")
	}
	if replacementDev == dev && replacementIno == ino {
		t.Fatal("test setup produced identical identities for two live files")
	}
	if err := os.Rename(replacementPath, realPath); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	_, _, err = hashFileSafe(root, "real", realPath, 1<<20, dev, ino, true)
	if err == nil {
		t.Fatalf("expected hashFileSafe to refuse a path whose identity changed since the walk observed it")
	}
}

func TestSnapshot_TOCTOU_SymlinkSwapRefusesToHash(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside-target")
	writeFile(t, target, "secret outside the workspace")
	realPath := filepath.Join(dir, "real")
	writeFile(t, realPath, "original content")
	info, err := os.Lstat(realPath)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino, ok := statIDs(info)
	if !ok {
		t.Skip("statIDs unavailable on this platform")
	}

	if err := os.Remove(realPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, realPath); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	_, _, err = hashFileSafe(root, "real", realPath, 1<<20, dev, ino, true)
	if err == nil {
		t.Fatalf("expected hashFileSafe to refuse hashing through a symlink swapped in after the walk (os.Root should refuse the escaping symlink)")
	}
}

// TestSnapshot_BudgetExceeded_IncompleteNamesTheCap is M6.
func TestSnapshot_BudgetExceeded_IncompleteNamesTheCap(t *testing.T) {
	root := t.TempDir()
	for i := range 10 {
		writeFile(t, filepath.Join(root, fmt.Sprintf("f%d", i)), "x")
	}
	budget := Budget{MaxEntries: 3}
	m, err := Snapshot(root, 1<<20, budget)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !m.BudgetExceeded {
		t.Fatalf("expected BudgetExceeded=true with a 3-entry cap over 10+ files")
	}
	if !strings.Contains(m.BudgetReason, "3") {
		t.Fatalf("expected the reason to name the cap (3), got %q", m.BudgetReason)
	}

	st, err := Diff(m, m, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Incomplete {
		t.Fatalf("expected Incomplete=true when a snapshot's budget was exceeded")
	}
	if !strings.Contains(st.IncompleteReason, "budget") {
		t.Fatalf("expected IncompleteReason to mention the budget, got %q", st.IncompleteReason)
	}
}

// TestDiff_BudgetTruncated_SuppressesEntryLevelConclusions is M4: when a
// snapshot's walk stops early on the Budget, a path missing from one
// snapshot but present in the other proves nothing -- the walk order can
// shift between runs (here, adding "0" pushes "c" out of the 4-entry
// window it was inside during the FIRST snapshot), so an untouched path
// must never be reported as removed (or added/modified) just because the
// budget-truncated walk didn't reach it that time.
func TestDiff_BudgetTruncated_SuppressesEntryLevelConclusions(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a"), "a")
	writeFile(t, filepath.Join(root, "b"), "b")
	writeFile(t, filepath.Join(root, "c"), "c")
	writeFile(t, filepath.Join(root, "d"), "d")

	budget := Budget{MaxEntries: 4}
	before, err := Snapshot(root, 1<<20, budget)
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	if !before.BudgetExceeded {
		t.Fatalf("expected the first snapshot to hit the 4-entry budget over root+a+b+c+d")
	}
	if _, ok := before.Entries[filepath.Join(root, "c")]; !ok {
		t.Fatalf("expected the first (untruncated-by-new-file) walk to have reached c before hitting budget")
	}

	// Add a new file that sorts BEFORE "a", shifting the second walk's
	// 4-entry window so it never reaches "c" this time, even though "c"
	// was never touched.
	writeFile(t, filepath.Join(root, "0"), "0")
	after, err := Snapshot(root, 1<<20, budget)
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}
	if !after.BudgetExceeded {
		t.Fatalf("expected the second snapshot to also hit the 4-entry budget")
	}
	if _, ok := after.Entries[filepath.Join(root, "c")]; ok {
		t.Fatalf("test setup assumption broken: expected the shifted window to NOT reach c")
	}

	st, err := Diff(before, after, testNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range st.Removed {
		if p == filepath.Join(root, "c") {
			t.Fatalf("c must NOT be reported removed: it was never touched, only pushed out of a budget-truncated walk's window; got Removed=%v", st.Removed)
		}
	}
	if len(st.Added) != 0 || len(st.Removed) != 0 || len(st.Modified) != 0 {
		t.Fatalf("expected all entry-level conclusions suppressed for a budget-truncated pair, got added=%v removed=%v modified=%v", st.Added, st.Removed, st.Modified)
	}
	if !st.Incomplete {
		t.Fatalf("expected Incomplete=true")
	}
	if !strings.Contains(st.IncompleteReason, "budget") {
		t.Fatalf("expected IncompleteReason to mention the budget, got %q", st.IncompleteReason)
	}
}

// TestSnapshot_M6_IntermediateSymlinkTraversal_RefusesToHashOutside proves
// M6: O_NOFOLLOW on hashFileSafe's own final path component only ever
// protected the LAST segment. An attacker who controls an INTERMEDIATE
// directory can rename it away and replace it with a symlink pointing back
// at the real directory (or anywhere else); a walker that opens the full
// absolute path by string concatenation follows that intermediate symlink
// transparently. root.OpenFile resolves every component relative to the
// root directory handle and refuses a component that is a symlink pointing
// outside the root, so hashing root/sub/file after this swap must fail
// rather than silently succeeding through the symlink.
func TestSnapshot_M6_IntermediateSymlinkTraversal_RefusesToHashOutside(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(sub, "file")
	writeFile(t, filePath, "content")

	info, err := os.Lstat(filePath)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino, ok := statIDs(info)
	if !ok {
		t.Skip("statIDs unavailable on this platform")
	}

	// Move "sub" outside root, then symlink root/sub back at the moved
	// directory: root/sub is now an intermediate path component that is a
	// symlink. The final component ("file") is untouched and its identity
	// (dev/ino) is unchanged, so a check that only re-verifies the final
	// open's identity would NOT catch this -- only refusing to traverse the
	// symlinked intermediate component at all does.
	moved := filepath.Join(t.TempDir(), "moved-sub")
	if err := os.Rename(sub, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, sub); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rootHandle.Close() }()

	_, _, err = hashFileSafe(rootHandle, filepath.Join("sub", "file"), filePath, 1<<20, dev, ino, true)
	if err == nil {
		t.Fatalf("expected hashFileSafe to refuse traversing an intermediate path component replaced by a symlink")
	}
}

func TestHashFileSHA256_Deterministic(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x")
	writeFile(t, f, "same content")
	a, err := HashFileSHA256(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashFileSHA256(f)
	if err != nil {
		t.Fatal(err)
	}
	if a != b || a == "" {
		t.Fatalf("hash not stable: %q vs %q", a, b)
	}
}

// metadataFreeFileInfo models a filesystem entry whose platform metadata does
// not expose syscall.Stat_t. The evidence writer must report that limitation
// instead of inventing a device/inode identity.
type metadataFreeFileInfo struct{}

func (metadataFreeFileInfo) Name() string       { return "metadata-free" }
func (metadataFreeFileInfo) Size() int64        { return 0 }
func (metadataFreeFileInfo) Mode() os.FileMode  { return 0 }
func (metadataFreeFileInfo) ModTime() time.Time { return testNow }
func (metadataFreeFileInfo) IsDir() bool        { return false }
func (metadataFreeFileInfo) Sys() any           { return nil }

func TestPlatformIdentityFallbacksAreExplicit(t *testing.T) {
	if dev, ino, ok := statIDs(metadataFreeFileInfo{}); ok || dev != 0 || ino != 0 {
		t.Fatalf("statIDs without Stat_t = (%d, %d, %t), want unavailable zero identity", dev, ino, ok)
	}

	missing := filepath.Join(t.TempDir(), "missing")
	if id, ok := mountID(missing); ok || id != 0 {
		t.Fatalf("mountID(%q) = (%d, %t), want unavailable fallback", missing, id, ok)
	}
}

func TestSnapshotFailureEvidence(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "entry"), "data")
	fileRoot := filepath.Join(root, "not-a-directory")
	writeFile(t, fileRoot, "data")

	tests := []struct {
		name       string
		root       string
		cap        int64
		budget     Budget
		wantErr    string
		wantAbsent bool
		wantBudget string
	}{
		{name: "non-positive cap is refused", root: root, cap: 0, wantErr: "capBytes must be positive"},
		{name: "regular file cannot be workspace root", root: fileRoot, cap: 1, wantErr: "open root"},
		{name: "missing root is evidence not empty success", root: filepath.Join(root, "gone"), cap: 1, wantAbsent: true},
		{name: "entry budget stops enumeration", root: root, cap: 1, budget: Budget{MaxEntries: 1}, wantBudget: "entry cap"},
		{name: "path-byte budget stops enumeration", root: root, cap: 1, budget: Budget{MaxTotalPathBytes: 1}, wantBudget: "path-bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest, err := Snapshot(tt.root, tt.cap, tt.budget)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Snapshot error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Snapshot: %v", err)
			}
			if manifest.RootMissing != tt.wantAbsent {
				t.Fatalf("RootMissing = %t, want %t", manifest.RootMissing, tt.wantAbsent)
			}
			if tt.wantBudget != "" && (!manifest.BudgetExceeded || !strings.Contains(manifest.BudgetReason, tt.wantBudget)) {
				t.Fatalf("budget evidence = exceeded:%t reason:%q, want %q", manifest.BudgetExceeded, manifest.BudgetReason, tt.wantBudget)
			}
		})
	}
}

func TestSnapshotRecordsAllSupportedEntryKinds(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "regular")
	oversize := filepath.Join(root, "oversize")
	link := filepath.Join(root, "link")
	pipe := filepath.Join(root, "pipe")
	writeFile(t, regular, "small")
	writeFile(t, oversize, "larger than cap")
	if err := os.Symlink("regular", link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := makeFIFO(pipe); err != nil {
		t.Skipf("FIFO unsupported: %v", err)
	}

	manifest, err := Snapshot(root, 5, DefaultBudget())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if got := manifest.Entries[regular]; got.Kind != KindFile || got.Digest == "" {
		t.Fatalf("regular entry = %+v, want hashed file", got)
	}
	if got := manifest.Entries[oversize]; got.Kind != KindFile || !got.Oversize || got.Digest != "" {
		t.Fatalf("oversize entry = %+v, want digest-free oversize file", got)
	}
	if got := manifest.Entries[link]; got.Kind != KindSymlink || got.Target != "regular" {
		t.Fatalf("symlink entry = %+v, want recorded target", got)
	}
	if got := manifest.Entries[pipe]; got.Kind != KindOther {
		t.Fatalf("FIFO entry = %+v, want other", got)
	}
}

func TestHashFileSafeRefusesUntrustworthyReads(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	writeFile(t, path, "longer than cap")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino, haveIDs := statIDs(info)
	handle, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handle.Close() }()

	tests := []struct {
		name     string
		relPath  string
		cap      int64
		wantErr  string
		badID    bool
		oversize bool
	}{
		{name: "oversize after open is not partially hashed", relPath: "file", cap: 1, oversize: true},
		{name: "missing file reports confined open failure", relPath: "missing", cap: 20, wantErr: "root-confined"},
		{name: "directory is not accepted as a file", relPath: ".", cap: 20, wantErr: "no longer a regular file"},
		{name: "identity change is refused", relPath: "file", cap: 20, wantErr: "identity changed", badID: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// statIDs reports ok=false off unix, and hashFileSafe then skips
			// the identity comparison entirely. The read would succeed and
			// return a digest, so this case would assert an error the platform
			// can never produce.
			if tt.badID && !haveIDs {
				t.Skip("statIDs is unavailable here, so hashFileSafe cannot compare identities")
			}
			wantDev := dev
			if tt.badID {
				wantDev++
			}
			digest, oversize, hashErr := hashFileSafe(handle, tt.relPath, filepath.Join(root, tt.relPath), tt.cap, wantDev, ino, haveIDs)
			if tt.wantErr != "" {
				if hashErr == nil || !strings.Contains(hashErr.Error(), tt.wantErr) {
					t.Fatalf("hashFileSafe error = %v, want %q", hashErr, tt.wantErr)
				}
				return
			}
			if hashErr != nil || oversize != tt.oversize || digest != "" {
				t.Fatalf("hashFileSafe = digest:%q oversize:%t err:%v, want oversize evidence", digest, oversize, hashErr)
			}
		})
	}
}

func TestDiffFailsClosedForPartialEvidence(t *testing.T) {
	entry := func(path, digest string) Entry { return Entry{Path: path, Kind: KindFile, Digest: digest} }
	tests := []struct {
		name       string
		before     Manifest
		after      Manifest
		wantErr    string
		wantReason string
		wantAdded  []string
	}{
		{name: "different roots cannot be compared", before: Manifest{Root: "/one"}, after: Manifest{Root: "/two"}, wantErr: "root mismatch"},
		{name: "root absent at both ends is incomplete", before: Manifest{Root: "/work", RootMissing: true}, after: Manifest{Root: "/work", RootMissing: true}, wantReason: "did not exist"},
		{name: "root disappearing keeps unreadable evidence", before: Manifest{Root: "/work", Entries: map[string]Entry{"/work/a": entry("/work/a", "a")}, Unreadable: []UnreadableEntry{{Path: "/work/hidden", Reason: "denied"}}}, after: Manifest{Root: "/work", RootMissing: true, Unreadable: []UnreadableEntry{{Path: "/work/hidden", Reason: "changed"}}}, wantReason: "no longer exists"},
		{name: "unreadable subtree is excluded while visible changes remain", before: Manifest{Root: "/work", Entries: map[string]Entry{}}, after: Manifest{Root: "/work", Entries: map[string]Entry{"/work/hidden/new": entry("/work/hidden/new", "n"), "/work/visible": entry("/work/visible", "v")}, Unreadable: []UnreadableEntry{{Path: "/work/hidden", Reason: "denied"}}}, wantReason: "unreadable", wantAdded: []string{"/work/visible"}},
		{name: "budget truncation suppresses all path conclusions", before: Manifest{Root: "/work", Entries: map[string]Entry{}}, after: Manifest{Root: "/work", Entries: map[string]Entry{"/work/new": entry("/work/new", "n")}, BudgetExceeded: true, BudgetReason: "entry cap"}, wantReason: "budget exceeded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statement, err := Diff(tt.before, tt.after, testNow)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Diff error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Diff: %v", err)
			}
			if !statement.Incomplete || !strings.Contains(statement.IncompleteReason, tt.wantReason) {
				t.Fatalf("statement = %+v, want incomplete reason containing %q", statement, tt.wantReason)
			}
			assertPaths(t, "added", statement.Added, tt.wantAdded...)
		})
	}
}

func TestVerifyRejectsMalformedEvidence(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	capsule := sha256.Sum256([]byte("capsule"))
	signed, err := Sign([]Statement{{Root: "/workspace"}}, hex.EncodeToString(capsule[:]), priv)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(SignedStatement) SignedStatement
		want string
	}{
		{name: "empty signature", edit: func(s SignedStatement) SignedStatement { s.Signature = ""; return s }, want: "signature is empty"},
		{name: "wrong signer identity", edit: func(s SignedStatement) SignedStatement { s.SignerKeyID = "00"; return s }, want: "does not match trusted key"},
		{name: "non-hex signature", edit: func(s SignedStatement) SignedStatement { s.Signature = "zz"; return s }, want: "decode signature"},
		{name: "short signature", edit: func(s SignedStatement) SignedStatement { s.Signature = "00"; return s }, want: "invalid signature length"},
		{name: "signature fails verification", edit: func(s SignedStatement) SignedStatement {
			s.Signature = strings.Repeat("00", ed25519.SignatureSize)
			return s
		}, want: "verification failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify(tt.edit(signed), pub)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Verify error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestEvidenceValidationRejectsMalformedBindingAndOutputPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	capsule := sha256.Sum256([]byte("capsule"))
	signed, err := Sign([]Statement{{Root: "/workspace"}}, hex.EncodeToString(capsule[:]), priv)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		signed SignedStatement
		verify bool
		want   string
	}{
		{name: "unknown schema is refused", signed: SignedStatement{}, verify: true, want: "unknown schema_version"},
		{name: "non-hex capsule binding is refused", signed: func() SignedStatement {
			s := signed
			s.PostureCapsuleSHA256 = strings.Repeat("z", sha256.Size*2)
			return s
		}(), verify: true, want: "not valid hex"},
		{name: "binding wraps signature failure", signed: SignedStatement{}, want: "statement signature"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotErr error
			if tt.verify {
				gotErr = Verify(tt.signed, pub)
			} else {
				gotErr = VerifyBindingBytes(tt.signed, []byte("capsule"), pub)
			}
			if gotErr == nil || !strings.Contains(gotErr.Error(), tt.want) {
				t.Fatalf("validation error = %v, want %q", gotErr, tt.want)
			}
		})
	}

	outputFile := filepath.Join(t.TempDir(), "not-a-directory")
	writeFile(t, outputFile, "file")
	if _, err := WriteJSON(outputFile, signed); err == nil || !strings.Contains(err.Error(), "create output dir") {
		t.Fatalf("WriteJSON output-root error = %v, want create output dir refusal", err)
	}
}

func TestEntryChangedTreatsUnverifiableMetadataAsChanged(t *testing.T) {
	baseTime := testNow
	tests := []struct {
		name   string
		before Entry
		after  Entry
		want   bool
	}{
		{name: "kind changes", before: Entry{Kind: KindDir}, after: Entry{Kind: KindFile}, want: true},
		{name: "symlink target changes", before: Entry{Kind: KindSymlink, Target: "one"}, after: Entry{Kind: KindSymlink, Target: "two"}, want: true},
		{name: "oversize size changes", before: Entry{Kind: KindFile, Oversize: true, Size: 1, ModTime: baseTime}, after: Entry{Kind: KindFile, Oversize: true, Size: 2, ModTime: baseTime}, want: true},
		{name: "other mtime changes", before: Entry{Kind: KindOther, Size: 1, ModTime: baseTime}, after: Entry{Kind: KindOther, Size: 1, ModTime: baseTime.Add(time.Second)}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := entryChanged(tt.before, tt.after); got != tt.want {
				t.Fatalf("entryChanged(%+v, %+v) = %t, want %t", tt.before, tt.after, got, tt.want)
			}
		})
	}
}

func TestHashFileSHA256RejectsMissingCapsule(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-capsule.json")
	if _, err := HashFileSHA256(missing); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("HashFileSHA256 missing error = %v, want not-exist failure", err)
	}
	if _, err := HashFileSHA256(t.TempDir()); err == nil {
		t.Fatal("HashFileSHA256 accepted a directory as capsule bytes")
	}
}

// TestSnapshot_RootStatErrorIsNotSilentlyEmpty proves a root that cannot be
// stat'd for a reason OTHER than absence returns an error rather than an empty
// manifest. An empty manifest would later diff as "nothing changed", which is
// the wrong failure direction for evidence: unreadable must never read as clean.
func TestSnapshot_RootStatErrorIsNotSilentlyEmpty(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission denial does not hold on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("root can stat through an unreadable parent")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "workspace")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	// Removing execute permission on the parent makes stat of the child fail
	// with a permission error rather than a not-exist error.
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(parent, 0o750) }()

	m, err := Snapshot(root, 1<<20, DefaultBudget())
	if err == nil {
		t.Fatalf("Snapshot = %+v, want an error when the root cannot be stat'd", m)
	}
	if m.RootMissing {
		t.Fatal("a permission failure must not be reported as a missing root")
	}
}
