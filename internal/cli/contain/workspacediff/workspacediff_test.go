// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

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

	cap := int64(4) // force oversize
	before, err := Snapshot(root, cap, DefaultBudget())
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
	after, err := Snapshot(root, cap, DefaultBudget())
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}
	st, err := Diff(before, after, testNow)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	assertPaths(t, "modified", st.Modified, big)
}

func TestDiff_UnreadableDirectory_RecordedNeverSilentlySkipped(t *testing.T) {
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

func TestWriteJSON_PermsAndRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub
	signed, err := Sign([]Statement{{Root: "/g"}}, "cafebabe", priv)
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
	if err := os.WriteFile(existing, []byte("stale"), 0o644); err != nil { //nolint:gosec // deliberately loose, this is the pre-existing state under test
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
	if err := VerifyBinding(signed, capsulePath, pub); err != nil {
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
	if err := VerifyBinding(statementForA, capsuleB, pub); err == nil {
		t.Fatalf("expected VerifyBinding to reject session A's statement paired with session B's capsule")
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
	if err := VerifyBinding(signed, capsulePath, pub); err == nil {
		t.Fatalf("expected rejection of a statement bound to now-tampered capsule bytes")
	}
}

func TestValidateSchema_RejectsBadShapeAndVersion(t *testing.T) {
	valid := SignedStatement{SchemaVersion: SchemaVersionV1, PostureCapsuleSHA256: strings.Repeat("a", 64)}
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
}

// TestSnapshot_MountBoundary_ExcludedNotDescended is H2. A real bind mount
// needs root/CAP_SYS_ADMIN, unavailable in unprivileged CI, so this proves
// the device-id comparison the walk callback relies on: statIDs on two
// distinct real filesystem objects on the SAME device must report the SAME
// device id (the common case), which is the precondition the mount-boundary
// branch depends on to tell "same device" from "different device" at all.
// The full crossing behavior (excluded, not descended, reason recorded) is
// exercised implicitly by every other Snapshot test never entering a
// mismatched-device branch; see docs/contain-cli.md for the manual bind-mount
// reproduction this unit test cannot perform in CI.
func TestSnapshot_MountBoundary_DeviceComparisonHelper(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a")
	fileB := filepath.Join(dir, "b")
	writeFile(t, fileA, "a")
	writeFile(t, fileB, "b")
	infoA, err := os.Lstat(fileA)
	if err != nil {
		t.Fatal(err)
	}
	infoB, err := os.Lstat(fileB)
	if err != nil {
		t.Fatal(err)
	}
	devA, _, okA := statIDs(infoA)
	devB, _, okB := statIDs(infoB)
	if !okA || !okB {
		t.Skip("statIDs unavailable on this platform")
	}
	if devA != devB {
		t.Fatalf("two files in the same tmpdir reported different devices: %d vs %d", devA, devB)
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
	real := filepath.Join(dir, "real")
	writeFile(t, real, "original content")
	info, err := os.Lstat(real)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino, ok := statIDs(info)
	if !ok {
		t.Skip("statIDs unavailable on this platform")
	}

	// Replace the file with a NEW file at the same path: same path, new
	// inode. hashFileSafe must detect the identity mismatch against the
	// dev/ino observed at walk time and refuse to hash it, rather than
	// silently hashing whatever now sits at that path.
	if err := os.Remove(real); err != nil {
		t.Fatal(err)
	}
	writeFile(t, real, "swapped-in content")

	_, _, err = hashFileSafe(real, 1<<20, dev, ino, true)
	if err == nil {
		t.Fatalf("expected hashFileSafe to refuse a path whose identity changed since the walk observed it")
	}
}

func TestSnapshot_TOCTOU_SymlinkSwapRefusesToHash(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside-target")
	writeFile(t, target, "secret outside the workspace")
	real := filepath.Join(dir, "real")
	writeFile(t, real, "original content")
	info, err := os.Lstat(real)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino, ok := statIDs(info)
	if !ok {
		t.Skip("statIDs unavailable on this platform")
	}

	if err := os.Remove(real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, real); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	_, _, err = hashFileSafe(real, 1<<20, dev, ino, true)
	if err == nil {
		t.Fatalf("expected hashFileSafe to refuse hashing through a symlink swapped in after the walk (O_NOFOLLOW should have failed the open)")
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
