// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package workspacediff records what changed inside a granted contain
// workspace between the start and end of a session, and emits it as a signed
// evidence statement bound to that session's posture capsule.
//
// This is evidence, not backup: no content is stored, only path/kind/size/
// mtime/digest metadata sufficient to name what changed. There is no
// snapshot store, no restore path, no dedup, no retention policy.
package workspacediff

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// EntryKind names the filesystem object kind recorded for a path. Symlinks
// are recorded by their own kind and are never followed: their target is not
// read, hashed, or descended into.
type EntryKind string

const (
	KindFile    EntryKind = "file"
	KindDir     EntryKind = "dir"
	KindSymlink EntryKind = "symlink"
	KindOther   EntryKind = "other"
)

// Entry is one path's recorded state at snapshot time.
type Entry struct {
	Path     string    `json:"path"`
	Kind     EntryKind `json:"kind"`
	Size     int64     `json:"size"`
	ModTime  time.Time `json:"mod_time"`
	Digest   string    `json:"digest,omitempty"`         // sha256 hex, regular files under the cap only
	Oversize bool      `json:"oversize,omitempty"`       // regular file exceeded the digest cap; no digest computed
	Target   string    `json:"symlink_target,omitempty"` // recorded, never followed
}

// UnreadableEntry names a path that could not be fully recorded, and why:
// permission denial, a TOCTOU identity change caught between walk and open,
// or a crossed mount boundary that was deliberately not descended into.
type UnreadableEntry struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Budget bounds how much a single Snapshot will walk, so a hostile or
// pathological workspace (a fork bomb of files, a symlink-driven blowup)
// cannot make evidence collection itself unbounded. These are local
// operational limits Pipelock chose, not a standard: see docs/contain-cli.md.
type Budget struct {
	// MaxEntries is the total number of filesystem objects (of any kind)
	// Snapshot will record before stopping. Zero means unlimited.
	MaxEntries int
	// MaxTotalPathBytes is the total number of path-string bytes Snapshot
	// will accumulate across all visited entries before stopping. Zero means
	// unlimited. This bounds pathological deep/wide trees independently of
	// entry count.
	MaxTotalPathBytes int64
}

// BoundaryCheck identifies the strength of the mount-boundary check used for
// a workspace snapshot. A device-only check cannot detect a bind mount on the
// same filesystem, so it must never be presented as mount-ID coverage.
type BoundaryCheck string

const (
	BoundaryCheckMountID    BoundaryCheck = "mount-id"
	BoundaryCheckDeviceOnly BoundaryCheck = "device-only"
)

// DefaultBudget returns Pipelock's local default snapshot budget: 200,000
// entries or 64 MiB of cumulative path bytes, whichever is hit first. Both
// are conservative operational defaults, not derived from any external
// specification.
func DefaultBudget() Budget {
	return Budget{MaxEntries: 200_000, MaxTotalPathBytes: 64 << 20}
}

// Manifest is the recorded state of a granted workspace at one point in time.
type Manifest struct {
	Root          string            `json:"root"`
	CapBytes      int64             `json:"cap_bytes"`
	BoundaryCheck BoundaryCheck     `json:"boundary_check"`
	RootMissing   bool              `json:"root_missing"`
	Entries       map[string]Entry  `json:"entries"`
	Unreadable    []UnreadableEntry `json:"unreadable"` // paths not fully recorded, with why
	unreadableOf  map[string]struct{}

	// BudgetExceeded/BudgetReason record that the walk stopped early because
	// it hit the Budget passed to Snapshot, rather than because the
	// workspace was fully enumerated.
	BudgetExceeded bool   `json:"budget_exceeded,omitempty"`
	BudgetReason   string `json:"budget_reason,omitempty"`

	entryCount     int
	totalPathBytes int64
}

// Snapshot walks root and records every entry's metadata. Regular files at or
// under capBytes get a sha256 content digest read through a symlink-safe,
// identity-checked open (see hashFileSafe); larger regular files are recorded
// with Oversize=true and no digest, never partially hashed. Directories the
// caller cannot read, directories that cross a mount boundary out of root,
// and files whose identity changed between listing and opening are all
// recorded as Unreadable with a reason, never silently skipped or descended
// into. A missing root is not an error: it is recorded as RootMissing so the
// caller can produce a fail-closed statement instead of an empty diff. The
// walk stops early, with BudgetExceeded set, if it exceeds budget.
func Snapshot(root string, capBytes int64, budget Budget) (Manifest, error) {
	if capBytes <= 0 {
		return Manifest{}, errors.New("workspacediff: capBytes must be positive")
	}
	cleanRoot := filepath.Clean(root)
	m := Manifest{
		Root:         cleanRoot,
		CapBytes:     capBytes,
		Entries:      make(map[string]Entry),
		unreadableOf: make(map[string]struct{}),
	}

	rootInfo, err := os.Lstat(cleanRoot)
	if err != nil {
		if os.IsNotExist(err) {
			m.RootMissing = true
			return m, nil
		}
		return Manifest{}, fmt.Errorf("workspacediff: stat root %s: %w", cleanRoot, err)
	}
	// M6: os.Root confines every subsequent open to cleanRoot's directory
	// tree using the OS's per-component (openat-family) resolution, so a
	// symlink swapped into an INTERMEDIATE path component between the walk
	// observing a path and hashFileSafe opening it cannot smuggle the open
	// outside the workspace -- O_NOFOLLOW on the final component alone
	// (openRegularNoFollow) only ever protected the last path segment.
	rootHandle, err := os.OpenRoot(cleanRoot)
	if err != nil {
		return Manifest{}, fmt.Errorf("workspacediff: open root %s: %w", cleanRoot, err)
	}
	defer func() { _ = rootHandle.Close() }()
	rootDev, _, rootDevOK := statIDs(rootInfo)
	// H3: st_dev alone cannot see a directory bind-mounted from elsewhere on
	// the SAME filesystem (identical st_dev, different mount). Mount ID
	// (Linux statx STATX_MNT_ID) does; consult it for every entry -- files
	// included, not only directories -- falling back to the device check
	// only when the kernel doesn't report a mount ID.
	rootMnt, rootMntOK := mountID(cleanRoot)
	if rootMntOK {
		m.BoundaryCheck = BoundaryCheckMountID
	} else {
		m.BoundaryCheck = BoundaryCheckDeviceOnly
	}

	walkErr := filepath.WalkDir(cleanRoot, func(path string, d fs.DirEntry, err error) error {
		m.entryCount++
		m.totalPathBytes += int64(len(path))
		if budget.MaxEntries > 0 && m.entryCount > budget.MaxEntries {
			m.BudgetExceeded = true
			m.BudgetReason = fmt.Sprintf("exceeded max entry cap (%d entries)", budget.MaxEntries)
			return filepath.SkipAll
		}
		if budget.MaxTotalPathBytes > 0 && m.totalPathBytes > budget.MaxTotalPathBytes {
			m.BudgetExceeded = true
			m.BudgetReason = fmt.Sprintf("exceeded max total path-bytes cap (%d bytes)", budget.MaxTotalPathBytes)
			return filepath.SkipAll
		}

		if err != nil {
			m.markUnreadable(path, fmt.Sprintf("read error: %v", err))
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			m.markUnreadable(path, fmt.Sprintf("stat error: %v", err))
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		mode := info.Mode()
		// Mount-boundary check applied to EVERY non-root entry regardless of
		// kind (H3): a bind-mounted regular file, not just a bind-mounted
		// directory, must be excluded rather than silently treated as part
		// of this workspace.
		if path != cleanRoot && mode&os.ModeSymlink == 0 {
			crossed := false
			if entryMnt, entryOK := mountID(path); crossedMount(rootMnt, entryMnt, rootMntOK, entryOK) {
				crossed = true
			} else if !rootMntOK || !entryOK {
				m.BoundaryCheck = BoundaryCheckDeviceOnly
				if rootDevOK {
					if dev, _, ok := statIDs(info); ok && dev != rootDev {
						crossed = true
					}
				}
			}
			if crossed {
				m.markUnreadable(path, "crossed a mount boundary; excluded, not descended into")
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		switch {
		case mode&os.ModeSymlink != 0:
			target, rerr := os.Readlink(path)
			if rerr != nil {
				m.markUnreadable(path, fmt.Sprintf("readlink error: %v", rerr))
				return nil
			}
			m.Entries[path] = Entry{Path: path, Kind: KindSymlink, Size: info.Size(), ModTime: info.ModTime(), Target: target}
		case d.IsDir():
			m.Entries[path] = Entry{Path: path, Kind: KindDir, ModTime: info.ModTime()}
		case mode.IsRegular():
			e := Entry{Path: path, Kind: KindFile, Size: info.Size(), ModTime: info.ModTime()}
			if info.Size() > capBytes {
				e.Oversize = true
			} else {
				wantDev, wantIno, haveIDs := statIDsWithInode(info)
				relPath, relErr := filepath.Rel(cleanRoot, path)
				if relErr != nil {
					m.markUnreadable(path, fmt.Sprintf("could not safely hash: %v", relErr))
					return nil
				}
				digest, oversize, herr := hashFileSafe(rootHandle, relPath, path, capBytes, wantDev, wantIno, haveIDs)
				if herr != nil {
					m.markUnreadable(path, fmt.Sprintf("could not safely hash: %v", herr))
					return nil
				}
				if oversize {
					e.Oversize = true
				} else {
					e.Digest = digest
				}
			}
			m.Entries[path] = e
		default:
			m.Entries[path] = Entry{Path: path, Kind: KindOther, Size: info.Size(), ModTime: info.ModTime()}
		}
		return nil
	})
	if walkErr != nil {
		return Manifest{}, fmt.Errorf("workspacediff: walk %s: %w", cleanRoot, walkErr)
	}
	sort.Slice(m.Unreadable, func(i, j int) bool { return m.Unreadable[i].Path < m.Unreadable[j].Path })
	return m, nil
}

func (m *Manifest) markUnreadable(path, reason string) {
	if _, ok := m.unreadableOf[path]; ok {
		return
	}
	if m.unreadableOf == nil {
		m.unreadableOf = make(map[string]struct{})
	}
	m.unreadableOf[path] = struct{}{}
	m.Unreadable = append(m.Unreadable, UnreadableEntry{Path: path, Reason: reason})
}

// hashFileSafe reads path's content digest through a symlink-safe open. It
// re-checks the opened descriptor's identity (device+inode) against what the
// walk observed and refuses to hash a path whose identity changed between
// listing and opening (a TOCTOU race: e.g. a file replaced by a symlink to a
// secret outside the workspace). Content is read through a length-capped
// reader so an attacker cannot force reading past capBytes even if the file
// grew after the size check.
func hashFileSafe(root *os.Root, relPath, path string, capBytes int64, wantDev, wantIno uint64, haveIDs bool) (digest string, oversize bool, err error) {
	f, err := root.OpenFile(relPath, os.O_RDONLY, 0)
	if err != nil {
		return "", false, fmt.Errorf("open %s (root-confined): %w", path, err)
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return "", false, fmt.Errorf("stat opened descriptor for %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return "", false, fmt.Errorf("%s is no longer a regular file (possible TOCTOU)", path)
	}
	if haveIDs {
		if dev, ino, ok := statIDs(fi); ok && (dev != wantDev || ino != wantIno) {
			return "", false, fmt.Errorf("%s identity changed between walk and open (possible TOCTOU)", path)
		}
	}

	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, capBytes+1))
	if err != nil {
		return "", false, fmt.Errorf("read %s: %w", path, err)
	}
	if n > capBytes {
		return "", true, nil
	}
	return hex.EncodeToString(h.Sum(nil)), false, nil
}

// statIDsWithInode is a small alias kept separate from statIDs used for the
// mount-boundary check so callers reading the mount check can't confuse a
// device-only comparison with the device+inode identity check used for
// TOCTOU detection; both currently share one platform implementation.
func statIDsWithInode(fi os.FileInfo) (dev, ino uint64, ok bool) {
	return statIDs(fi)
}

func hashFile(path string) (string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Counts summarizes a Statement's changed-entry tallies.
type Counts struct {
	Added      int `json:"added"`
	Removed    int `json:"removed"`
	Modified   int `json:"modified"`
	Unreadable int `json:"unreadable"`
}

// Statement is what changed inside a granted workspace between two
// snapshots, bound to the session whose posture capsule digest it carries.
// It is evidence only: it names paths, never carries file content.
type Statement struct {
	Root               string            `json:"root"`
	CapBytes           int64             `json:"cap_bytes"`
	BoundaryCheck      BoundaryCheck     `json:"boundary_check"`
	GeneratedAt        time.Time         `json:"generated_at"`
	RootMissingAtStart bool              `json:"root_missing_at_start"`
	RootMissingAtEnd   bool              `json:"root_missing_at_end"`
	Incomplete         bool              `json:"incomplete"`
	IncompleteReason   string            `json:"incomplete_reason,omitempty"`
	Added              []string          `json:"added"`
	Removed            []string          `json:"removed"`
	Modified           []string          `json:"modified"`
	Unreadable         []UnreadableEntry `json:"unreadable"`
	Counts             Counts            `json:"counts"`
}

// Diff compares a before/after snapshot pair of the SAME root and reports
// what changed. If the workspace root disappeared between snapshots, the
// statement says so explicitly (Incomplete=true) rather than reporting an
// empty diff. Any path unreadable in either snapshot (permission denial, a
// crossed mount, or a caught TOCTOU race) is EXCLUDED, along with its entire
// subtree, from Added/Removed/Modified: a directory that became unreadable
// mid-session must never make its still-present descendants look "removed."
// Whenever any such path exists, or a snapshot's walk budget was exceeded,
// the statement sets Incomplete=true and says why, so "nothing reported" can
// never be confused with "nothing observed."
func Diff(before, after Manifest, now time.Time) (Statement, error) {
	if before.Root != after.Root {
		return Statement{}, fmt.Errorf("workspacediff: root mismatch: before=%s after=%s", before.Root, after.Root)
	}
	st := Statement{
		Root:               before.Root,
		CapBytes:           before.CapBytes,
		BoundaryCheck:      boundaryCheckFor(before, after),
		GeneratedAt:        now,
		RootMissingAtStart: before.RootMissing,
		RootMissingAtEnd:   after.RootMissing,
	}

	boundaryReason := ""
	if st.BoundaryCheck == BoundaryCheckDeviceOnly {
		boundaryReason = "mount boundary check unavailable on this kernel"
	}
	if after.RootMissing && !before.RootMissing {
		st.Incomplete = true
		st.IncompleteReason = joinIncompleteReasons(boundaryReason, "workspace root no longer exists at session end; cannot enumerate changes")
		st.Unreadable = mergeUnreadable(before.Unreadable, after.Unreadable)
		st.Counts.Unreadable = len(st.Unreadable)
		return st, nil
	}
	if before.RootMissing && after.RootMissing {
		st.Incomplete = true
		st.IncompleteReason = joinIncompleteReasons(boundaryReason, "workspace root did not exist at session start or end")
		return st, nil
	}

	excluded := excludedPrefixes(before.Unreadable, after.Unreadable)

	// M4: if EITHER snapshot's walk stopped early on the Budget, a path's
	// presence in one snapshot but not the other proves nothing -- the walk
	// may simply not have reached it that time (its ORDER can shift between
	// the two walks, e.g. a new path sorting ahead of it), not that it was
	// actually added, removed, or modified. Reporting entry-level
	// conclusions from a budget-truncated pair would silently misreport an
	// untouched path as removed. Suppress ALL entry-level conclusions in
	// that case; the operator still gets accurate counts (zero, since none
	// are trustworthy) and an explicit Incomplete reason naming why.
	budgetTruncated := before.BudgetExceeded || after.BudgetExceeded
	if !budgetTruncated {
		beforeEntries := before.Entries
		afterEntries := after.Entries
		seen := make(map[string]struct{}, len(beforeEntries)+len(afterEntries))
		for p := range beforeEntries {
			seen[p] = struct{}{}
		}
		for p := range afterEntries {
			seen[p] = struct{}{}
		}
		for p := range seen {
			if withinExcluded(p, excluded) {
				continue
			}
			b, inBefore := beforeEntries[p]
			a, inAfter := afterEntries[p]
			switch {
			case inBefore && !inAfter:
				st.Removed = append(st.Removed, p)
			case !inBefore && inAfter:
				st.Added = append(st.Added, p)
			case inBefore && inAfter && entryChanged(b, a):
				st.Modified = append(st.Modified, p)
			}
		}
		sort.Strings(st.Added)
		sort.Strings(st.Removed)
		sort.Strings(st.Modified)
	}
	st.Unreadable = mergeUnreadable(before.Unreadable, after.Unreadable)
	st.Counts = Counts{
		Added:      len(st.Added),
		Removed:    len(st.Removed),
		Modified:   len(st.Modified),
		Unreadable: len(st.Unreadable),
	}

	var reasons []string
	if boundaryReason != "" {
		reasons = append(reasons, boundaryReason)
	}
	if len(st.Unreadable) > 0 {
		reasons = append(reasons, fmt.Sprintf(
			"%d path(s) unreadable, mount-excluded, or identity-changed; their subtrees are omitted from added/removed/modified rather than reported as changed",
			len(st.Unreadable)))
	}
	if budgetTruncated {
		reason := before.BudgetReason
		if after.BudgetExceeded {
			reason = after.BudgetReason
		}
		reasons = append(reasons, fmt.Sprintf(
			"snapshot budget exceeded: %s; added/removed/modified are suppressed entirely because a partial walk cannot distinguish an untouched path from a real change",
			reason))
	}
	if len(reasons) > 0 {
		st.Incomplete = true
		st.IncompleteReason = strings.Join(reasons, "; ")
	}
	return st, nil
}

func boundaryCheckFor(before, after Manifest) BoundaryCheck {
	if before.BoundaryCheck == BoundaryCheckDeviceOnly || after.BoundaryCheck == BoundaryCheckDeviceOnly {
		return BoundaryCheckDeviceOnly
	}
	return BoundaryCheckMountID
}

func joinIncompleteReasons(reasons ...string) string {
	filtered := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		if reason != "" {
			filtered = append(filtered, reason)
		}
	}
	return strings.Join(filtered, "; ")
}

func excludedPrefixes(a, b []UnreadableEntry) []string {
	set := make(map[string]struct{}, len(a)+len(b))
	for _, e := range a {
		set[e.Path] = struct{}{}
	}
	for _, e := range b {
		set[e.Path] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// withinExcluded reports whether p is an excluded path itself or lies inside
// one of its subtrees.
func withinExcluded(p string, excluded []string) bool {
	for _, prefix := range excluded {
		if p == prefix || strings.HasPrefix(p, prefix+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func mergeUnreadable(a, b []UnreadableEntry) []UnreadableEntry {
	byPath := make(map[string]string, len(a)+len(b))
	order := make([]string, 0, len(a)+len(b))
	add := func(entries []UnreadableEntry) {
		for _, e := range entries {
			if existing, ok := byPath[e.Path]; ok {
				if existing != e.Reason && e.Reason != "" && !strings.Contains(existing, e.Reason) {
					byPath[e.Path] = existing + "; " + e.Reason
				}
				continue
			}
			byPath[e.Path] = e.Reason
			order = append(order, e.Path)
		}
	}
	add(a)
	add(b)
	sort.Strings(order)
	out := make([]UnreadableEntry, 0, len(order))
	for _, p := range order {
		out = append(out, UnreadableEntry{Path: p, Reason: byPath[p]})
	}
	return out
}

func entryChanged(b, a Entry) bool {
	if b.Kind != a.Kind {
		return true
	}
	switch a.Kind {
	case KindSymlink:
		return b.Target != a.Target
	case KindFile:
		// An oversize file (either snapshot) can never be compared by digest;
		// treat any size or mtime movement as a change rather than silently
		// declaring it unchanged.
		if b.Oversize || a.Oversize {
			return b.Size != a.Size || !b.ModTime.Equal(a.ModTime)
		}
		return b.Digest != a.Digest
	case KindDir:
		return false
	default:
		return b.Size != a.Size || !b.ModTime.Equal(a.ModTime)
	}
}

// SignedStatement is the on-disk evidence artifact: the statement plus its
// binding to the session's posture capsule and the ed25519 signature over the
// canonical JSON encoding of everything except the signature itself.
type SignedStatement struct {
	SchemaVersion        string      `json:"schema_version"`
	Statements           []Statement `json:"statements"`
	PostureCapsuleSHA256 string      `json:"posture_capsule_sha256"`
	SignerKeyID          string      `json:"signer_key_id"`
	Signature            string      `json:"signature"`
}

const SchemaVersionV1 = "workspace-change-statement/v1"

// Sign binds sts (one Statement per granted workspace root) to the posture
// capsule identified by capsuleSHA256 (the SAME session's signed posture
// capsule, hex sha256 of its bytes) and signs the result with privKey. It
// does not touch internal/receipt or internal/posture: it is a second,
// independent artifact that references the session's posture capsule by
// digest rather than extending its schema.
func Sign(sts []Statement, capsuleSHA256 string, privKey ed25519.PrivateKey) (SignedStatement, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return SignedStatement{}, fmt.Errorf("workspacediff: invalid signing key length: got %d, want %d", len(privKey), ed25519.PrivateKeySize)
	}
	if capsuleSHA256 == "" {
		return SignedStatement{}, errors.New("workspacediff: capsuleSHA256 is required to bind the statement to its session")
	}
	signed := SignedStatement{
		SchemaVersion:        SchemaVersionV1,
		Statements:           sts,
		PostureCapsuleSHA256: capsuleSHA256,
		SignerKeyID:          hex.EncodeToString(privKey.Public().(ed25519.PublicKey)),
	}
	payload, err := signablePayload(signed)
	if err != nil {
		return SignedStatement{}, err
	}
	signed.Signature = hex.EncodeToString(ed25519.Sign(privKey, payload))
	return signed, nil
}

// ValidateSchema checks a statement carries a known schema version and a
// digest-shaped (64 lowercase-or-uppercase hex char) capsule binding, before
// any cryptographic verification runs.
func ValidateSchema(signed SignedStatement) error {
	if signed.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("workspacediff: unknown schema_version %q, want %q", signed.SchemaVersion, SchemaVersionV1)
	}
	if len(signed.PostureCapsuleSHA256) != sha256.Size*2 {
		return fmt.Errorf("workspacediff: posture_capsule_sha256 must be a %d-hex-char sha256 digest, got %d chars", sha256.Size*2, len(signed.PostureCapsuleSHA256))
	}
	if _, err := hex.DecodeString(signed.PostureCapsuleSHA256); err != nil {
		return fmt.Errorf("workspacediff: posture_capsule_sha256 is not valid hex: %w", err)
	}
	return nil
}

// Verify checks a SignedStatement's schema, then its signature against
// trustedKey and that SignerKeyID matches it (defense-in-depth consistency
// check, same pattern as the posture capsule verifier). Verify alone proves
// only that the statement itself is authentic; it does NOT prove the
// statement belongs to any particular posture capsule. Use VerifyBinding to
// check that too.
func Verify(signed SignedStatement, trustedKey ed25519.PublicKey) error {
	if err := ValidateSchema(signed); err != nil {
		return err
	}
	if signed.Signature == "" {
		return errors.New("workspacediff: signature is empty")
	}
	expectedKeyID := hex.EncodeToString(trustedKey)
	if signed.SignerKeyID != expectedKeyID {
		return fmt.Errorf("workspacediff: signer_key_id %q does not match trusted key", signed.SignerKeyID)
	}
	sig, err := hex.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("workspacediff: decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("workspacediff: invalid signature length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
	unsigned := signed
	unsigned.Signature = ""
	payload, err := signablePayload(unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(trustedKey, payload, sig) {
		return errors.New("workspacediff: signature verification failed")
	}
	return nil
}

// ErrCapsuleDigestMismatch means a signed statement and a posture capsule
// file were both individually valid, but do not belong to the same session:
// the statement's posture_capsule_sha256 does not equal the sha256 of the
// capsule file's actual bytes.
var ErrCapsuleDigestMismatch = errors.New("workspacediff: statement is not bound to this capsule file")

// VerifyBindingBytes is the ONLY check that proves a statement and a posture
// capsule are from the same session. Verify alone checks just the
// statement's own signature, which a statement from an unrelated session
// still passes; VerifyBindingBytes additionally hashes capsuleBytes and
// requires that digest to equal the statement's declared
// posture_capsule_sha256.
//
// capsuleBytes MUST be the exact bytes the caller already authenticated
// (e.g. the buffer VerifyCapsule ran against), never bytes re-read from the
// capsule's path after that authentication: hashing a freshly re-opened path
// here would authenticate one set of bytes and bind against a possibly
// different set read moments later (TOCTOU), letting a capsule swapped in
// between the two reads pass binding it was never checked against. There is
// deliberately no path-taking variant of this function so no caller can
// reproduce that gap.
func VerifyBindingBytes(signed SignedStatement, capsuleBytes []byte, trustedKey ed25519.PublicKey) error {
	if err := Verify(signed, trustedKey); err != nil {
		return fmt.Errorf("statement signature: %w", err)
	}
	sum := sha256.Sum256(capsuleBytes)
	capsuleHash := hex.EncodeToString(sum[:])
	if !strings.EqualFold(capsuleHash, signed.PostureCapsuleSHA256) {
		return fmt.Errorf("%w: capsule bytes hash=%s, statement binds to=%s", ErrCapsuleDigestMismatch, capsuleHash, signed.PostureCapsuleSHA256)
	}
	return nil
}

func signablePayload(signed SignedStatement) ([]byte, error) {
	unsigned := signed
	unsigned.Signature = ""
	b, err := json.Marshal(unsigned)
	if err != nil {
		return nil, fmt.Errorf("workspacediff: marshal signable payload: %w", err)
	}
	return b, nil
}

// WriteJSON atomically writes signed as indented JSON at 0o600 inside
// outputDir (0o750), named workspace-change-statement.json, returning the
// written path. Atomic write-then-rename, mirroring
// posture.WriteProofJSON, so an existing file at the destination (however it
// got its permissions) never survives with stale content or a stale mode: a
// fresh 0o600 file always replaces it.
func WriteJSON(outputDir string, signed SignedStatement) (string, error) {
	cleanDir := filepath.Clean(outputDir)
	if err := os.MkdirAll(cleanDir, 0o750); err != nil {
		return "", fmt.Errorf("workspacediff: create output dir: %w", err)
	}
	data, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return "", fmt.Errorf("workspacediff: marshal signed statement: %w", err)
	}
	data = append(data, '\n')
	path := filepath.Join(cleanDir, "workspace-change-statement.json")
	tmp, err := os.CreateTemp(cleanDir, ".workspace-change-statement-*.tmp")
	if err != nil {
		return "", fmt.Errorf("workspacediff: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("workspacediff: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("workspacediff: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("workspacediff: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return "", fmt.Errorf("workspacediff: rename into place %s: %w", path, err)
	}
	return path, nil
}

// HashFileSHA256 returns the hex sha256 digest of the file at path, used to
// bind a statement to the exact posture capsule bytes this session wrote.
func HashFileSHA256(path string) (string, error) {
	return hashFile(path)
}
