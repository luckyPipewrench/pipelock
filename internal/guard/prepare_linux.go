// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// preparedRule is one pinned filesystem object and the rights it will carry.
//
// The descriptor is the point of the whole design. A Landlock rule built from
// a path string re-resolves that string at ruleset-build time, which reopens
// the window between the floor check and the grant: the name can be pointed
// somewhere else in between, and the rule lands on the attacker's target. A
// descriptor names an inode, so once it is pinned the name is irrelevant.
// Proven on Linux 7.1.5: after a grant, repointing the symlink it was declared
// through leaves the workload denied through that same pathname, with no
// writes reaching either target.
type preparedRule struct {
	fd       int
	access   uint64
	declared string
	kind     AccessKind
	// resolved and isDir exist so the post-enforcement reachability check can
	// re-open by NAME. Probing through fd would always succeed, because a
	// descriptor opened before the restriction stays usable after it.
	resolved string
	isDir    bool
}

// PreparedManifest holds pinned descriptors for every grantable path. It owns
// file descriptors, so Close is mandatory on every path out, including the
// error paths.
type PreparedManifest struct {
	// mu guards rules against a concurrent Close during Apply.
	//
	// Close closes each descriptor and writes -1 over it. Without this lock a
	// Close racing Apply could leave Apply handing a stale descriptor NUMBER to
	// the kernel, and if any other goroutine opened a file in that window the
	// number could have been reused, so the ruleset would grant an unrelated
	// object. The window is small and the outcome is a wrong grant, which is the
	// kind of defect that does not announce itself.
	mu       sync.Mutex
	applied  bool
	rules    []preparedRule
	outcomes []PathOutcome
	complete bool
}

// Outcomes returns the per-path dispositions, including the paths that
// produced no rule.
func (p *PreparedManifest) Outcomes() []PathOutcome {
	out := make([]PathOutcome, len(p.outcomes))
	copy(out, p.outcomes)
	return out
}

// Complete reports whether every declared path was granted.
func (p *PreparedManifest) Complete() bool { return p.complete }

// Close releases every pinned descriptor.
//
// A nil receiver is valid. Prepare returns a nil manifest when planning fails,
// and its contract tells callers to Close the result even on error, so the
// documented usage would otherwise panic on exactly the path where something
// has already gone wrong.
func (p *PreparedManifest) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var firstErr error
	for i := range p.rules {
		if p.rules[i].fd < 0 {
			continue
		}
		if err := unix.Close(p.rules[i].fd); err != nil && firstErr == nil {
			firstErr = err
		}
		p.rules[i].fd = -1
	}
	return firstErr
}

// Landlock filesystem right sets.
//
// These are composed here rather than borrowed from go-landlock's RODirs/RWDirs
// helpers because those helpers only accept path strings, which is precisely
// the reopen-by-name behaviour this package exists to avoid.
//
// Two deliberate departures from the library's defaults:
//
//   - Refer IS granted on writable directories. Without it rename(2) between
//     directories fails, which breaks write-to-temp-then-rename -- the standard
//     way careful software avoids leaving a half-written file behind. Omitting
//     it would push workloads toward writing in place, which is worse for the
//     operator and no safer for us.
//   - ResolveUnix is NOT granted, so connect(2) on a pathname Unix socket
//     inside a writable directory is denied. A writable state directory is not
//     a statement that the workload may speak to whatever is listening there.
//     This is only meaningful from SocketMediationABI; below it the right
//     cannot be requested and the record reports partial coverage.
//
// Device-node creation (MakeChar, MakeBlock) is withheld everywhere. A workload
// that can mknod a block device inside its own state directory can read the
// underlying disk, which would route around every path rule above it.
// The bits come from go-landlock's syscall package rather than x/sys/unix.
// x/sys v0.46.0 stops at LANDLOCK_ACCESS_FS_IOCTL_DEV and does not define the
// ABI 9 resolve-unix bit at all, so sourcing them from x/sys would make the
// socket restriction silently unexpressible -- the handled-access mask below
// would omit it, and connect(2) would go unmediated exactly as it does today.
const (
	rightsReadFile = llsys.AccessFSExecute |
		llsys.AccessFSReadFile

	rightsReadDir = llsys.AccessFSExecute |
		llsys.AccessFSReadFile |
		llsys.AccessFSReadDir

	rightsWriteFile = llsys.AccessFSReadFile |
		llsys.AccessFSWriteFile |
		llsys.AccessFSTruncate

	rightsWriteDir = llsys.AccessFSExecute |
		llsys.AccessFSReadFile |
		llsys.AccessFSWriteFile |
		llsys.AccessFSReadDir |
		llsys.AccessFSRemoveDir |
		llsys.AccessFSRemoveFile |
		llsys.AccessFSMakeDir |
		llsys.AccessFSMakeReg |
		llsys.AccessFSMakeSock |
		llsys.AccessFSMakeFifo |
		llsys.AccessFSMakeSym |
		llsys.AccessFSTruncate |
		llsys.AccessFSRefer
)

// rightsFor maps a declared access kind to its Landlock right set.
//
// An unrecognized kind returns NO rights, which produces a refusal rather than
// a grant. The previous default returned the writable-directory set, so a kind
// this function had never heard of received the widest rights the package
// issues. That is backwards for a default: an unknown access is exactly the
// case where nothing is known about what the caller intended, and the safe
// answer to "I do not recognize this" is to grant nothing.
func rightsFor(access AccessKind) uint64 {
	switch access {
	case AccessReadFile:
		return rightsReadFile
	case AccessReadDirectory:
		return rightsReadDir
	case AccessWriteFile:
		return rightsWriteFile
	case AccessWriteDirectory:
		return rightsWriteDir
	case accessRuntimeDevice:
		return llsys.AccessFSReadFile | llsys.AccessFSWriteFile
	default:
		return 0
	}
}

// Prepare resolves a profile's manifests into pinned descriptors.
//
// uid is the identity the workload will run as; existing state roots must
// belong to it. Prepare mutates the filesystem in exactly one circumstance: an
// absent read-write directory LEAF. It never creates ancestors, so a typo, an
// unmounted volume, or a path under a directory that does not exist yet is a
// refusal rather than a freshly built tree in the wrong place.
//
// The caller must Close the result even when an error is returned.
func Prepare(cfg *config.Config, profileName string, uid int) (*PreparedManifest, error) {
	grants, err := planManifests(cfg, profileName)
	if err != nil {
		return nil, err
	}
	return prepareGrants(grants, uid, config.ExplainGuardPathFloor)
}

func prepareGrants(grants []grant, uid int, explainFloor floorEvaluator) (*PreparedManifest, error) {
	prepared := &PreparedManifest{
		rules:    make([]preparedRule, 0, len(grants)),
		outcomes: make([]PathOutcome, 0, len(grants)),
		complete: true,
	}

	for _, g := range grants {
		outcome := PathOutcome{DeclaredPath: g.declared, Access: g.access}

		if g.refusal != "" {
			outcome.State = StateRefused
			outcome.Reason = g.refusal
			prepared.outcomes = append(prepared.outcomes, outcome)
			prepared.complete = false
			continue
		}

		// Resolve symlinks first, then re-run the floor against the physical
		// target. A declaration may legitimately point through a symlink, but
		// the thing that ends up pinned is the target, so the target is what
		// has to clear the floor. Checking only the declared spelling would let
		// an innocuous name reach credential material.
		resolved, err := resolvePhysical(g.declared)
		if err != nil {
			outcome.State = StateWithheld
			outcome.Reason = fmt.Sprintf("resolving %q: %v", g.declared, err)
			prepared.outcomes = append(prepared.outcomes, outcome)
			prepared.complete = false
			continue
		}
		outcome.ResolvedPath = resolved

		if refusal := floorRefusal(resolved, g.access, explainFloor); refusal != "" && !g.floorExempt {
			outcome.State = StateRefused
			outcome.Reason = "resolved target refused by compiled floor: " + refusal
			prepared.outcomes = append(prepared.outcomes, outcome)
			prepared.complete = false
			continue
		}

		rights := rightsFor(g.access)
		if rights == 0 {
			outcome.State = StateRefused
			outcome.Reason = fmt.Sprintf("unrecognized access kind %q; no rights can be derived, so nothing is granted", g.access)
			prepared.outcomes = append(prepared.outcomes, outcome)
			prepared.complete = false
			continue
		}

		fd, state, reason := pinTarget(resolved, g.access, uid, g.floorExempt)
		outcome.State = state
		outcome.Reason = reason
		if !state.Granted() {
			prepared.outcomes = append(prepared.outcomes, outcome)
			prepared.complete = false
			continue
		}
		prepared.rules = append(prepared.rules, preparedRule{
			fd:       fd,
			access:   rights,
			declared: g.declared,
			kind:     g.access,
			resolved: resolved,
			isDir:    g.access.IsDirectory(),
		})
		prepared.outcomes = append(prepared.outcomes, outcome)
	}

	return prepared, nil
}

// floorRefusal re-runs the compiled floor and returns its reason, or "".
func floorRefusal(path string, access AccessKind, explainFloor floorEvaluator) string {
	floorAccess := config.GuardAccessRead
	if access.IsWrite() {
		floorAccess = config.GuardAccessWrite
	}
	decision, err := explainFloor(path, floorAccess)
	if err != nil {
		// An unevaluable path is refused rather than allowed. The floor not
		// producing an answer is not the same as the floor saying yes.
		return fmt.Sprintf("floor evaluation failed: %v", err)
	}
	if decision.Refused {
		return decision.Reason
	}
	return ""
}

// resolvePhysical resolves a path to its physical location, tolerating an
// absent final component (the ordinary first-run state-directory case) but not
// an absent parent.
func resolvePhysical(path string) (string, error) {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return filepath.Clean(resolved), nil
	}
	parent, leaf := filepath.Split(filepath.Clean(path))
	parentResolved, err := filepath.EvalSymlinks(filepath.Clean(parent))
	if err != nil {
		return "", fmt.Errorf("parent directory does not resolve: %w", err)
	}
	return filepath.Join(parentResolved, leaf), nil
}

// pinTarget opens the resolved path as an O_PATH descriptor, creating an
// absent read-write directory leaf when that is the declared access.
func pinTarget(resolved string, access AccessKind, uid int, runtimeGrant bool) (int, PathState, string) {
	fd, err := openNoSymlinks(resolved, access.IsDirectory())
	switch {
	case err == nil:
		if reason := verifyPinned(fd, resolved, access, uid, runtimeGrant); reason != "" {
			_ = unix.Close(fd)
			return -1, StateRefused, reason
		}
		return fd, StateGranted, ""

	case !errors.Is(err, unix.ENOENT):
		return -1, StateWithheld, fmt.Sprintf("opening %q: %v", resolved, err)

	case access != AccessWriteDirectory:
		// Absent, and not something Guard will create. A missing read path or
		// a missing exact file is reported, never invented: creating an empty
		// file where a workload expected content substitutes a silent wrong
		// answer for a loud missing one.
		return -1, StateWithheld, fmt.Sprintf("%q does not exist and guard only creates read-write directory leaves", resolved)
	}

	return createLeaf(resolved, uid)
}

// createLeaf creates one absent directory leaf under an existing parent.
func createLeaf(resolved string, uid int) (int, PathState, string) {
	parent, leaf := filepath.Split(resolved)
	parentClean := filepath.Clean(parent)
	if leaf == "" {
		return -1, StateRefused, fmt.Sprintf("%q has no leaf component to create", resolved)
	}

	parentFD, err := openNoSymlinks(parentClean, true)
	if err != nil {
		// The parent is absent or unreachable. Guard does not build the tree.
		return -1, StateWithheld, fmt.Sprintf("parent %q is not an existing directory: %v", parentClean, err)
	}
	defer func() { _ = unix.Close(parentFD) }()

	if reason := verifyAncestor(parentFD, parentClean); reason != "" {
		return -1, StateRefused, reason
	}

	// 0o750 is a ceiling, not a target: mkdir applies the umask, which can only
	// clear bits. So the created directory is at most 0o750 and can never be
	// group- or world-writable, with no follow-up chmod and therefore no window
	// between creation and hardening.
	created := true
	if err := unix.Mkdirat(parentFD, leaf, 0o750); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return -1, StateWithheld, fmt.Sprintf("creating %q: %v", resolved, err)
		}
		created = false
	}

	fd, err := openatNoSymlinks(parentFD, leaf, true)
	if err != nil {
		return -1, StateWithheld, fmt.Sprintf("reopening created %q: %v", resolved, err)
	}
	if reason := verifyPinned(fd, resolved, AccessWriteDirectory, uid, false); reason != "" {
		_ = unix.Close(fd)
		return -1, StateRefused, reason
	}
	if created {
		return fd, StateCreated, ""
	}
	return fd, StateGranted, ""
}

// openNoSymlinks opens an absolute path with no symlink traversal at all.
//
// RESOLVE_NO_SYMLINKS is safe here precisely because the caller already
// resolved the path physically: there should be nothing left to traverse. If a
// symlink has appeared in the meantime, someone swapped a component between
// the floor check and this open, and refusing is the correct answer.
func openNoSymlinks(path string, dir bool) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, fmt.Errorf("path must be absolute (got %q)", path)
	}
	rel := strings.TrimPrefix(filepath.Clean(path), "/")
	if rel == "" {
		return -1, fmt.Errorf("refusing to pin the filesystem root")
	}
	root, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("opening filesystem root: %w", err)
	}
	defer func() { _ = unix.Close(root) }()
	return openatNoSymlinks(root, rel, dir)
}

func openatNoSymlinks(dirfd int, rel string, dir bool) (int, error) {
	flags := uint64(unix.O_PATH | unix.O_CLOEXEC)
	if dir {
		flags |= unix.O_DIRECTORY
	}
	how := &unix.OpenHow{
		Flags:   flags,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(dirfd, rel, how)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

// verifyPinned checks the pinned object is the shape and ownership declared.
//
// The type check is done on the descriptor, not on the name, so it describes
// the object that will actually be granted. Refusing a socket, FIFO, or device
// here is not redundant with the rights masks above: a directory grant whose
// target turns out to be a device node would hand out access to raw storage.
func verifyPinned(fd int, resolved string, access AccessKind, uid int, runtimeGrant bool) string {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Sprintf("stat of pinned %q failed: %v", resolved, err)
	}

	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		if !access.IsDirectory() {
			return fmt.Sprintf("%q is a directory but was declared as an exact file", resolved)
		}
	case unix.S_IFREG:
		if access.IsDirectory() {
			return fmt.Sprintf("%q is a regular file but was declared as a directory subtree", resolved)
		}
	case unix.S_IFCHR:
		// Fixed runtime devices are root-owned and world-writable by design.
		// The resolved-path check still refuses symlinks to any other device.
		if !runtimeGrant || access != accessRuntimeDevice || !runtimeDevicePath(resolved) {
			return fmt.Sprintf("%q is a device node and is not one of Guard's fixed runtime devices", resolved)
		}
		return ""
	default:
		return fmt.Sprintf("%q is neither a regular file nor a directory; guard refuses to grant sockets, FIFOs, and device nodes", resolved)
	}

	if !access.IsWrite() {
		return ""
	}
	// Write grants carry the ownership and mode requirements. A read grant on a
	// root-owned shared directory is ordinary and refusing it would strand
	// legitimate deployments; a WRITE grant on a directory somebody else can
	// also write is an invitation to have the workload's state replaced.
	if int(st.Uid) != uid {
		return fmt.Sprintf("writable %q is owned by uid %d, not the workload uid %d", resolved, st.Uid, uid)
	}
	if st.Mode&0o022 != 0 {
		return fmt.Sprintf("writable %q is group- or world-writable (mode %04o)", resolved, st.Mode&0o7777)
	}
	return ""
}

func runtimeDevicePath(path string) bool {
	clean := filepath.Clean(path)
	for _, device := range runtimeDevices {
		if clean == device {
			return true
		}
	}
	return false
}

// verifyAncestor refuses to create state beneath a directory other users can
// write, since such a parent lets them pre-create or swap the leaf.
//
// Ownership is deliberately NOT required here: /home is normally root-owned
// and 0755, and demanding the workload own every ancestor would refuse the
// most ordinary layout there is.
func verifyAncestor(fd int, path string) string {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Sprintf("stat of parent %q failed: %v", path, err)
	}
	if st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0 {
		return fmt.Sprintf("refusing to create state under group- or world-writable parent %q (mode %04o)", path, st.Mode&0o7777)
	}
	return ""
}
