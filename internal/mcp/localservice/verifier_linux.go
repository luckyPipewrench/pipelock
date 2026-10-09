// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	defaultProcRoot = "/proc"
	// exeCacheMax bounds the executable digest cache.
	exeCacheMax = 64
	// environMaxBytes bounds the environment read. A larger environment is
	// refused rather than truncated, so a variable past the cut cannot hide.
	environMaxBytes = 16 << 20
	// statStartTimeIndex is field 22 (starttime) counted from field 3, the
	// first field after the closing parenthesis of the command name.
	statStartTimeIndex = 19
	// statusUIDFields is "Uid:" plus real, effective, saved and filesystem uid.
	statusUIDFields = 5
	deletedSuffix   = " (deleted)"
	shortHashLen    = 12
	nsecPerSec      = int64(1_000_000_000)

	// verifyRetryInterval is the poll period while a server has not accepted.
	verifyRetryInterval = 3 * time.Millisecond
	// verifyRetryCap bounds that wait when the caller's context has no deadline.
	verifyRetryCap = 2 * time.Second
)

// errServerPending marks the only retryable state: the connection is
// established but its server end has no accepted socket yet.
var errServerPending = errors.New("server has not accepted the connection")

// Verifier checks the owner of the server end of loopback connections. It is
// safe for concurrent use.
type Verifier struct {
	procRoot string
	// beforeRecheck runs between the checks and the final incarnation re-read.
	// Tests use it to change the process state in that window.
	beforeRecheck func()
	// onAttempt runs before each verification attempt; tests count attempts.
	onAttempt func()
	// retryCap overrides verifyRetryCap when positive.
	retryCap time.Duration

	mu       sync.Mutex
	exeSums  map[exeKey]string
	exeOrder []exeKey
}

// NewVerifier returns a Verifier that reads the live /proc.
func NewVerifier() *Verifier { return &Verifier{procRoot: defaultProcRoot} }

type exeKey struct {
	dev, ino               uint64
	size, mtimeNs, ctimeNs int64
}

type incarnation struct {
	startTime uint64
	bootID    string
}

// owner is the single process holding the server end of the connection.
type owner struct {
	pid    int
	fdName string
	link   string // expected fd link target, socket:[inode]
}

func (v *Verifier) path(elem ...string) string {
	root := v.procRoot
	if root == "" {
		root = defaultProcRoot
	}
	return filepath.Join(append([]string{root}, elem...)...)
}

func (v *Verifier) pidPath(pid int, elem ...string) string {
	return v.path(append([]string{strconv.Itoa(pid)}, elem...)...)
}

func toU64[T ~int32 | ~int64 | ~uint32 | ~uint64](v T) uint64 { return uint64(v) }

func toI64[T ~int32 | ~int64](v T) int64 { return int64(v) }

func shortHash(h string) string {
	if len(h) > shortHashLen {
		return h[:shortHashLen]
	}
	return h
}

// VerifyConn is VerifyConnContext with a background context; the retry for a
// server that has not accepted yet is still bounded by the package cap.
func (v *Verifier) VerifyConn(conn net.Conn, pin Pin) (Evidence, error) {
	return v.VerifyConnContext(context.Background(), conn, pin)
}

// VerifyConnContext proves which process owns the server end of conn and
// compares it with pin. It must be called on the connection right after the
// dial. On success the connection's server is the process described by the
// returned Evidence at the moment of the check.
//
// A dial completes in the kernel before the server calls accept, and until
// then the server's socket has no inode. Only that state (the server row
// absent or present without an inode) is retried, polling until ctx is done or
// the package cap elapses, then the last error is returned. Every other error
// returns at once: a wrong owner is not a timing problem and is never retried.
func (v *Verifier) VerifyConnContext(ctx context.Context, conn net.Conn, pin Pin) (Evidence, error) {
	var ev Evidence
	err := v.retryPending(ctx, func() error {
		var attemptErr error
		ev, attemptErr = v.verifyOnce(conn, pin)
		return attemptErr
	})
	if err != nil {
		return Evidence{}, err
	}
	return ev, nil
}

// retryPending runs attempt until it returns anything other than
// errServerPending, polling until ctx is done or the retry cap elapses.
func (v *Verifier) retryPending(ctx context.Context, attempt func() error) error {
	limit := v.retryCap
	if limit <= 0 {
		limit = verifyRetryCap
	}
	var poll, deadline *time.Timer
	var pending error
	for {
		if err := ctx.Err(); err != nil {
			if pending != nil {
				return pending
			}
			return err
		}
		if v.onAttempt != nil {
			v.onAttempt()
		}
		err := attempt()
		if err == nil {
			// Cancellation can arrive while reading or hashing process state.
			// A completed check must not admit that canceled connection.
			return ctx.Err()
		}
		if !errors.Is(err, errServerPending) {
			return err
		}
		pending = err
		if poll == nil {
			poll = time.NewTimer(verifyRetryInterval)
			deadline = time.NewTimer(limit)
			defer poll.Stop()
			defer deadline.Stop()
		} else {
			poll.Reset(verifyRetryInterval)
		}
		select {
		case <-ctx.Done():
			return err
		case <-deadline.C:
			return err
		case <-poll.C:
		}
	}
}

func (v *Verifier) verifyOnce(conn net.Conn, pin Pin) (Evidence, error) {
	if err := pin.validate(); err != nil {
		return Evidence{}, err
	}
	local, remote, err := loopbackEndpoints(conn)
	if err != nil {
		return Evidence{}, err
	}

	// Pin the goroutine to one thread so the thread-scoped socket tables read
	// below belong to the network namespace the dial used.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	srv, err := v.findServerRow(local, remote)
	if err != nil {
		return Evidence{}, err
	}
	own, err := v.findOwner(srv.inode)
	if err != nil {
		return Evidence{}, err
	}
	first, err := v.readIncarnation(own.pid)
	if err != nil {
		return Evidence{}, err
	}

	ev := Evidence{PID: own.pid, StartTime: first.startTime, BootID: first.bootID}
	if ev.UID, err = v.checkPrincipal(own.pid, srv.uid, pin); err != nil {
		return Evidence{}, err
	}
	if err = v.checkExecutable(own.pid, pin, &ev); err != nil {
		return Evidence{}, err
	}
	if err = v.checkMappedFiles(own.pid, pin, &ev); err != nil {
		return Evidence{}, err
	}
	if err = v.checkEnvironment(own.pid, pin); err != nil {
		return Evidence{}, err
	}

	if v.beforeRecheck != nil {
		v.beforeRecheck()
	}
	// exec preserves PID/starttime and descriptors without CLOEXEC. Recheck
	// all pins before the final image, incarnation and sole-owner check.
	if _, err = v.checkPrincipal(own.pid, srv.uid, pin); err != nil {
		return Evidence{}, err
	}
	if err = v.checkMappedFiles(own.pid, pin, &Evidence{}); err != nil {
		return Evidence{}, err
	}
	if err = v.checkEnvironment(own.pid, pin); err != nil {
		return Evidence{}, err
	}
	if err = v.confirmOwner(own, first, srv.inode, ev); err != nil {
		return Evidence{}, err
	}
	return ev, nil
}

// loopbackEndpoints returns the unmapped local and remote addresses of a TCP
// connection when both are loopback.
func loopbackEndpoints(conn net.Conn) (local, remote netip.AddrPort, err error) {
	if conn == nil {
		return local, remote, fmt.Errorf("no connection to verify: %w", ErrNotLoopback)
	}
	l, lok := conn.LocalAddr().(*net.TCPAddr)
	r, rok := conn.RemoteAddr().(*net.TCPAddr)
	if !lok || !rok {
		return local, remote, fmt.Errorf("%T to %T is not TCP: %w", conn.LocalAddr(), conn.RemoteAddr(), ErrNotLoopback)
	}
	local = unmapAddrPort(l.AddrPort())
	remote = unmapAddrPort(r.AddrPort())
	if !local.Addr().IsLoopback() || !remote.Addr().IsLoopback() {
		return local, remote, fmt.Errorf("endpoints %s and %s are not both loopback: %w", local.Addr(), remote.Addr(), ErrNotLoopback)
	}
	return local, remote, nil
}

func unmapAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().WithZone("").Unmap(), ap.Port())
}

// readSocketTables reads the TCP socket tables of the calling thread's network
// namespace. thread-self is used when present; self is the fallback.
func (v *Verifier) readSocketTables() ([]sockRow, error) {
	base := "thread-self"
	if _, err := os.Stat(v.path(base, "net")); err != nil {
		base = "self"
	}
	data, err := os.ReadFile(v.path(base, "net", "tcp"))
	if err != nil {
		return nil, fmt.Errorf("read socket table %s/net/tcp: %w: %w", base, ErrSocketNotFound, err)
	}
	rows := parseNetTCP(data)
	// tcp6 is absent when IPv6 is disabled; a present but unreadable table is not.
	data6, err := os.ReadFile(v.path(base, "net", "tcp6"))
	switch {
	case err == nil:
		rows = append(rows, parseNetTCP(data6)...)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("read socket table %s/net/tcp6: %w: %w", base, ErrSocketNotFound, err)
	}
	return rows, nil
}

// findServerRow finds the established row for each end of the connection and
// returns the server's. The server end is the row whose local address is our
// remote address.
func (v *Verifier) findServerRow(local, remote netip.AddrPort) (sockRow, error) {
	rows, err := v.readSocketTables()
	if err != nil {
		return sockRow{}, err
	}
	var (
		clientSeen bool
		server     sockRow
		serverSeen bool
	)
	for _, row := range rows {
		if row.state != tcpStateEstablished {
			continue
		}
		if row.local == local && row.remote == remote {
			clientSeen = true
		}
		if row.local == remote && row.remote == local {
			if serverSeen && server.inode != row.inode {
				return sockRow{}, fmt.Errorf("%s -> %s has two server sockets: %w", local, remote, ErrMultipleOwners)
			}
			server, serverSeen = row, true
		}
	}
	if !clientSeen {
		return sockRow{}, fmt.Errorf("client end %s -> %s is not established in this network namespace: %w", local, remote, ErrSocketNotFound)
	}
	if !serverSeen {
		return sockRow{}, fmt.Errorf("server end %s -> %s is not established in this network namespace: %w: %w", remote, local, ErrSocketNotFound, errServerPending)
	}
	if server.inode == 0 {
		return sockRow{}, fmt.Errorf("server end %s has no socket inode (the server has not accepted the connection yet): %w: %w", remote, ErrSocketNotFound, errServerPending)
	}
	return server, nil
}

// findOwner walks every process's descriptor table for the socket inode.
func (v *Verifier) findOwner(inode uint64) (owner, error) {
	want := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	entries, err := os.ReadDir(v.path())
	if err != nil {
		return owner{}, fmt.Errorf("list processes: %w: %w", ErrOwnerNotVisible, err)
	}
	var (
		holders    []owner
		unreadable int
	)
	for _, ent := range entries {
		pid, ok := parsePID(ent.Name())
		if !ok {
			continue
		}
		fdDir := v.pidPath(pid, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			unreadable++
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || link != want {
				continue
			}
			holders = append(holders, owner{pid: pid, fdName: fd.Name(), link: want})
			break
		}
	}
	switch len(holders) {
	case 0:
		return owner{}, fmt.Errorf("no visible process holds %s (%d process descriptor tables were unreadable; check hidepid, PID namespace and privilege): %w", want, unreadable, ErrOwnerNotVisible)
	case 1:
		return holders[0], nil
	default:
		pids := make([]string, len(holders))
		for i, h := range holders {
			pids[i] = strconv.Itoa(h.pid)
		}
		return owner{}, fmt.Errorf("%s is held by processes %s: %w", want, strings.Join(pids, ","), ErrMultipleOwners)
	}
}

func parsePID(name string) (int, bool) {
	if name == "" {
		return 0, false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return 0, false
		}
	}
	pid, err := strconv.Atoi(name)
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// procReadError classifies a failure to read a per-process file: a vanished
// process is a changed owner, anything else is invisibility.
func procReadError(pid int, what string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("pid %d exited while reading %s: %w: %w", pid, what, ErrOwnerChanged, err)
	}
	return fmt.Errorf("pid %d %s is unreadable: %w: %w", pid, what, ErrOwnerNotVisible, err)
}

// readIncarnation returns the process start time and the boot id.
func (v *Verifier) readIncarnation(pid int) (incarnation, error) {
	stat, err := os.ReadFile(v.pidPath(pid, "stat"))
	if err != nil {
		return incarnation{}, procReadError(pid, "stat", err)
	}
	// The command name is parenthesised and may itself contain ")" or spaces,
	// so fields are counted from the last ")".
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return incarnation{}, fmt.Errorf("pid %d stat has no command terminator: %w", pid, ErrOwnerNotVisible)
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) <= statStartTimeIndex {
		return incarnation{}, fmt.Errorf("pid %d stat has too few fields: %w", pid, ErrOwnerNotVisible)
	}
	start, err := strconv.ParseUint(fields[statStartTimeIndex], 10, 64)
	if err != nil {
		return incarnation{}, fmt.Errorf("pid %d stat start time is malformed: %w: %w", pid, ErrOwnerNotVisible, err)
	}
	boot, err := os.ReadFile(v.path("sys", "kernel", "random", "boot_id"))
	if err != nil {
		return incarnation{}, fmt.Errorf("read boot id: %w: %w", ErrOwnerNotVisible, err)
	}
	return incarnation{startTime: start, bootID: strings.TrimSpace(string(boot))}, nil
}

// checkPrincipal requires both the process's effective uid and the uid the
// kernel recorded on the socket to equal the registered principal.
func (v *Verifier) checkPrincipal(pid int, socketUID uint32, pin Pin) (uint32, error) {
	euid, err := v.effectiveUID(pid)
	if err != nil {
		return 0, err
	}
	if euid != pin.PrincipalUID || socketUID != pin.PrincipalUID {
		return 0, fmt.Errorf("%s is %d but the process serving the connection runs as effective uid %d and its socket is recorded for uid %d: %w",
			fieldPrincipalUID, pin.PrincipalUID, euid, socketUID, ErrPrincipalMismatch)
	}
	return euid, nil
}

// effectiveUID reads the effective uid from the process status file.
func (v *Verifier) effectiveUID(pid int) (uint32, error) {
	status, err := os.ReadFile(v.pidPath(pid, "status"))
	if err != nil {
		return 0, procReadError(pid, "status", err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != statusUIDFields {
			break
		}
		euid, err := strconv.ParseUint(fields[2], 10, 32)
		if err == nil {
			return uint32(euid), nil //nolint:gosec // ParseUint bitSize 32 bounds the value
		}
		break
	}
	return 0, fmt.Errorf("pid %d status has no usable Uid line: %w", pid, ErrOwnerNotVisible)
}

// fileIdentity returns the device and inode of an open file's fstat.
func fileIdentity(fi fs.FileInfo) (dev, ino uint64, st *syscall.Stat_t, ok bool) {
	st, ok = fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, nil, false
	}
	return toU64(st.Dev), toU64(st.Ino), st, true
}

func hashFile(f *os.File) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// checkExecutable hashes the image the process is running, opened through its
// exe link, so replacing the file on disk after launch does not change what is
// measured.
func (v *Verifier) checkExecutable(pid int, pin Pin, ev *Evidence) error {
	dev, ino, sum, err := v.executableDigest(pid)
	if err != nil {
		return err
	}
	if sum != pin.ExecutableSHA256 {
		return fmt.Errorf("%s does not match the executable of the process serving the connection (pid %d runs %s, registered %s): %w",
			fieldExecutable, pid, shortHash(sum), shortHash(pin.ExecutableSHA256), ErrApplicationMismatch)
	}
	ev.ExecutableDev, ev.ExecutableIno, ev.ExecutableSHA256 = dev, ino, sum
	return nil
}

// executableDigest hashes the image the process is running, opened through its
// exe link, and caches the digest by file identity.
func (v *Verifier) executableDigest(pid int) (dev, ino uint64, sum string, err error) {
	f, err := os.Open(v.pidPath(pid, "exe"))
	if err != nil {
		return 0, 0, "", fmt.Errorf("pid %d executable cannot be opened: %w: %w", pid, ErrOwnerNotVisible, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, "", fmt.Errorf("pid %d executable cannot be inspected: %w: %w", pid, ErrOwnerNotVisible, err)
	}
	dev, ino, st, ok := fileIdentity(fi)
	if !ok {
		return 0, 0, "", fmt.Errorf("pid %d executable has no inode identity: %w", pid, ErrOwnerNotVisible)
	}
	key := exeKey{
		dev: dev, ino: ino, size: fi.Size(),
		mtimeNs: toI64(st.Mtim.Sec)*nsecPerSec + toI64(st.Mtim.Nsec),
		ctimeNs: toI64(st.Ctim.Sec)*nsecPerSec + toI64(st.Ctim.Nsec),
	}
	sum, hit := v.cachedSum(key)
	if !hit {
		if sum, err = hashFile(f); err != nil {
			return 0, 0, "", fmt.Errorf("pid %d executable cannot be read: %w: %w", pid, ErrOwnerNotVisible, err)
		}
		v.storeSum(key, sum)
	}
	return dev, ino, sum, nil
}

func (v *Verifier) cachedSum(k exeKey) (string, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	sum, ok := v.exeSums[k]
	return sum, ok
}

func (v *Verifier) storeSum(k exeKey, sum string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.exeSums == nil {
		v.exeSums = make(map[exeKey]string, exeCacheMax)
	}
	if _, ok := v.exeSums[k]; ok {
		return
	}
	for len(v.exeOrder) >= exeCacheMax {
		delete(v.exeSums, v.exeOrder[0])
		v.exeOrder = v.exeOrder[1:]
	}
	v.exeSums[k] = sum
	v.exeOrder = append(v.exeOrder, k)
}

// heldFile is a file the owner holds as a descriptor or a memory mapping.
type heldFile struct {
	dev, ino uint64
	path     string
	// special marks a descriptor that is not a regular file (device, socket
	// file, directory).
	special bool
}

// heldFiles lists regular-path files the owner holds. Descriptors are resolved
// through the kernel's own link (stat follows the open file, not the path), and
// mappings are read from maps.
func (v *Verifier) heldFiles(pid int) ([]heldFile, error) {
	var held []heldFile
	fdDir := v.pidPath(pid, "fd")
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, procReadError(pid, "fd table", err)
	}
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err != nil || !strings.HasPrefix(link, "/") {
			continue
		}
		fi, err := os.Stat(filepath.Join(fdDir, fd.Name()))
		if err != nil {
			continue
		}
		if dev, ino, _, ok := fileIdentity(fi); ok {
			held = append(held, heldFile{dev: dev, ino: ino, path: strings.TrimSuffix(link, deletedSuffix), special: !fi.Mode().IsRegular()})
		}
	}
	maps, err := os.ReadFile(v.pidPath(pid, "maps"))
	if err != nil {
		return nil, procReadError(pid, "maps", err)
	}
	for _, line := range strings.Split(string(maps), "\n") {
		if h, ok := parseMapsLine(line); ok {
			held = append(held, h)
		}
	}
	return held, nil
}

// parseMapsLine reads "start-end perms offset major:minor inode path".
func parseMapsLine(line string) (heldFile, bool) {
	const mapsFixedFields = 6
	fields := strings.Fields(line)
	if len(fields) < mapsFixedFields {
		return heldFile{}, false
	}
	majStr, minStr, ok := strings.Cut(fields[3], ":")
	if !ok {
		return heldFile{}, false
	}
	maj, err := strconv.ParseUint(majStr, 16, 32)
	if err != nil {
		return heldFile{}, false
	}
	mnr, err := strconv.ParseUint(minStr, 16, 32)
	if err != nil {
		return heldFile{}, false
	}
	ino, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil || ino == 0 {
		return heldFile{}, false
	}
	p := strings.Join(fields[5:], " ")
	if !strings.HasPrefix(p, "/") {
		return heldFile{}, false
	}
	return heldFile{dev: unix.Mkdev(uint32(maj), uint32(mnr)), ino: ino, path: strings.TrimSuffix(p, deletedSuffix)}, true
}

// checkMappedFiles requires the owner to hold each pinned file as the very
// inode Pipelock just opened, then hashes that opened descriptor. Opening and
// hashing the same descriptor leaves no window between the identity check and
// the content check.
func (v *Verifier) checkMappedFiles(pid int, pin Pin, ev *Evidence) error {
	if len(pin.MappedFiles) == 0 {
		return nil
	}
	held, err := v.heldFiles(pid)
	if err != nil {
		return err
	}
	for i, pf := range pin.MappedFiles {
		sum, err := v.checkOnePinnedFile(pid, i, pf, held)
		if err != nil {
			return err
		}
		ev.MappedFiles = append(ev.MappedFiles, FilePin{Path: pf.Path, SHA256: sum})
	}
	return nil
}

func (v *Verifier) checkOnePinnedFile(pid, i int, pf FilePin, held []heldFile) (string, error) {
	field := fmt.Sprintf("%s[%d]", fieldMappedFiles, i)
	clean := filepath.Clean(pf.Path)
	f, err := os.Open(clean)
	if err != nil {
		return "", fmt.Errorf("%s.path %s cannot be opened: %w: %w", field, clean, ErrApplicationMismatch, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("%s.path %s cannot be inspected: %w: %w", field, clean, ErrApplicationMismatch, err)
	}
	dev, ino, _, ok := fileIdentity(fi)
	if !ok || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s.path %s is not a regular file: %w", field, clean, ErrApplicationMismatch)
	}

	var samePath bool
	var holds bool
	for _, h := range held {
		if h.dev == dev && h.ino == ino {
			holds = true
			break
		}
		if h.path == clean {
			samePath = true
		}
	}
	switch {
	case holds:
	case samePath:
		return "", fmt.Errorf("%s.path %s is stale: pid %d holds a different file at that path than the one on disk now: %w", field, clean, pid, ErrApplicationMismatch)
	default:
		return "", fmt.Errorf("%s.path %s is not open or mapped by the owner (pid %d): %w", field, clean, pid, ErrApplicationMismatch)
	}

	sum, err := hashFile(f)
	if err != nil {
		return "", fmt.Errorf("%s.path %s cannot be read: %w: %w", field, clean, ErrApplicationMismatch, err)
	}
	if sum != pf.SHA256 {
		return "", fmt.Errorf("%s.sha256 does not match %s held by the owner (pid %d, file hashes to %s, registered %s): %w",
			field, clean, pid, shortHash(sum), shortHash(pf.SHA256), ErrApplicationMismatch)
	}
	return sum, nil
}

// readEnviron reads the whole initial environment of the process. A larger
// environment is refused rather than truncated.
func (v *Verifier) readEnviron(pid int) ([]byte, error) {
	f, err := os.Open(v.pidPath(pid, "environ"))
	if err != nil {
		return nil, fmt.Errorf("pid %d environment cannot be opened: %w: %w", pid, ErrOwnerNotVisible, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, environMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("pid %d environment cannot be read: %w: %w", pid, ErrOwnerNotVisible, err)
	}
	if len(data) > environMaxBytes {
		return nil, fmt.Errorf("pid %d environment exceeds %d bytes and cannot be fully checked: %w", pid, environMaxBytes, ErrOwnerNotVisible)
	}
	return data, nil
}

// checkEnvironment refuses loader and interpreter control variables unless the
// registration names them with the exact value. Only names are reported.
func (v *Verifier) checkEnvironment(pid int, pin Pin) error {
	data, err := v.readEnviron(pid)
	if err != nil {
		return err
	}
	var offending []string
	for _, entry := range bytes.Split(data, []byte{0}) {
		name, value, ok := strings.Cut(string(entry), "=")
		if !ok {
			continue
		}
		if _, deny := controlEnvironmentSet[name]; !deny {
			continue
		}
		if registered, ok := pin.ControlEnvironment[name]; ok && registered == value {
			continue
		}
		offending = append(offending, name)
	}
	if len(offending) == 0 {
		return nil
	}
	sort.Strings(offending)
	return fmt.Errorf("%s does not register %s, which the process serving the connection (pid %d) carries: %w",
		fieldControlEnv, strings.Join(offending, ", "), pid, ErrControlEnvironment)
}

// confirmOwner rechecks the executable image, sole socket ownership,
// incarnation and descriptor after the pins are measured. PID/starttime alone
// cannot detect exec, and one unchanged descriptor cannot detect fd passing.
func (v *Verifier) confirmOwner(own owner, first incarnation, inode uint64, image Evidence) error {
	second, err := v.readIncarnation(own.pid)
	if err != nil {
		return err
	}
	if second != first {
		return fmt.Errorf("pid %d start time or boot id changed during verification: %w", own.pid, ErrOwnerChanged)
	}
	link, err := os.Readlink(v.pidPath(own.pid, "fd", own.fdName))
	if err != nil || link != own.link {
		return fmt.Errorf("pid %d no longer holds %s on descriptor %s: %w", own.pid, own.link, own.fdName, ErrOwnerChanged)
	}
	dev, ino, sum, err := v.executableDigest(own.pid)
	if err != nil {
		return err
	}
	if dev != image.ExecutableDev || ino != image.ExecutableIno || sum != image.ExecutableSHA256 {
		return fmt.Errorf("pid %d executable changed during verification; check %s: %w", own.pid, fieldExecutable, ErrOwnerChanged)
	}
	current, err := v.findOwner(inode)
	if err != nil {
		return err
	}
	if current.pid != own.pid {
		return fmt.Errorf("socket owner changed from pid %d to pid %d during verification: %w", own.pid, current.pid, ErrOwnerChanged)
	}
	second, err = v.readIncarnation(own.pid)
	if err != nil {
		return err
	}
	if second != first {
		return fmt.Errorf("pid %d start time or boot id changed during verification: %w", own.pid, ErrOwnerChanged)
	}
	link, err = os.Readlink(v.pidPath(own.pid, "fd", own.fdName))
	if err != nil || link != own.link {
		return fmt.Errorf("pid %d no longer holds %s on descriptor %s: %w", own.pid, own.link, own.fdName, ErrOwnerChanged)
	}
	return nil
}
