// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

const (
	lifecycleCleanupTimeout   = 12 * time.Second
	lifecycleClientTimeout    = 2 * time.Second
	lifecycleAdmissionTimeout = 3 * time.Second
	lifecyclePollInterval     = 50 * time.Millisecond
	// lifecycleCommandBudget is the deadline lifecycleSystemCommand gives each
	// systemd helper. Cleanup reserves a multiple of it so an optional bind
	// retry cannot spend the commands that still have to run.
	lifecycleCommandBudget = 2 * time.Second
	// Optional bind retries get one helper budget. They stop earlier when the
	// parent deadline no longer holds the reserve below.
	lifecycleBindRetryBudget = lifecycleCommandBudget
	// After the first cleanup bind check returns, these helpers still have to
	// finish before stop: argv, the invocation recheck, the confirming bind
	// read, and the stop action.
	lifecycleCommandsAfterFirstBindCheck = 4
	// After the confirming bind check returns, only stop remains.
	lifecycleCommandsAfterConfirmingBindCheck = 1
	lifecycleFilename                         = "lifecycle.json"
	lifecycleDescriptionPrefix                = "pipelock-contain-lifecycle:"
)

func containRunLifecycleContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
}

func newContainRunLifecycle(dir string) (*containRunLifecycle, error) {
	if !isRoot() {
		return nil, errors.New("lifecycle output requires root")
	}
	file, err := openLifecycleDirectory(dir, 0)
	if err != nil {
		return nil, err
	}
	return initializeContainRunLifecycle(file)
}

// The caller has checked root and opened a new, owner-verified directory.
// Retain that descriptor for every publication and transfer its ownership to
// the lifecycle only after the initial record is durably written.
func initializeContainRunLifecycle(file *os.File) (*containRunLifecycle, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("generate lifecycle identity: %w", err)
	}
	runID := hex.EncodeToString(nonce[:])
	l := &containRunLifecycle{
		record: containLifecycleRecord{
			Schema: 1, RunID: runID, Unit: "pipelock-contain-" + runID + ".service", Phase: "reserved",
			AdmissionTimeoutSeconds: int(lifecycleAdmissionTimeout / time.Second), CleanupTimeoutSeconds: int(lifecycleCleanupTimeout / time.Second), ClientWaitTimeoutSeconds: int(lifecycleClientTimeout / time.Second),
		},
		close: file.Close,
		save:  func(record containLifecycleRecord) error { return writeLifecycleRecord(file, record) },
	}
	if err := l.write(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return l, nil
}

// Open every component without following symlinks, retaining a directory handle
// for all later writes. Root-owned sticky ancestors (e.g. /tmp) are allowed;
// other writable ancestors would permit replacing the output directory.
func openLifecycleDirectory(dir string, owner uint32) (*os.File, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == "/" {
		return nil, errors.New("lifecycle directory must be a clean absolute new path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(dir, "/"), "/")
	for i, part := range parts {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		// Non-root test owners may traverse root-owned ancestors, but production
		// always passes owner=0. The new leaf must have exactly that owner.
		if (st.Uid != 0 && st.Uid != owner) || (st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0) {
			_ = unix.Close(fd)
			return nil, errors.New("lifecycle directory has an unsafe ancestor owner or mode")
		}
		if i == len(parts)-1 {
			if err := unix.Mkdirat(fd, part, 0o700); err != nil {
				_ = unix.Close(fd)
				return nil, fmt.Errorf("create new lifecycle directory: %w", err)
			}
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("open lifecycle directory: %w", openErr)
		}
		fd = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if st.Uid != owner || st.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return nil, errors.New("lifecycle directory must be owned by root and mode 0700")
	}
	return os.NewFile(uintptr(fd), dir), nil
}

func writeLifecycleRecord(dir *os.File, record containLifecycleRecord) error {
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if len(body) > maxCmdOutputBytes {
		return errors.New("lifecycle record exceeds size limit")
	}
	body = append(body, '\n')
	fd, err := unix.Openat(int(dir.Fd()), ".lifecycle-next", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create lifecycle record: %w", err)
	}
	file := os.NewFile(uintptr(fd), ".lifecycle-next")
	defer func() { _ = unix.Unlinkat(int(dir.Fd()), ".lifecycle-next", 0) }()
	_, writeErr := file.Write(body)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := unix.Renameat(int(dir.Fd()), ".lifecycle-next", int(dir.Fd()), lifecycleFilename); err != nil {
		return err
	}
	return dir.Sync()
}

type lifecycleBackend struct {
	show        func(context.Context, string) (map[string]string, error)
	action      func(context.Context, string, ...string) error
	cgroupEmpty func(string) (bool, error)
	wait        func(context.Context, time.Duration) error
	now         func() time.Time
	execStart   func(context.Context, string) ([]string, error)
	// binds reads BindPaths and BindReadOnlyPaths as typed D-Bus tuples.
	// Nil, or a reader that returns errTypedBindsUnavailable, falls back to
	// systemctl show and then fails closed unless every entry names its option.
	binds func(context.Context, string) (bindPaths, readOnly []systemdBindEntry, err error)
}

// errLifecycleTypedObservation is a failed typed bind read. It is retried
// inside the admission and cleanup deadlines. It is not an identity mismatch
// and it is not permission to treat display text as a typed tuple.
var errLifecycleTypedObservation = errors.New("typed lifecycle bind observation failed")

// errLifecycleInvocationChanged means the invocation id moved while it was
// being checked. That unit is not the reserved one, so it is not admitted
// and cleanup does not stop it.
var errLifecycleInvocationChanged = errors.New("invocation changed during typed command observation")

// Immediate test doubles return without sleeping. Cap those polls so a
// persistent error cannot busy-loop inside a deadline that is still open.
const lifecycleTypedRetryInstantCap = 8

type lifecycleBindObservation struct {
	BindPaths []systemdBindEntry
	ReadOnly  []systemdBindEntry
}

func defaultLifecycleBackend() lifecycleBackend {
	return lifecycleBackend{show: lifecycleSystemdShow, action: lifecycleSystemdAction, cgroupEmpty: lifecycleCgroupEmpty, wait: waitForReadiness, now: time.Now, execStart: lifecycleExecStart, binds: lifecycleSystemdBinds}
}

// Keep the line-based observation scalar-only. ExecStart's display format can
// contain argument newlines; the typed reader verifies its path and exact argv.
const lifecycleSystemdProperties = "Id,LoadState,ActiveState,SubState,Transient,Description,InvocationID,ControlGroup,User,ExecMainCode,ExecMainStatus,MainPID,PrivateNetwork,PrivateTmp,JoinsNamespaceOf,KillMode,SendSIGKILL,Restart,ProtectSystem,ProtectHome,NoNewPrivileges,BindPaths,BindReadOnlyPaths,InaccessiblePaths,TemporaryFileSystem,ProtectKernelTunables,ProtectKernelModules,ProtectControlGroups"

func lifecycleSystemdShow(ctx context.Context, unit string) (map[string]string, error) {
	out, code, err := lifecycleSystemctl(ctx, "show", unit, "--property="+lifecycleSystemdProperties)
	if err != nil {
		return nil, err
	}
	return parseLifecycleSystemdShow(unit, out, code)
}

func parseLifecycleSystemdShow(unit, out string, code int) (map[string]string, error) {
	fields := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return nil, errors.New("malformed lifecycle systemctl properties")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate lifecycle systemctl property")
		}
		fields[key] = value
	}
	if fields["Id"] != unit || fields["LoadState"] == "" {
		return nil, errors.New("missing or mismatched lifecycle unit identity")
	}
	if code != 0 && fields["LoadState"] != "not-found" {
		return nil, fmt.Errorf("inspect lifecycle service: systemctl exit %d", code)
	}
	return fields, nil
}

func lifecycleSystemdAction(ctx context.Context, unit string, args ...string) error {
	args = append(args, unit)
	_, code, err := lifecycleSystemctl(ctx, args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("lifecycle systemctl action exited %d", code)
	}
	return nil
}

func lifecycleSystemctl(ctx context.Context, args ...string) (string, int, error) {
	return lifecycleSystemCommand(ctx, "/usr/bin/systemctl", append([]string{"--no-ask-password", "--no-pager"}, args...)...)
}

func lifecycleSystemCommand(ctx context.Context, binary string, args ...string) (string, int, error) {
	bounded, cancel := context.WithTimeout(ctx, lifecycleCommandBudget)
	defer cancel()
	cmd := exec.CommandContext(bounded, binary, args...) //nolint:gosec // G204: binary is one of the two fixed systemd helper paths, never user input.
	cmd.Env = lifecycleManagerEnvironment()
	cmd.WaitDelay = time.Second
	buf := newCappedBuffer(maxCmdOutputBytes + 1)
	cmd.Stdout, cmd.Stderr = buf, buf
	err := cmd.Run()
	if len(buf.String()) > maxCmdOutputBytes {
		return "", -1, errors.New("lifecycle systemctl output exceeds bound")
	}
	if bounded.Err() != nil {
		return "", -1, bounded.Err()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return buf.String(), exitErr.ExitCode(), nil
	}
	return buf.String(), 0, err
}

func lifecycleManagerEnvironment() []string {
	// In particular, do not inherit DBUS_SYSTEM_BUS_ADDRESS or SYSTEMD_HOST:
	// launch and observation must address the same local system manager.
	return []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_PAGER="}
}

func lifecycleUnitObjectPath(unit string) string {
	// Unit names generated here contain only ASCII letters, digits, '-' and
	// '.'. Encode all non-alphanumerics per systemd's D-Bus unit path contract.
	var object strings.Builder
	object.WriteString("/org/freedesktop/systemd1/unit/")
	for _, c := range []byte(unit) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			object.WriteByte(c)
		} else {
			_, _ = fmt.Fprintf(&object, "_%02x", c)
		}
	}
	return object.String()
}

func lifecycleBusJSON(ctx context.Context, unit, property string) (string, error) {
	out, code, err := lifecycleSystemCommand(ctx, "/usr/bin/busctl", "--system", "--json=short", "--allow-interactive-authorization=no", "--auto-start=no", "get-property", "org.freedesktop.systemd1", lifecycleUnitObjectPath(unit), "org.freedesktop.systemd1.Service", property)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("read typed lifecycle %s: busctl exit %d", property, code)
	}
	return out, nil
}

func lifecycleExecStart(ctx context.Context, unit string) ([]string, error) {
	out, err := lifecycleBusJSON(ctx, unit, "ExecStart")
	if err != nil {
		return nil, err
	}
	return parseLifecycleExecStart([]byte(out))
}

func lifecycleSystemdBinds(ctx context.Context, unit string) ([]systemdBindEntry, []systemdBindEntry, error) {
	bindRaw, err := lifecycleBusJSON(ctx, unit, "BindPaths")
	if err != nil {
		if lifecycleBusctlMissing(err) {
			return nil, nil, errTypedBindsUnavailable
		}
		return nil, nil, err
	}
	readOnlyRaw, err := lifecycleBusJSON(ctx, unit, "BindReadOnlyPaths")
	if err != nil {
		if lifecycleBusctlMissing(err) {
			return nil, nil, errTypedBindsUnavailable
		}
		return nil, nil, err
	}
	bindPaths, err := parseTypedSystemdBinds([]byte(bindRaw))
	if err != nil {
		return nil, nil, fmt.Errorf("lifecycle bind paths: %w", err)
	}
	readOnly, err := parseTypedSystemdBinds([]byte(readOnlyRaw))
	if err != nil {
		return nil, nil, fmt.Errorf("lifecycle read-only bind paths: %w", err)
	}
	return bindPaths, readOnly, nil
}

func lifecycleBusctlMissing(err error) bool {
	if err == nil {
		return false
	}
	var execErr *exec.Error
	if errors.As(err, &execErr) && errors.Is(execErr.Err, exec.ErrNotFound) {
		return true
	}
	// An absolute executable skips PATH lookup. The kernel reports that as
	// *fs.PathError with ENOENT, not *exec.Error / exec.ErrNotFound. That
	// ENOENT is the missing-reader case: the display-form fallback may run,
	// and it still fails closed unless every entry names norbind or rbind.
	return errors.Is(err, os.ErrNotExist)
}

func parseLifecycleExecStart(body []byte) ([]string, error) {
	if len(body) > maxCmdOutputBytes {
		return nil, errors.New("typed lifecycle ExecStart exceeds bound")
	}
	if err := jsonscan.RejectDuplicateKeys(body); err != nil {
		return nil, fmt.Errorf("invalid typed lifecycle ExecStart JSON: %w", err)
	}
	if err := jsonscan.RejectCaseFoldedAliases(body, "type", "data"); err != nil {
		return nil, fmt.Errorf("invalid typed lifecycle ExecStart fields: %w", err)
	}
	var payload struct {
		Type string              `json:"type"`
		Data [][]json.RawMessage `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode typed lifecycle ExecStart: %w", err)
	}
	if payload.Type != "a(sasbttttuii)" || len(payload.Data) != 1 || len(payload.Data[0]) != 10 {
		return nil, errors.New("typed lifecycle ExecStart has unexpected signature or command count")
	}
	var path string
	var argv []string
	var ignoreFailure bool
	row := payload.Data[0]
	if err := errors.Join(json.Unmarshal(row[0], &path), json.Unmarshal(row[1], &argv), json.Unmarshal(row[2], &ignoreFailure)); err != nil {
		return nil, fmt.Errorf("decode typed lifecycle command: %w", err)
	}
	if path != defaultLaunchScript || len(argv) == 0 || argv[0] != defaultLaunchScript || ignoreFailure || string(bytes.TrimSpace(row[2])) != "false" {
		return nil, errors.New("typed lifecycle command differs from plk-launch")
	}
	return argv, nil
}

func verifyLifecycleArgv(ctx context.Context, b lifecycleBackend, l *containRunLifecycle) error {
	if b.execStart == nil {
		return errors.New("typed lifecycle ExecStart reader is unavailable")
	}
	argv, err := b.execStart(ctx, l.record.Unit)
	if err != nil {
		return err
	}
	if len(l.argv) == 0 || !slices.Equal(argv, l.argv) {
		return errors.New("observed lifecycle argv differs from requested launch")
	}
	return nil
}

func lifecycleCgroupEmpty(group string) (bool, error) {
	if !strings.HasPrefix(group, "/system.slice/pipelock-contain-") || filepath.Clean(group) != group || strings.Contains(strings.TrimPrefix(group, "/system.slice/"), "/") {
		return false, errors.New("unexpected lifecycle cgroup path")
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &filesystem); err != nil {
		return false, err
	}
	if filesystem.Type != unix.CGROUP2_SUPER_MAGIC {
		return false, errors.New("lifecycle cleanup requires the cgroup v2 filesystem")
	}
	file, err := os.Open(filepath.Clean(filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(group, "/"), "cgroup.events")))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	body, readErr := io.ReadAll(io.LimitReader(file, 4097))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return false, err
	}
	return parseLifecycleCgroupEvents(body)
}

func parseLifecycleCgroupEvents(body []byte) (bool, error) {
	if len(body) > 4096 {
		return false, errors.New("lifecycle cgroup events exceeds bound")
	}
	var populated string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "populated ") {
			if populated != "" {
				return false, errors.New("duplicate cgroup populated witness")
			}
			populated = strings.TrimPrefix(line, "populated ")
		}
	}
	if populated == "0" {
		return true, nil
	}
	if populated == "1" {
		return false, nil
	}
	return false, errors.New("lifecycle requires a cgroup v2 populated witness")
}

func lifecycleOwned(fields map[string]string, record containLifecycleRecord, uid uint32) error {
	if err := lifecycleServiceIdentity(fields, record, uid); err != nil {
		return err
	}
	return lifecycleFilesystemOwned(fields, record, nil)
}

// confirmLifecycleOwned is the admission and cleanup ownership check. Enforce
// mode reads bind mounts as typed D-Bus tuples. systemctl show's BindPaths
// text is used only when that reader is unavailable, and then a missing
// option is a failure rather than norbind.
func confirmLifecycleOwned(ctx context.Context, b lifecycleBackend, fields map[string]string, record containLifecycleRecord, uid uint32) error {
	if err := lifecycleServiceIdentity(fields, record, uid); err != nil {
		return err
	}
	if err := confirmLifecycleFilesystem(ctx, b, fields, record); err != nil {
		return err
	}
	if record.FilesystemMode != config.ContainmentFilesystemModeEnforce {
		return nil
	}
	// The bind read is its own manager observation. A unit whose user or
	// invocation changed during that read is not the one just identified.
	current, err := b.show(ctx, record.Unit)
	if err != nil {
		return err
	}
	return lifecycleServiceIdentity(current, record, uid)
}

// confirmLifecycleFilesystem checks the bind and profile properties. It does
// not decide whether the unit is the reserved invocation.
func confirmLifecycleFilesystem(ctx context.Context, b lifecycleBackend, fields map[string]string, record containLifecycleRecord) error {
	if record.FilesystemMode != config.ContainmentFilesystemModeEnforce {
		return nil
	}
	observed, err := observeLifecycleBinds(ctx, b, record.Unit, fields)
	if err != nil {
		return err
	}
	return lifecycleFilesystemOwned(fields, record, observed)
}

func lifecycleServiceIdentity(fields map[string]string, record containLifecycleRecord, uid uint32) error {
	if fields["Id"] != record.Unit || fields["Transient"] != "yes" || fields["Description"] != lifecycleDescriptionPrefix+record.RunID {
		return errors.New("transient lifecycle ownership is missing or ambiguous")
	}
	invocation := fields["InvocationID"]
	decoded, err := hex.DecodeString(invocation)
	if err != nil || len(decoded) != 16 || invocation == strings.Repeat("0", 32) {
		return errors.New("lifecycle invocation identity is missing or invalid")
	}
	if record.InvocationID != "" && invocation != record.InvocationID {
		return errors.New("lifecycle invocation identity changed")
	}
	if fields["User"] != strconv.FormatUint(uint64(uid), 10) {
		return errors.New("lifecycle service user differs from launch identity")
	}
	if fields["ControlGroup"] != "/system.slice/"+record.Unit {
		return errors.New("lifecycle cgroup differs from reserved service")
	}
	if fields["PrivateNetwork"] != "yes" || fields["PrivateTmp"] != "yes" || fields["JoinsNamespaceOf"] != containedNetworkNamespaceUnit || fields["KillMode"] != "control-group" || fields["SendSIGKILL"] != "yes" || fields["Restart"] != "no" {
		return errors.New("lifecycle service properties differ from managed launch")
	}
	return nil
}

func observeLifecycleBinds(ctx context.Context, b lifecycleBackend, unit string, fields map[string]string) (*lifecycleBindObservation, error) {
	if b.binds != nil {
		bindPaths, readOnly, err := b.binds(ctx, unit)
		if err == nil {
			return &lifecycleBindObservation{BindPaths: bindPaths, ReadOnly: readOnly}, nil
		}
		if !errors.Is(err, errTypedBindsUnavailable) {
			return nil, fmt.Errorf("%w: %w", errLifecycleTypedObservation, err)
		}
	}
	bindPaths, err := parseSystemdBindShow(fields["BindPaths"])
	if err != nil {
		return nil, fmt.Errorf("lifecycle bind paths: %w", err)
	}
	readOnly, err := parseSystemdBindShow(fields["BindReadOnlyPaths"])
	if err != nil {
		return nil, fmt.Errorf("lifecycle read-only bind paths: %w", err)
	}
	bindEntries, err := entriesFromCanonicalBinds(bindPaths)
	if err != nil {
		return nil, fmt.Errorf("lifecycle bind paths: %w", err)
	}
	readOnlyEntries, err := entriesFromCanonicalBinds(readOnly)
	if err != nil {
		return nil, fmt.Errorf("lifecycle read-only bind paths: %w", err)
	}
	return &lifecycleBindObservation{BindPaths: bindEntries, ReadOnly: readOnlyEntries}, nil
}

func entriesFromCanonicalBinds(list []string) ([]systemdBindEntry, error) {
	out := make([]systemdBindEntry, 0, len(list))
	for _, recorded := range list {
		src, dest, opt, err := splitCanonicalBind(recorded)
		if err != nil {
			return nil, err
		}
		entry := systemdBindEntry{Source: src, Destination: dest}
		switch opt {
		case "norbind":
		case "rbind":
			entry.Flags = systemdBindRecursiveFlag
		default:
			return nil, fmt.Errorf("recorded bind option %q is not norbind or rbind", opt)
		}
		out = append(out, entry)
	}
	return out, nil
}

func lifecycleFilesystemBindsMatch(observed *lifecycleBindObservation, record containLifecycleRecord) error {
	if observed == nil {
		return errors.New("lifecycle bind paths were not observed")
	}
	if err := matchTypedBindEntries(observed.BindPaths, record.FilesystemBindPaths); err != nil {
		return fmt.Errorf("lifecycle bind paths: %w", err)
	}
	if err := matchTypedBindEntries(observed.ReadOnly, record.FilesystemBindReadOnlyPaths); err != nil {
		return fmt.Errorf("lifecycle read-only bind paths: %w", err)
	}
	return nil
}

func lifecycleFilesystemOwned(fields map[string]string, record containLifecycleRecord, binds *lifecycleBindObservation) error {
	if record.FilesystemMode != config.ContainmentFilesystemModeEnforce {
		return nil
	}
	if fields["ProtectSystem"] != "strict" || fields["ProtectHome"] != "tmpfs" || fields["NoNewPrivileges"] != "yes" {
		return errors.New("lifecycle filesystem profile differs from managed launch")
	}
	if binds == nil {
		bindPaths, err := parseSystemdBindShow(fields["BindPaths"])
		if err != nil {
			return fmt.Errorf("lifecycle bind paths: %w", err)
		}
		if !sameBindList(bindPaths, record.FilesystemBindPaths) {
			return errors.New("lifecycle bind paths differ from managed launch")
		}
		readOnly, err := parseSystemdBindShow(fields["BindReadOnlyPaths"])
		if err != nil {
			return fmt.Errorf("lifecycle read-only bind paths: %w", err)
		}
		if !sameBindList(readOnly, record.FilesystemBindReadOnlyPaths) {
			return errors.New("lifecycle read-only bind paths differ from managed launch")
		}
	} else if err := lifecycleFilesystemBindsMatch(binds, record); err != nil {
		return err
	}
	if err := sameLifecyclePathList(fields["InaccessiblePaths"], record.FilesystemInaccessiblePaths); err != nil {
		return fmt.Errorf("lifecycle inaccessible paths: %w", err)
	}
	if err := sameLifecyclePathList(fields["TemporaryFileSystem"], lifecyclePathSingleton(record.FilesystemTemporaryFileSystem)); err != nil {
		return fmt.Errorf("lifecycle temporary filesystem: %w", err)
	}
	if !systemdShowYes(fields["ProtectKernelTunables"], record.FilesystemProtectKernelTunables) ||
		!systemdShowYes(fields["ProtectKernelModules"], record.FilesystemProtectKernelModules) ||
		!systemdShowYes(fields["ProtectControlGroups"], record.FilesystemProtectControlGroups) {
		return errors.New("lifecycle kernel protection differs from managed launch")
	}
	return nil
}

func lifecyclePathSingleton(path string) []string {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return []string{path}
}

func sameLifecyclePathList(got string, want []string) error {
	parsed, err := parseSystemdPathList(got)
	if err != nil {
		return err
	}
	if !samePathSet(parsed, want) {
		return errors.New("differ from managed launch")
	}
	return nil
}

func parseSystemdPathList(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	tokens, err := splitSystemdShowTokens(value)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(tokens))
	for _, token := range tokens {
		path := unquoteSystemdPath(token)
		if path == "" {
			continue
		}
		out = append(out, path)
	}
	return out, nil
}

func samePathSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	left := append([]string(nil), got...)
	right := append([]string(nil), want...)
	sort.Strings(left)
	sort.Strings(right)
	return slices.Equal(left, right)
}

func systemdShowYes(got, want string) bool {
	if strings.TrimSpace(want) == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(want)) ||
		(strings.EqualFold(want, "yes") && strings.EqualFold(strings.TrimSpace(got), "true"))
}

func lifecycleTerminal(fields map[string]string) bool {
	return fields["LoadState"] == "not-found" || ((fields["ActiveState"] == "inactive" || fields["ActiveState"] == "failed") && fields["MainPID"] == "0")
}

func lifecycleAdmissionPending(fields map[string]string, record containLifecycleRecord) bool {
	if fields["LoadState"] == "not-found" {
		return true
	}
	// Manager object creation and service admission are distinct events. Only
	// the exact reserved marker may wait for its runtime identity to appear;
	// this state never authorizes cleanup.
	return fields["Id"] == record.Unit && fields["Description"] == lifecycleDescriptionPrefix+record.RunID &&
		fields["Transient"] == "yes" && (fields["ActiveState"] == "activating" || fields["ActiveState"] == "inactive") &&
		(fields["InvocationID"] == "" || fields["ControlGroup"] == "")
}

func lifecycleObservationRetryable(ctx context.Context, reserve time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return false
	}
	return time.Until(deadline) > reserve
}

// retryLifecycleTypedObservation repeats a typed bind read until it succeeds,
// the error is not a transport failure, or the deadline no longer leaves
// reserve. Callers pass the admission or cleanup context they already hold.
// There is no extra sleep outside that deadline. A wait that returns without
// blocking is counted so a persistent error cannot busy-loop.
func retryLifecycleTypedObservation(ctx context.Context, b lifecycleBackend, reserve time.Duration, read func() error) error {
	instant := 0
	for {
		err := read()
		if err == nil || !errors.Is(err, errLifecycleTypedObservation) {
			return err
		}
		if b.wait == nil || !lifecycleObservationRetryable(ctx, reserve) {
			return err
		}
		started := time.Now()
		if waitErr := b.wait(ctx, lifecyclePollInterval); waitErr != nil || ctx.Err() != nil {
			return err
		}
		if time.Since(started) < time.Millisecond {
			instant++
			if instant >= lifecycleTypedRetryInstantCap {
				return err
			}
		}
	}
}

// lifecycleFilesystemAdmission retries a transient typed bind read inside the
// admission deadline. Identity is the caller's job. A bind failure is not an
// ownership failure: the caller records that separately.
func lifecycleFilesystemAdmission(ctx context.Context, b lifecycleBackend, fields map[string]string, l *containRunLifecycle, uid uint32) error {
	if l.record.FilesystemMode != config.ContainmentFilesystemModeEnforce {
		return confirmLifecycleFilesystem(ctx, b, fields, l.record)
	}
	witnessedID := fields["InvocationID"]
	return retryLifecycleTypedObservation(ctx, b, 0, func() error {
		current, err := b.show(ctx, l.record.Unit)
		if err != nil {
			return err
		}
		if current["InvocationID"] != witnessedID {
			return errLifecycleInvocationChanged
		}
		if err := lifecycleServiceIdentity(current, l.record, uid); err != nil {
			return err
		}
		return confirmLifecycleFilesystem(ctx, b, current, l.record)
	})
}

// lifecycleOwnershipAllowsAction reads filesystem binds before a destructive
// cleanup action. The optional retry is capped so the remaining helper
// commands still fit in the parent deadline. A bind outage does not block
// stop when ownership was already witnessed; a unit whose identity does not
// match is not stopped.
func lifecycleOwnershipAllowsAction(ctx context.Context, b lifecycleBackend, fields map[string]string, l *containRunLifecycle, uid uint32, commandsAfter int) error {
	reserve := time.Duration(commandsAfter) * lifecycleCommandBudget
	err := confirmLifecycleOwned(ctx, b, fields, l.record, uid)
	if err == nil {
		return nil
	}
	if errors.Is(err, errLifecycleTypedObservation) && lifecycleObservationRetryable(ctx, reserve) {
		allowance := lifecycleBindRetryAllowance(ctx, reserve)
		if allowance > 0 {
			retryCtx, cancel := context.WithTimeout(ctx, allowance)
			retried := retryLifecycleTypedObservation(retryCtx, b, 0, func() error {
				return confirmLifecycleOwned(retryCtx, b, fields, l.record, uid)
			})
			cancel()
			switch {
			case retried == nil:
				return nil
			case errors.Is(retried, context.DeadlineExceeded) && ctx.Err() == nil:
				err = fmt.Errorf("%w: optional bind retry exhausted its budget", errLifecycleTypedObservation)
			default:
				err = retried
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, errLifecycleTypedObservation) && l.record.OwnershipObserved {
		return lifecycleServiceIdentity(fields, l.record, uid)
	}
	return err
}

// lifecycleOwnershipStillWitnessed rechecks identity and argv after a filesystem
// admission failure. A replacement invocation or a failed argv read is not a
// cleanup witness. The bind error stays with the caller.
func lifecycleOwnershipStillWitnessed(ctx context.Context, b lifecycleBackend, l *containRunLifecycle, uid uint32, witnessedID string) (bool, error) {
	if err := verifyLifecycleArgv(ctx, b, l); err != nil {
		return false, err
	}
	current, err := b.show(ctx, l.record.Unit)
	if err != nil {
		return false, err
	}
	if current["InvocationID"] != witnessedID {
		return false, errLifecycleInvocationChanged
	}
	if err := lifecycleServiceIdentity(current, l.record, uid); err != nil {
		return false, err
	}
	return true, nil
}

// lifecycleBindRetryAllowance is the optional retry window. It is one helper
// budget, or less when that budget would enter the reserve kept for the
// commands that still have to run.
func lifecycleBindRetryAllowance(ctx context.Context, reserve time.Duration) time.Duration {
	allowance := lifecycleBindRetryBudget
	deadline, ok := ctx.Deadline()
	if !ok {
		return allowance
	}
	room := time.Until(deadline) - reserve
	if room < allowance {
		allowance = room
	}
	if allowance < 0 {
		return 0
	}
	return allowance
}

// stopLifecycleService acts only after ownership has been witnessed. Filesystem
// admission is not that witness: a bind outage still stops the invocation
// whose identity, cgroup, user, and argv were verified, and it leaves
// admission false. Every destructive operation rechecks the invocation. A
// vanished service is evidence only when its previously observed cgroup is
// also empty/absent.
func stopLifecycleService(ctx context.Context, l *containRunLifecycle, uid uint32, b lifecycleBackend) error {
	if !l.record.OwnershipObserved {
		return errors.New("cannot clean up an unobserved lifecycle invocation")
	}
	start := b.now()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		fields, err := b.show(ctx, l.record.Unit)
		if err != nil {
			return err
		}
		if fields["Id"] != l.record.Unit {
			return errors.New("cleanup observed a different unit")
		}
		if current := fields["InvocationID"]; current != "" && current != l.record.InvocationID {
			return errors.New("cleanup observed a different invocation")
		}
		empty, err := b.cgroupEmpty(l.record.ControlGroup)
		if err != nil {
			return err
		}
		if lifecycleTerminal(fields) && empty {
			// Inactive units can clear InvocationID and ControlGroup. No action
			// is taken here: the retained admitted cgroup and terminal manager
			// state jointly establish that no workload remains.
			if fields["LoadState"] != "not-found" && (fields["Description"] != lifecycleDescriptionPrefix+l.record.RunID || fields["Transient"] != "yes") {
				return errors.New("terminal lifecycle unit ownership changed")
			}
			l.record.CgroupEmpty, l.record.CleanupComplete = true, true
			l.record.Terminal = lifecycleTerminalFields(fields)
			return nil
		}
		if fields["LoadState"] == "not-found" {
			return errors.New("lifecycle unit vanished while its cgroup remained populated")
		}
		if err := lifecycleOwnershipAllowsAction(ctx, b, fields, l, uid, lifecycleCommandsAfterFirstBindCheck); err != nil {
			return err
		}
		if err := verifyLifecycleArgv(ctx, b, l); err != nil {
			return err
		}
		// The typed argv read is a second manager observation; recheck the
		// invocation immediately before acting so the two cannot be mixed.
		confirmed, err := b.show(ctx, l.record.Unit)
		if err != nil {
			return err
		}
		if err := lifecycleOwnershipAllowsAction(ctx, b, confirmed, l, uid, lifecycleCommandsAfterConfirmingBindCheck); err != nil {
			return err
		}
		if !l.record.StopRequested {
			if err := b.action(ctx, l.record.Unit, "--no-block", "stop"); err != nil {
				return err
			}
			l.record.StopRequested = true
		} else if !l.record.KillRequested && b.now().Sub(start) >= 4*time.Second {
			if err := b.action(ctx, l.record.Unit, "kill", "--kill-whom=all", "--signal=KILL"); err != nil {
				return err
			}
			l.record.KillRequested = true
		}
		if err := b.wait(ctx, lifecyclePollInterval); err != nil {
			return err
		}
	}
}

func lifecycleTerminalFields(fields map[string]string) map[string]string {
	result := make(map[string]string)
	for _, key := range []string{"Id", "LoadState", "ActiveState", "SubState", "InvocationID", "ExecMainCode", "ExecMainStatus", "MainPID"} {
		if value, ok := fields[key]; ok {
			result[key] = value
		}
	}
	return result
}

func launchContainedAgentLifecycle(opts containedAgentCommandOptions, l *containRunLifecycle) error {
	return launchContainedAgentLifecycleWithBackend(opts, l, defaultLifecycleBackend(), containedAgentCommand)
}

func launchContainedAgentLifecycleWithBackend(opts containedAgentCommandOptions, l *containRunLifecycle, b lifecycleBackend, command func(containedAgentCommandOptions) (*exec.Cmd, string)) error {
	fields, err := b.show(opts.ctx, l.record.Unit)
	if err != nil {
		return err
	}
	if fields["LoadState"] != "not-found" {
		return errors.New("refusing preexisting lifecycle service")
	}
	l.record.ArgvSHA256, err = stringSliceSHA256(opts.args)
	if err != nil {
		return err
	}
	l.record.FilesystemMode = opts.filesystem.Mode
	if opts.filesystem.Mode == config.ContainmentFilesystemModeEnforce {
		l.record.FilesystemBindPaths = append([]string(nil), opts.filesystem.BindPaths...)
		l.record.FilesystemBindReadOnlyPaths = append([]string(nil), opts.filesystem.BindReadOnlyPaths...)
		l.record.FilesystemInaccessiblePaths = filesystemInaccessiblePaths(opts.filesystem.Properties)
		l.record.FilesystemTemporaryFileSystem = "/dev/shm"
		l.record.FilesystemProtectKernelTunables = "yes"
		l.record.FilesystemProtectKernelModules = "yes"
		l.record.FilesystemProtectControlGroups = "yes"
	}
	l.argv = append([]string{defaultLaunchScript}, opts.args...)
	// Hash the executing image, not a pathname that an atomic replacement
	// could have changed after this process started.
	l.record.BinarySHA256, err = sha256HexOfFile("/proc/self/exe")
	if err != nil {
		return err
	}
	if err := l.write(); err != nil {
		return err
	}
	// Cancellation first stops the owned service, then its systemd-run client.
	// Killing only that client cannot prove the PID1-owned service has stopped.
	runCtx := opts.ctx
	clientCtx, cancelClient := context.WithCancel(context.WithoutCancel(runCtx))
	defer cancelClient()
	opts.lifecycleUnit, opts.lifecycleRunID, opts.ctx = l.record.Unit, l.record.RunID, clientCtx
	cmd, _ := command(opts)
	cmd.Env = lifecycleManagerEnvironment()
	cmd.WaitDelay = lifecycleClientTimeout
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return superviseLifecycleService(runCtx, done, cancelClient, l, opts.uid, b)
}

func superviseLifecycleService(ctx context.Context, done <-chan error, cancelClient context.CancelFunc, l *containRunLifecycle, uid uint32, b lifecycleBackend) error {
	// Cancellation during manager admission gets a short independent
	// observation window. If admission remains unobserved, cleanup is unknown:
	// a submitted PID1-owned service may outlive its client. Never invent an
	// ownership witness or stop a guessed service to cover that failure.
	admission, cancelAdmission := context.WithTimeout(context.WithoutCancel(ctx), lifecycleAdmissionTimeout)
	var primaryErr error
	var clientErr error
	clientDone := false
	for !l.record.AdmissionObserved {
		fields, err := b.show(admission, l.record.Unit)
		if err != nil {
			primaryErr = err
			break
		}
		if !lifecycleAdmissionPending(fields, l.record) {
			if err := lifecycleServiceIdentity(fields, l.record, uid); err != nil {
				primaryErr = err
				break
			}
			if err := verifyLifecycleArgv(admission, b, l); err != nil {
				primaryErr = err
				break
			}
			confirmed, err := b.show(admission, l.record.Unit)
			if err != nil {
				primaryErr = err
				break
			}
			if err := lifecycleServiceIdentity(confirmed, l.record, uid); err != nil {
				primaryErr = err
				break
			}
			if confirmed["InvocationID"] != fields["InvocationID"] {
				primaryErr = errLifecycleInvocationChanged
				break
			}
			fsErr := lifecycleFilesystemAdmission(admission, b, confirmed, l, uid)
			if fsErr != nil {
				witnessed, witnessErr := lifecycleOwnershipStillWitnessed(admission, b, l, uid, confirmed["InvocationID"])
				if !witnessed {
					primaryErr = witnessErr
					break
				}
				// Identity and argv matched. The bind or profile read did not.
				// Record the cleanup witness and leave admission false.
				l.record.OwnershipObserved = true
				l.record.ArgvObserved = true
				l.record.InvocationID, l.record.ControlGroup = confirmed["InvocationID"], confirmed["ControlGroup"]
				primaryErr = fsErr
				if writeErr := l.write(); writeErr != nil {
					primaryErr = errors.Join(fsErr, writeErr)
				}
				break
			}
			l.record.OwnershipObserved = true
			l.record.AdmissionObserved = true
			l.record.ArgvObserved = true
			l.record.InvocationID, l.record.ControlGroup = fields["InvocationID"], fields["ControlGroup"]
			l.record.Phase = "admitted"
			primaryErr = l.write()
			break
		}
		select {
		case clientErr = <-done:
			clientDone = true
			primaryErr = errors.New("lifecycle client exited without an admission witness")
		default:
		}
		if primaryErr != nil {
			break
		}
		if err := b.wait(admission, lifecyclePollInterval); err != nil {
			primaryErr = err
			break
		}
	}
	cancelAdmission()
	if primaryErr == nil {
		select {
		case clientErr = <-done:
			clientDone = true
		case <-ctx.Done():
			primaryErr = ctx.Err()
		}
	}
	cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), lifecycleCleanupTimeout)
	cleanupErr := stopLifecycleService(cleanupCtx, l, uid, b)
	cancelCleanup()
	cancelClient()
	if !clientDone {
		timer := time.NewTimer(lifecycleClientTimeout)
		select {
		case clientErr = <-done:
		case <-timer.C:
			clientErr = errors.New("lifecycle systemd-run client did not exit within deadline")
		}
		timer.Stop()
	}
	cancelErr := ctx.Err()
	result := errors.Join(primaryErr, cleanupErr, clientErr, cancelErr)
	l.record.Cancelled = cancelErr != nil
	l.record.Final = true
	l.record.Phase = "complete"
	if result != nil {
		l.record.Phase = "incomplete"
		l.record.Failure = boundedLifecycleError(result)
	}
	return errors.Join(result, l.write())
}
