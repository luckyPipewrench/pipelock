// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const filesystemBaselineScript = `
op="$1"
inode="$2"
secret="$3"
if ! got=$(stat -c %i "$op" 2>/dev/null); then
  exit 21
fi
if [ "$got" != "$inode" ]; then
  exit 21
fi
if [ ! -r "$secret" ]; then
  exit 22
fi
exit 0
`

const filesystemCanaryScript = `
op="$1"
inode="$2"
write_dir="$3"
workspace="$4"
secret="$5"
if got=$(stat -c %i "$op" 2>/dev/null); then
  if [ "$got" = "$inode" ]; then
    exit 11
  fi
fi
err=$(touch "$write_dir/pipelock-write-canary" 2>&1) && exit 12
case "$err" in
  *"Read-only file system"*|*"EROFS"*) ;;
  *) exit 12 ;;
esac
if [ -n "$workspace" ]; then
  if [ ! -r "$workspace" ]; then exit 13; fi
  if ! echo x >> "$workspace" 2>/dev/null; then exit 13; fi
fi
if [ -r "$secret" ]; then exit 14; fi
exit 0
`

var (
	filesystemCanaryRoot           = isRoot
	filesystemOperatorCanaryParent = "/home"
	// ProtectSystem=strict mounts the whole hierarchy read-only except /dev,
	// /proc, /sys, and explicit binds. A canary under /usr fails on a host
	// whose /usr is already read-only, and then every enforce launch is
	// refused. /var/lib is writable for root on the host and read-only inside
	// the profile, so the create is rejected only after the sandbox is applied.
	filesystemStateCanaryParent = "/var/lib"
)

func probeFilesystemConfinementEnforce(ctx context.Context, env *probeEnv, profile filesystemProfile) (status, detail string) {
	if env == nil || env.runCmd == nil {
		return statusFail, "filesystem confinement canary has no command runner"
	}
	if profile.Mode != config.ContainmentFilesystemModeEnforce {
		return statusFilesystemOff, "filesystem profile: off"
	}
	if !filesystemCanaryRoot() {
		return statusFail, "filesystem confinement canary requires root to start a transient systemd service"
	}
	var cleanups []func()
	var cleanupErr error
	recordCleanup := func(err error) {
		cleanupErr = errors.Join(cleanupErr, err)
	}
	defer func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
		status, detail = filesystemCleanupResult(status, detail, cleanupErr)
	}()

	opParent, err := openNoFollowDir(filesystemOperatorCanaryParent)
	if err != nil {
		return statusFail, fmt.Sprintf("open operator home canary parent: %v", err)
	}
	cleanups = append(cleanups, opParent.close)
	opName, opDir, err := opParent.mkdirExclusive(".pipelock-fs-canary-", 0o755)
	if err != nil {
		return statusFail, fmt.Sprintf("create operator home canary: %v", err)
	}
	cleanups = append(cleanups, func() { recordCleanup(opParent.removeBounded(ctx, opName)) }, opDir.close)
	opFile, inode, err := opDir.createExclusiveFile("canary-", 0o644, []byte("canary\n"))
	if err != nil {
		return statusFail, fmt.Sprintf("write operator home canary: %v", err)
	}
	cleanups = append(cleanups, func() { opDir.unlink(opFile) })

	stateParent, err := openNoFollowDir(filesystemStateCanaryParent)
	if err != nil {
		return statusFail, fmt.Sprintf("open filesystem canary parent: %v", err)
	}
	cleanups = append(cleanups, stateParent.close)
	writeName, writeDir, err := stateParent.mkdirExclusive(".pipelock-fs-write-", 0o1777)
	if err != nil {
		return statusFail, fmt.Sprintf("create write canary: %v", err)
	}
	cleanups = append(cleanups, func() { recordCleanup(stateParent.removeBounded(ctx, writeName)) }, writeDir.close)
	secretName, secretDir, err := stateParent.mkdirExclusive(".pipelock-fs-secret-", 0o755)
	if err != nil {
		return statusFail, fmt.Sprintf("create secret canary: %v", err)
	}
	cleanups = append(cleanups, func() { recordCleanup(stateParent.removeBounded(ctx, secretName)) }, secretDir.close)
	secretFile, _, err := secretDir.createExclusiveFile("secret-", 0o644, []byte("secret\n"))
	if err != nil {
		return statusFail, fmt.Sprintf("write secret canary: %v", err)
	}
	cleanups = append(cleanups, func() { secretDir.unlink(secretFile) })

	opPath := filepath.Join(opDir.path, opFile)
	writePath := writeDir.path
	secretPath := filepath.Join(secretDir.path, secretFile)
	workspace := ""
	if dir := filesystemWorkspaceCanaryDir(profile, env.agentHome); dir != "" {
		wsParent, wsErr := openNoFollowDir(dir)
		if wsErr != nil {
			return statusFail, fmt.Sprintf("open workspace canary: %v", wsErr)
		}
		cleanups = append(cleanups, wsParent.close)
		wsFile, _, wsErr := wsParent.createExclusiveFile(".pipelock-fs-workspace-", 0o666, []byte("workspace\n"))
		if wsErr != nil {
			return statusFail, fmt.Sprintf("write workspace canary: %v", wsErr)
		}
		cleanups = append(cleanups, func() { wsParent.unlink(wsFile) })
		workspace = filepath.Join(wsParent.path, wsFile)
	}

	baseline := []string{"/bin/bash", "-c", filesystemBaselineScript, "bash", opPath, inode, secretPath}
	baseArgs, err := privateTmpSystemdRunArgsForAgent(env, baseline)
	if err != nil {
		return statusFail, fmt.Sprintf("prepare filesystem confinement baseline: %v", err)
	}
	baseOut, baseCode, err := env.runCmd(ctx, systemdRunPath, baseArgs...)
	if err != nil {
		return statusFail, fmt.Sprintf("filesystem confinement baseline could not start: %v", err)
	}
	if baseCode != 0 {
		return statusFail, filesystemBaselineFailure(baseCode, baseOut)
	}

	props := append([]string{}, profile.Properties...)
	props = append(props, "InaccessiblePaths="+systemdPathToken(secretDir.path))
	if env.filesystemCanaryOmitProperties {
		props = nil
	}
	command := []string{"/bin/bash", "-c", filesystemCanaryScript, "bash", opPath, inode, writePath, workspace, secretPath}
	args, err := privateTmpSystemdRunArgsForAgentProperties(env, command, props)
	if err != nil {
		return statusFail, fmt.Sprintf("prepare filesystem confinement canary: %v", err)
	}
	out, code, err := env.runCmd(ctx, systemdRunPath, args...)
	if err != nil {
		return statusFail, fmt.Sprintf("filesystem confinement canary could not start: %v", err)
	}
	return filesystemCanaryOutcome(code, out)
}

func filesystemBaselineFailure(code int, output string) string {
	switch code {
	case 21:
		return "operator home canary is not a valid proof"
	case 22:
		return "secret canary is not a valid proof"
	default:
		if output == "" {
			return fmt.Sprintf("filesystem canary is not a valid proof (baseline exited %d)", code)
		}
		return fmt.Sprintf("filesystem canary is not a valid proof (baseline exited %d): %s", code, oneLine(output))
	}
}

type noFollowDir struct {
	file *os.File
	path string
}

func openNoFollowDir(path string) (*noFollowDir, error) {
	cleaned, err := cleanLinuxPath(path)
	if err != nil {
		return nil, err
	}
	if cleaned == "/" {
		return nil, errors.New("refusing to pin the filesystem root")
	}
	root, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	defer func() { _ = unix.Close(root) }()
	fd, err := openatNoSymlinkDir(root, strings.TrimPrefix(cleaned, "/"))
	if err != nil {
		return nil, fmt.Errorf("open %s without following symlinks: %w", cleaned, err)
	}
	return &noFollowDir{file: os.NewFile(uintptr(fd), cleaned), path: cleaned}, nil
}

// openatNoSymlinkDir opens rel under dirfd. openat2 refuses a symlink in any
// component and refuses a walk that leaves dirfd. A kernel that cannot do
// that open fails closed; a path open would follow the intermediate link.
func openatNoSymlinkDir(dirfd int, rel string) (int, error) {
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	}
	fd, err := unix.Openat2(dirfd, rel, how)
	if err == nil {
		return fd, nil
	}
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
		return -1, fmt.Errorf("openat2 symlink-safe open is unavailable: %w", err)
	}
	return -1, err
}

func (d *noFollowDir) close() {
	if d != nil && d.file != nil {
		_ = d.file.Close()
		d.file = nil
	}
}

func (d *noFollowDir) mkdirExclusive(prefix string, mode uint32) (string, *noFollowDir, error) {
	var last error
	for range 8 {
		name, err := randomCanaryComponent(prefix)
		if err != nil {
			return "", nil, err
		}
		if err := unix.Mkdirat(int(d.file.Fd()), name, mode); err != nil {
			if errors.Is(err, unix.EEXIST) {
				last = err
				continue
			}
			return "", nil, err
		}
		fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			_ = unix.Unlinkat(int(d.file.Fd()), name, unix.AT_REMOVEDIR)
			return "", nil, err
		}
		if err := unix.Fchmod(fd, mode); err != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(int(d.file.Fd()), name, unix.AT_REMOVEDIR)
			return "", nil, err
		}
		full := filepath.Join(d.path, name)
		return name, &noFollowDir{file: os.NewFile(uintptr(fd), full), path: full}, nil
	}
	if last == nil {
		last = errors.New("no name available")
	}
	return "", nil, last
}

func (d *noFollowDir) createExclusiveFile(prefix string, mode uint32, body []byte) (string, string, error) {
	var last error
	for range 8 {
		name, err := randomCanaryComponent(prefix)
		if err != nil {
			return "", "", err
		}
		fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_WRONLY|unix.O_CLOEXEC, mode)
		if err != nil {
			if errors.Is(err, unix.EEXIST) {
				last = err
				continue
			}
			return "", "", err
		}
		if err := unix.Fchmod(fd, mode); err != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(int(d.file.Fd()), name, 0)
			return "", "", err
		}
		file := os.NewFile(uintptr(fd), filepath.Join(d.path, name))
		_, writeErr := file.Write(body)
		var st unix.Stat_t
		statErr := unix.Fstat(fd, &st)
		closeErr := file.Close()
		if err := errors.Join(writeErr, statErr, closeErr); err != nil {
			_ = unix.Unlinkat(int(d.file.Fd()), name, 0)
			return "", "", err
		}
		return name, strconv.FormatUint(st.Ino, 10), nil
	}
	if last == nil {
		last = errors.New("no name available")
	}
	return "", "", last
}

func (d *noFollowDir) unlink(name string) {
	if d == nil || d.file == nil {
		return
	}
	_ = unix.Unlinkat(int(d.file.Fd()), name, 0)
}

const (
	filesystemCleanupMaxEntries = 64
	filesystemCleanupMaxDepth   = 8
	filesystemCleanupBatch      = 16
)

func filesystemCleanupResult(status, detail string, err error) (string, string) {
	if err == nil {
		return status, detail
	}
	if status == statusPass || detail == "" {
		return statusFail, err.Error()
	}
	return statusFail, detail + "; " + err.Error()
}

// removeDir deletes one canary directory without following symlinks. Callers
// that must fail the probe use removeBounded so a huge tree cannot hang cleanup.
func (d *noFollowDir) removeDir(name string) {
	if d == nil {
		return
	}
	_ = d.removeBounded(context.Background(), name)
}

func (d *noFollowDir) removeBounded(ctx context.Context, name string) error {
	if d == nil || d.file == nil {
		return errors.New("filesystem canary cleanup directory is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	seen := 0
	return d.removeTree(ctx, name, 0, &seen)
}

func (d *noFollowDir) removeTree(ctx context.Context, name string, depth int, seen *int) error {
	leftover := d.path
	if leftover == "" {
		leftover = name
	} else {
		leftover = filepath.Join(d.path, name)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("filesystem canary cleanup stopped at %s: %w", leftover, err)
	}
	if depth > filesystemCleanupMaxDepth {
		return fmt.Errorf("filesystem canary cleanup exceeded its depth at %s", leftover)
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if unlinkErr := unix.Unlinkat(int(d.file.Fd()), name, 0); unlinkErr != nil {
			return fmt.Errorf("filesystem canary cleanup stopped at %s: %w", leftover, unlinkErr)
		}
		*seen++
		return nil
	}
	child := &noFollowDir{file: os.NewFile(uintptr(fd), leftover), path: leftover}
	defer child.close()
	if err := child.removeChildren(ctx, depth, seen); err != nil {
		return err
	}
	child.close()
	if err := unix.Unlinkat(int(d.file.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("filesystem canary cleanup stopped at %s: %w", leftover, err)
	}
	return nil
}

func (d *noFollowDir) removeChildren(ctx context.Context, depth int, seen *int) error {
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("filesystem canary cleanup stopped at %s: %w", d.path, err)
		}
		names, err := d.file.Readdirnames(filesystemCleanupBatch)
		if err != nil && !errors.Is(err, io.EOF) && len(names) == 0 {
			return fmt.Errorf("filesystem canary cleanup stopped at %s: %w", d.path, err)
		}
		if len(names) == 0 {
			return nil
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("filesystem canary cleanup stopped at %s: %w", d.path, err)
			}
			if *seen >= filesystemCleanupMaxEntries {
				return fmt.Errorf("filesystem canary cleanup exceeded its entry limit at %s", d.path)
			}
			if err := d.removeOne(ctx, name, depth, seen); err != nil {
				return err
			}
		}
	}
}

func (d *noFollowDir) removeOne(ctx context.Context, name string, depth int, seen *int) error {
	var st unix.Stat_t
	if err := unix.Fstatat(int(d.file.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("filesystem canary cleanup stopped at %s: %w", filepath.Join(d.path, name), err)
	}
	*seen++
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(int(d.file.Fd()), name, 0); err != nil {
			return fmt.Errorf("filesystem canary cleanup stopped at %s: %w", filepath.Join(d.path, name), err)
		}
		return nil
	}
	return d.removeTree(ctx, name, depth+1, seen)
}

func randomCanaryComponent(prefix string) (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buf[:]), nil
}

func filesystemWorkspaceCanaryDir(profile filesystemProfile, agentHome string) string {
	home := ""
	if cleaned, err := cleanLinuxPath(agentHome); err == nil {
		home = cleaned
	}
	for _, bind := range profile.BindPaths {
		src, _, _ := strings.Cut(bind, ":")
		if src == "" || src == home {
			continue
		}
		return src
	}
	return ""
}
