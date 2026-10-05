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
	defer func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
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
	cleanups = append(cleanups, func() { opParent.removeDir(opName) }, opDir.close)
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
	cleanups = append(cleanups, func() { stateParent.removeDir(writeName) }, writeDir.close)
	secretName, secretDir, err := stateParent.mkdirExclusive(".pipelock-fs-secret-", 0o755)
	if err != nil {
		return statusFail, fmt.Sprintf("create secret canary: %v", err)
	}
	cleanups = append(cleanups, func() { stateParent.removeDir(secretName) }, secretDir.close)
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
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s without following symlinks: %w", path, err)
	}
	return &noFollowDir{file: os.NewFile(uintptr(fd), path), path: path}, nil
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

func (d *noFollowDir) removeDir(name string) {
	if d == nil || d.file == nil {
		return
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		child := &noFollowDir{file: os.NewFile(uintptr(fd), name)}
		child.removeEntries()
		child.close()
	}
	_ = unix.Unlinkat(int(d.file.Fd()), name, unix.AT_REMOVEDIR)
}

func (d *noFollowDir) removeEntries() {
	if d == nil || d.file == nil {
		return
	}
	names, err := d.file.Readdirnames(-1)
	if err != nil {
		return
	}
	for _, name := range names {
		if err := unix.Unlinkat(int(d.file.Fd()), name, 0); err == nil {
			continue
		}
		d.removeDir(name)
	}
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
