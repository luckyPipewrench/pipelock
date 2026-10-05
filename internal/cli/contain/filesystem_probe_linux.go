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
	"syscall"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

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
	// ProtectSystem=strict remounts /usr, /boot, /efi, and /etc read-only.
	// /var stays writable, so a canary there would succeed and refuse every
	// enforce launch. /usr is outside /home, /tmp, /var/tmp, /dev, /proc, and /sys.
	filesystemWriteCanaryParent = "/usr"
	filesystemMkdir             = os.Mkdir
	filesystemWriteFile         = os.WriteFile
	filesystemChmod             = os.Chmod
	filesystemRemove            = os.Remove
	filesystemRemoveAll         = os.RemoveAll
	filesystemStatInode         = defaultFilesystemStatInode
)

func probeFilesystemConfinementEnforce(ctx context.Context, env *probeEnv, profile filesystemProfile) (string, string) {
	if env == nil || env.runCmd == nil {
		return statusFail, "filesystem confinement canary has no command runner"
	}
	if profile.Mode != config.ContainmentFilesystemModeEnforce {
		return statusFilesystemOff, "filesystem profile: off"
	}
	if !filesystemCanaryRoot() {
		return statusFail, "filesystem confinement canary requires root to start a transient systemd service"
	}
	id, err := filesystemCanaryID()
	if err != nil {
		return statusFail, fmt.Sprintf("filesystem confinement canary id: %v", err)
	}
	opDir := filepath.Join(filesystemOperatorCanaryParent, ".pipelock-fs-canary-"+id)
	if err := filesystemMkdir(opDir, 0o755); err != nil {
		return statusFail, fmt.Sprintf("create operator home canary: %v", err)
	}
	defer func() { _ = filesystemRemoveAll(opDir) }()
	opFile := filepath.Join(opDir, "canary")
	if err := filesystemWriteFile(opFile, []byte("canary\n"), 0o644); err != nil {
		return statusFail, fmt.Sprintf("write operator home canary: %v", err)
	}
	inode, err := filesystemStatInode(opFile)
	if err != nil {
		return statusFail, fmt.Sprintf("stat operator home canary: %v", err)
	}
	writeDir := filepath.Join(filesystemWriteCanaryParent, ".pipelock-fs-write-"+id)
	if err := filesystemMkdir(writeDir, 0o755); err != nil {
		return statusFail, fmt.Sprintf("create write canary: %v", err)
	}
	defer func() { _ = filesystemRemoveAll(writeDir) }()
	if err := filesystemChmod(writeDir, 0o1777); err != nil {
		return statusFail, fmt.Sprintf("chmod write canary: %v", err)
	}
	secretDir, err := firstInaccessibleDirectory(profile.Properties)
	if err != nil {
		return statusFail, err.Error()
	}
	secretFile := filepath.Join(secretDir, ".pipelock-fs-secret-"+id)
	if err := filesystemWriteFile(secretFile, []byte("secret\n"), 0o644); err != nil {
		return statusFail, fmt.Sprintf("write secret canary: %v", err)
	}
	defer func() { _ = filesystemRemove(secretFile) }()
	if err := filesystemChmod(secretFile, 0o644); err != nil {
		return statusFail, fmt.Sprintf("chmod secret canary: %v", err)
	}
	workspace := ""
	if dir := filesystemWorkspaceCanaryDir(profile, env.agentHome); dir != "" {
		workspace = filepath.Join(dir, ".pipelock-fs-workspace-"+id)
		if err := filesystemWriteFile(workspace, []byte("workspace\n"), 0o666); err != nil {
			return statusFail, fmt.Sprintf("write workspace canary: %v", err)
		}
		defer func() { _ = filesystemRemove(workspace) }()
		if err := filesystemChmod(workspace, 0o666); err != nil {
			return statusFail, fmt.Sprintf("chmod workspace canary: %v", err)
		}
	}
	command := []string{"/bin/bash", "-c", filesystemCanaryScript, "bash", opFile, inode, writeDir, workspace, secretFile}
	args, err := privateTmpSystemdRunArgsForAgentProperties(env, command, profile.Properties)
	if err != nil {
		return statusFail, fmt.Sprintf("prepare filesystem confinement canary: %v", err)
	}
	out, code, err := env.runCmd(ctx, systemdRunPath, args...)
	if err != nil {
		return statusFail, fmt.Sprintf("filesystem confinement canary could not start: %v", err)
	}
	return filesystemCanaryOutcome(code, out)
}

func filesystemCanaryID() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

func defaultFilesystemStatInode(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("inode unavailable")
	}
	return strconv.FormatUint(stat.Ino, 10), nil
}

// firstInaccessibleDirectory returns the first hidden path the canary can put
// a world-readable file inside. A hidden file cannot host that file, and
// reading the file itself would pass on mode 0600 even with no hide.
func firstInaccessibleDirectory(properties []string) (string, error) {
	saw := false
	for _, prop := range properties {
		rest, ok := strings.CutPrefix(prop, "InaccessiblePaths=")
		if !ok || rest == "" {
			continue
		}
		saw = true
		target := unquoteSystemdPath(rest)
		info, err := os.Stat(target)
		if err != nil {
			return "", fmt.Errorf("stat inaccessible path %s: %w", target, err)
		}
		if info.IsDir() {
			return target, nil
		}
	}
	if !saw {
		return "", errors.New("filesystem profile has no inaccessible path to prove")
	}
	return "", errors.New("filesystem profile has no inaccessible directory to prove")
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
