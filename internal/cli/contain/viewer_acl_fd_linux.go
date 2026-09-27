// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"golang.org/x/sys/unix"
)

// runViewerACLCommand makes the held inode fd 3 in the child. ACL tools must
// follow this one procfs magic link to reach the inode; their -P option rejects
// /proc/self/fd/3 itself, so it cannot be used with this descriptor path.
func runViewerACLCommand(ctx context.Context, file *os.File, name string, args ...string) (string, int, error) {
	args = append([]string(nil), args...)
	args[len(args)-1] = "/proc/self/fd/3"
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- caller supplies only getfacl/setfacl with fixed arguments.
	cmd.ExtraFiles = []*os.File{file}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return string(out), exit.ExitCode(), nil
	}
	return string(out), -1, err
}

func viewerACLExpectedUID(env *installEnv) (uint32, error) {
	if env.viewerACLUID != nil {
		return *env.viewerACLUID, nil
	}
	if env.lookupUser == nil {
		return 0, errors.New("legacy viewer ACL agent lookup unavailable")
	}
	agent, err := env.lookupUser(env.agentUserName)
	if err != nil {
		return 0, fmt.Errorf("lookup legacy viewer ACL owner: %w", err)
	}
	uid, err := strconv.ParseUint(agent.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse legacy viewer ACL owner: %w", err)
	}
	return uint32(uid), nil
}

func openViewerACLDir(parent *os.File, name, displayPath string, uid uint32) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open legacy viewer traverse path %s without following symlinks: %w", displayPath, err)
	}
	file := os.NewFile(uintptr(fd), displayPath)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat legacy viewer traverse path %s: %w", displayPath, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid {
		_ = file.Close()
		return nil, fmt.Errorf("legacy viewer traverse path %s is not an agent-owned real directory", displayPath)
	}
	return file, nil
}

func revokePinnedViewerACL(ctx context.Context, env *installEnv, file *os.File) error {
	if env.runViewerACL == nil {
		return errors.New("legacy viewer ACL command unavailable")
	}
	pinned := *env
	pinned.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		return env.runViewerACL(ctx, file, name, args...)
	}
	return revokeViewerTraverseDir(ctx, &pinned, file.Name())
}

func removeViewerTraverseACLNoFollow(ctx context.Context, env *installEnv) error {
	if env.agentHome == "" {
		return nil
	}
	uid, err := viewerACLExpectedUID(env)
	if err != nil {
		return err
	}
	homeFD, err := unix.Open(env.agentHome, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open legacy viewer traverse path %s without following symlinks: %w", env.agentHome, err)
	}
	current := os.NewFile(uintptr(homeFD), env.agentHome)
	defer func() { _ = current.Close() }()
	var homeStat unix.Stat_t
	if err := unix.Fstat(homeFD, &homeStat); err != nil {
		return fmt.Errorf("stat legacy viewer traverse path %s: %w", env.agentHome, err)
	}
	if homeStat.Mode&unix.S_IFMT != unix.S_IFDIR || homeStat.Uid != uid {
		return fmt.Errorf("legacy viewer traverse path %s is not an agent-owned real directory", env.agentHome)
	}
	if err := revokePinnedViewerACL(ctx, env, current); err != nil {
		return err
	}
	for _, part := range []string{".local", "state", "pipelock", "display"} {
		path := current.Name() + "/" + part
		next, err := openViewerACLDir(current, part, path, uid)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err != nil {
			return err
		}
		_ = current.Close()
		current = next
		if err := revokePinnedViewerACL(ctx, env, current); err != nil {
			return err
		}
	}
	const leaf = "rfb.sock"
	socket := current.Name() + "/" + leaf
	var st unix.Stat_t
	if err := unix.Fstatat(int(current.Fd()), leaf, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect legacy RFB socket: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != uid {
		return fmt.Errorf("legacy RFB path %s is not an agent-owned socket", socket)
	}
	fd, err := unix.Openat(int(current.Fd()), leaf, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open legacy RFB socket: %w", err)
	}
	file := os.NewFile(uintptr(fd), socket)
	defer func() { _ = file.Close() }()
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat legacy RFB socket: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != uid {
		return fmt.Errorf("legacy RFB path %s is not an agent-owned socket", socket)
	}
	if err := revokePinnedViewerACL(ctx, env, file); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(current.Fd()), leaf, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove legacy RFB socket: %w", err)
	}
	return nil
}
