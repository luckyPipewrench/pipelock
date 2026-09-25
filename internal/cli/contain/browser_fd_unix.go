// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package contain

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const agentBrowserNonblock = unix.O_NONBLOCK

// browserDir pins the agent-controlled directory for config mutations. The
// optional path check is diagnostic; openat, renameat, and unlinkat use this fd.
type browserDir struct {
	file *os.File
	env  *installEnv
	root *os.Root
}

func openBrowserDir(env *installEnv, root *os.Root, create bool, uid, gid int) (*browserDir, error) {
	// Keep the existing hook for fault injection, but never trust its result as
	// the security check: openat and fstat decide which inode is used.
	if _, err := browserLstat(env, root, agentBrowserDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	homeFile, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open agent home: %w", err)
	}
	defer func() { _ = homeFile.Close() }()
	home := int(homeFile.Fd())
	fd, err := unix.Openat(home, agentBrowserDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) && create {
		mkErr := unix.Mkdirat(home, agentBrowserDir, uint32(modeDirPrivate))
		if mkErr != nil && !errors.Is(mkErr, unix.EEXIST) {
			return nil, fmt.Errorf("mkdir agent-browser directory: %w", mkErr)
		}
		fd, err = unix.Openat(home, agentBrowserDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == nil && mkErr == nil {
			f := os.NewFile(uintptr(fd), agentBrowserDir)
			if chownErr := browserFchown(env, f, uid, gid); chownErr != nil {
				_ = f.Close()
				return nil, fmt.Errorf("chown agent-browser directory: %w", chownErr)
			}
			// Keep f alive through the owner check below.
			return checkedBrowserDir(env, root, f, uid)
		}
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("agent-browser directory is a symlink: %w", err)
		}
		return nil, fmt.Errorf("open agent-browser directory: %w", err)
	}
	return checkedBrowserDir(env, root, os.NewFile(uintptr(fd), agentBrowserDir), uid)
}

func checkedBrowserDir(env *installEnv, root *os.Root, f *os.File, uid int) (*browserDir, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat agent-browser directory: %w", err)
	}
	owned := int64(st.Uid) == int64(uid)
	if env.agentBrowserDirOwner != nil {
		owned = env.agentBrowserDirOwner(f, uid)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || !owned {
		_ = f.Close()
		return nil, fmt.Errorf("agent-browser directory is not agent-owned")
	}
	return &browserDir{file: f, env: env, root: root}, nil
}

func (d *browserDir) Close() error { return d.file.Close() }

func browserBase(name string) (string, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return "", fmt.Errorf("invalid agent-browser leaf %q", name)
	}
	return name, nil
}

func (d *browserDir) lstat(name string) (os.FileInfo, error) {
	name, err := browserBase(name)
	if err != nil {
		return nil, err
	}
	if d.root != nil {
		if _, err := browserLstat(d.env, d.root, filepath.Join(agentBrowserDir, name)); err != nil {
			return nil, err
		}
	}
	f, err := d.open(name, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return nil, fmt.Errorf("%s is a symlink: %w", name, err)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return f.Stat()
}

func (d *browserDir) open(name string, flags int, mode os.FileMode) (*os.File, error) {
	name, err := browserBase(name)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), filepath.Join(agentBrowserDir, name)), nil
}

func (d *browserDir) remove(name string) error {
	name, err := browserBase(name)
	if err != nil {
		return err
	}
	if d.env.agentBrowserRemove != nil {
		if err := d.env.agentBrowserRemove(d.root, filepath.Join(agentBrowserDir, name)); err != nil {
			return err
		}
	}
	return unix.Unlinkat(int(d.file.Fd()), name, 0)
}

func (d *browserDir) rename(oldName, newName string) error {
	oldName, err := browserBase(oldName)
	if err != nil {
		return err
	}
	newName, err = browserBase(newName)
	if err != nil {
		return err
	}
	return unix.Renameat(int(d.file.Fd()), oldName, int(d.file.Fd()), newName)
}
