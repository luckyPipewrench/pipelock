// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package contain

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const agentBrowserNonblock = 0

// Containment installs are Linux-only. This preserves the previous browser
// config behavior for Windows builds and local config tooling.
type browserDir struct{ root *os.Root }

func openBrowserDir(env *installEnv, root *os.Root, create bool, _, _ int) (*browserDir, error) {
	info, err := browserLstat(env, root, agentBrowserDir)
	if errors.Is(err, os.ErrNotExist) && create {
		if err := root.Mkdir(agentBrowserDir, modeDirPrivate); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("mkdir agent-browser directory: %w", err)
		}
		info, err = browserLstat(env, root, agentBrowserDir)
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink; refusing privileged access", agentBrowserDir)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s exists and is not a directory", agentBrowserDir)
	}
	return &browserDir{root: root}, nil
}

func (d *browserDir) Close() error { return nil }
func (d *browserDir) lstat(name string) (os.FileInfo, error) {
	return d.root.Lstat(filepath.Join(agentBrowserDir, name))
}

func (d *browserDir) open(name string, flags int, mode os.FileMode) (*os.File, error) {
	return d.root.OpenFile(filepath.Join(agentBrowserDir, name), flags, mode)
}

func (d *browserDir) remove(name string) error {
	return d.root.Remove(filepath.Join(agentBrowserDir, name))
}

func (d *browserDir) rename(oldName, newName string) error {
	return d.root.Rename(filepath.Join(agentBrowserDir, oldName), filepath.Join(agentBrowserDir, newName))
}
