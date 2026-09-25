// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/browserdefaults"
)

// agentBrowserDefaultsRecordFile is the ownership record for the Chromium
// default merged into the contained agent's agent-browser config.
const agentBrowserDefaultsRecordFile = "agent-browser-defaults.json"

func browserFchown(env *installEnv, f *os.File, uid, gid int) error {
	if env.agentBrowserFchown != nil {
		return env.agentBrowserFchown(f, uid, gid)
	}
	return f.Chown(uid, gid)
}

func browserWrite(env *installEnv, f *os.File, data []byte) (int, error) {
	if env.agentBrowserWrite != nil {
		return env.agentBrowserWrite(f, data)
	}
	return f.Write(data)
}

func browserLstat(env *installEnv, root *os.Root, name string) (os.FileInfo, error) {
	if env.agentBrowserLstat != nil {
		return env.agentBrowserLstat(root, name)
	}
	return root.Lstat(name)
}

const (
	agentBrowserDir  = ".agent-browser"
	agentBrowserFile = agentBrowserDir + "/config.json"
)

func openAgentBrowserHome(env *installEnv) (*os.Root, error) {
	home := agentHomeDir(env)
	if err := ensureSafeDirectory(env, home); err != nil {
		return nil, fmt.Errorf("agent home: %w", err)
	}
	if err := env.mkdirAll(home, modeDirPrivate); err != nil {
		return nil, fmt.Errorf("mkdir agent home: %w", err)
	}
	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, fmt.Errorf("open agent home: %w", err)
	}
	return root, nil
}

func agentBrowserUID(env *installEnv) (int, int, error) {
	uid, gid, err := uidGidFor(env, env.agentUserName)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve %s uid: %w", env.agentUserName, err)
	}
	return uid, gid, nil
}

func openAgentBrowserDir(env *installEnv, root *os.Root, create bool) (*browserDir, error) {
	uid, gid, err := agentBrowserUID(env)
	if err != nil {
		return nil, err
	}
	return openBrowserDir(env, root, create, uid, gid)
}

func agentBrowserLeaf(dir *browserDir, name string) (os.FileInfo, error) {
	info, err := dir.lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink; refusing privileged access", name)
	}
	return info, nil
}

func readAgentBrowserRoot(env *installEnv, root *os.Root) ([]byte, bool, error) {
	dir, err := openAgentBrowserDir(env, root, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = dir.Close() }()
	info, err := agentBrowserLeaf(dir, "config.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s exists and is not a regular file", agentBrowserFile)
	}
	f, err := dir.open("config.json", os.O_RDONLY|agentBrowserNonblock, 0)
	if err != nil {
		return nil, false, fmt.Errorf("open agent-browser config: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err = f.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("stat agent-browser config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s exists and is not a regular file", agentBrowserFile)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, false, fmt.Errorf("read agent-browser config: %w", err)
	}
	return data, true, nil
}

func writeAgentBrowserDir(env *installEnv, dir *browserDir, name string, data []byte, uid, gid int) error {
	if info, err := agentBrowserLeaf(dir, name); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s exists and is not a regular file", name)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := dir.open(name, os.O_WRONLY|os.O_CREATE|agentBrowserNonblock, modeAgentConfig)
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s exists and is not a regular file", name)
	}
	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("truncate %s: %w", name, err)
	}
	if err := f.Chmod(modeAgentConfig); err != nil {
		return fmt.Errorf("chmod %s: %w", name, err)
	}
	if _, err := browserWrite(env, f, data); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := browserFchown(env, f, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", name, err)
	}
	return nil
}

func writeAgentBrowserRoot(env *installEnv, root *os.Root, name string, data []byte, uid, gid int) error {
	dir, err := openBrowserDir(env, root, true, uid, gid)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return writeAgentBrowserDir(env, dir, filepath.Base(name), data, uid, gid)
}

func ownAgentBrowserDirs(env *installEnv, root *os.Root, uid, gid int) error {
	f, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open agent home: %w", err)
	}
	if err := browserFchown(env, f, uid, gid); err != nil {
		_ = f.Close()
		return fmt.Errorf("chown agent home: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close agent home: %w", err)
	}
	dir, err := openBrowserDir(env, root, true, uid, gid)
	if err != nil {
		return err
	}
	return dir.Close()
}

func restoreAgentBrowserDir(env *installEnv, dir *browserDir) error {
	if _, err := agentBrowserLeaf(dir, "config.json.bak"); err == nil {
		if err := dir.remove("config.json"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove managed agent-browser config: %w", err)
		}
		if err := dir.rename("config.json.bak", "config.json"); err != nil {
			return fmt.Errorf("restore agent-browser config: %w", err)
		}
		if archive := popArchivedBackup(env, agentBrowserConfigPath(env)+".bak"); archive != "" {
			leaf := filepath.Base(archive)
			if _, err := agentBrowserLeaf(dir, leaf); err != nil {
				return fmt.Errorf("stat archived agent-browser backup: %w", err)
			}
			if err := dir.rename(leaf, "config.json.bak"); err != nil {
				return fmt.Errorf("restore archived agent-browser backup: %w", err)
			}
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := dir.remove("config.json"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove agent-browser config: %w", err)
	}
	return nil
}

func restoreAgentBrowserRoot(env *installEnv, root *os.Root) error {
	dir, err := openAgentBrowserDir(env, root, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return restoreAgentBrowserDir(env, dir)
}

func backupAndWriteAgentBrowserRoot(env *installEnv, root *os.Root, data []byte, uid, gid int) error {
	dir, err := openBrowserDir(env, root, true, uid, gid)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	if _, err := agentBrowserLeaf(dir, "config.json"); err == nil {
		bak := "config.json.bak"
		if _, err := agentBrowserLeaf(dir, bak); err == nil {
			archive := fmt.Sprintf("%s.archived-%s", bak, backupArchiveNow().UTC().Format(backupArchiveTimeFormat))
			for i := 1; ; i++ {
				if _, err := agentBrowserLeaf(dir, archive); errors.Is(err, os.ErrNotExist) {
					break
				} else if err != nil {
					return fmt.Errorf("stat archived agent-browser backup: %w", err)
				}
				archive = fmt.Sprintf("%s.archived-%s.%d", bak, backupArchiveNow().UTC().Format(backupArchiveTimeFormat), i)
			}
			if err := dir.rename(bak, archive); err != nil {
				return fmt.Errorf("archive agent-browser backup: %w", err)
			}
			rememberArchivedBackup(env, agentBrowserConfigPath(env)+".bak", filepath.Join(agentHomeDir(env), agentBrowserDir, archive))
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := dir.rename("config.json", bak); err != nil {
			return fmt.Errorf("backup agent-browser config: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeAgentBrowserDir(env, dir, "config.json", data, uid, gid); err != nil {
		return errors.Join(err, restoreAgentBrowserDir(env, dir))
	}
	return nil
}

// agentBrowserConfigPath is agent-browser's user config in the contained
// agent's home. Every agent launched under containment runs as that one
// account, so one file covers all of them.
func agentBrowserConfigPath(env *installEnv) string {
	return filepath.Join(agentHomeDir(env), ".agent-browser", "config.json")
}

// agentBrowserDefaultsRecordPath keeps the ownership record in the ROOT-OWNED
// managed directory, never in the agent home. The record decides what
// rollback removes from a file the agent controls; a record the agent could
// write is a record the agent could use to steer a privileged edit.
func agentBrowserDefaultsRecordPath(env *installEnv) string {
	return filepath.Join(env.configDir, "contain", agentBrowserDefaultsRecordFile)
}

// readAgentBrowserConfig reads the agent-browser config without following a
// symlink anywhere on the path. The file sits in a directory the contained
// agent owns, so a symlink there is an attempt to make root read or write
// somewhere else: it is refused, never followed. A missing file is not an
// error.
func readAgentBrowserConfig(env *installEnv, _ string) ([]byte, bool, error) {
	root, err := openAgentBrowserHome(env)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = root.Close() }()
	return readAgentBrowserRoot(env, root)
}

func restoreAgentBrowserConfig(env *installEnv) error {
	root, err := openAgentBrowserHome(env)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return restoreAgentBrowserRoot(env, root)
}

// readAgentBrowserDefaultsRecord loads the root-side ownership record.
func readAgentBrowserDefaultsRecord(env *installEnv) ([]byte, bool, error) {
	data, err := env.readFile(agentBrowserDefaultsRecordPath(env))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read agent-browser defaults ownership record: %w", err)
	}
	return data, true, nil
}

func writeAgentBrowserDefaultsRecord(env *installEnv, data []byte) error {
	path := agentBrowserDefaultsRecordPath(env)
	if err := env.mkdirAll(filepath.Dir(path), modeDirSystem); err != nil {
		return fmt.Errorf("create managed directory for agent-browser defaults ownership record: %w", err)
	}
	if err := env.writeFile(path, data, modeConfigSecret); err != nil {
		return fmt.Errorf("write agent-browser defaults ownership record: %w", err)
	}
	return nil
}

func removeAgentBrowserDefaultsRecord(env *installEnv) error {
	if err := env.removeFile(agentBrowserDefaultsRecordPath(env)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove agent-browser defaults ownership record: %w", err)
	}
	return nil
}

// stepWriteAgentBrowserDefaults merges browserdefaults.Flag into the
// contained agent's agent-browser user config. That file is the lowest
// precedence agent-browser reads, so a project config, an AGENT_BROWSER_ARGS
// value, or a CLI flag the agent sets still wins; exporting the environment
// variable from containment instead would replace the agent's own arguments.
//
// Only an addition Pipelock makes is recorded. A flag already present, placed
// by the agent or the operator, is left alone and rollback will not touch it.
func stepWriteAgentBrowserDefaults() step {
	var (
		wroteConfig bool
		wroteRecord bool
		prevRecord  []byte
	)
	restore := func(env *installEnv) error {
		var errs []error
		if wroteConfig {
			if err := restoreAgentBrowserConfig(env); err != nil {
				errs = append(errs, err)
			}
		}
		if wroteRecord {
			var err error
			if prevRecord != nil {
				err = writeAgentBrowserDefaultsRecord(env, prevRecord)
			} else {
				err = removeAgentBrowserDefaultsRecord(env)
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
		wroteConfig, wroteRecord, prevRecord = false, false, nil
		return errors.Join(errs...)
	}
	return step{
		name: "write-agent-browser-defaults",
		desc: "merge Chromium launch default into the agent's agent-browser user config",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			wroteConfig, wroteRecord, prevRecord = false, false, nil
			fail := func(cause error) (bool, error) {
				if rerr := restore(env); rerr != nil {
					return false, errors.Join(cause, rerr)
				}
				return false, cause
			}
			uid, gid, err := uidGidFor(env, env.agentUserName)
			if err != nil {
				return false, fmt.Errorf("resolve %s uid: %w", env.agentUserName, err)
			}
			path := agentBrowserConfigPath(env)
			// Every read and validation happens before anything is written, so a
			// refused file leaves the agent home and the record untouched.
			data, existed, err := readAgentBrowserConfig(env, path)
			if err != nil {
				return false, err
			}
			merged, rec, already, err := browserdefaults.Merge(data, existed)
			if err != nil {
				return false, fmt.Errorf("%w in %s; repair the file and rerun pipelock contain install", err, path)
			}
			if already {
				return false, nil
			}
			rec.Path = path
			if old, ok, err := readAgentBrowserDefaultsRecord(env); err != nil {
				return false, err
			} else if ok {
				// A record whose flag is gone describes nothing any more. This
				// addition gets a fresh record; the old one is put back if this
				// step is undone.
				prevRecord = old
			}
			root, err := openAgentBrowserHome(env)
			if err != nil {
				return false, err
			}
			defer func() { _ = root.Close() }()
			if err := ownAgentBrowserDirs(env, root, uid, gid); err != nil {
				return false, err
			}
			// Record first: if the config write then fails, the record is
			// restored; if the record write fails, the config was never touched.
			if err := writeAgentBrowserDefaultsRecord(env, rec.Marshal()); err != nil {
				return fail(err)
			}
			wroteRecord = true
			if err := backupAndWriteAgentBrowserRoot(env, root, merged, uid, gid); err != nil {
				return fail(fmt.Errorf("write %s: %w", path, err))
			}
			wroteConfig = true
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			return restore(env)
		},
	}
}

// removeAgentBrowserDefaults takes out only the flag Pipelock recorded adding.
// Without a root-side record it does nothing: the flag then belongs to the
// agent or the operator. A refused or unreadable config keeps the record so a
// later rollback can retry.
func removeAgentBrowserDefaults(env *installEnv) error {
	recordData, ok, err := readAgentBrowserDefaultsRecord(env)
	if err != nil || !ok {
		return err
	}
	rec, err := browserdefaults.DecodeRecord(recordData)
	if err != nil {
		return err
	}
	path := agentBrowserConfigPath(env)
	if rec.Path != filepath.Clean(path) {
		return fmt.Errorf("agent-browser defaults ownership record describes %q, not %s; refusing to edit", rec.Path, path)
	}
	data, exists, err := readAgentBrowserConfig(env, path)
	if err != nil {
		return err
	}
	if !exists {
		return removeAgentBrowserDefaultsRecord(env)
	}
	out, remove, changed, err := browserdefaults.Remove(data, rec)
	if err != nil {
		return fmt.Errorf("%w in %s; repair the file and rerun rollback", err, path)
	}
	switch {
	case remove:
		// Pipelock created the file and nothing else lives in it. The lstat in
		// readAgentBrowserConfig proved it a regular file; unlink removes the
		// name and never follows a link swapped in since.
		root, err := openAgentBrowserHome(env)
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()
		dir, err := openAgentBrowserDir(env, root, false)
		if err != nil {
			return err
		}
		defer func() { _ = dir.Close() }()
		if err := dir.remove("config.json"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	case changed:
		uid, gid, err := uidGidFor(env, env.agentUserName)
		if err != nil {
			return fmt.Errorf("resolve %s uid: %w", env.agentUserName, err)
		}
		root, err := openAgentBrowserHome(env)
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()
		if err := writeAgentBrowserRoot(env, root, agentBrowserFile, out, uid, gid); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return removeAgentBrowserDefaultsRecord(env)
}

// actionRemoveAgentBrowserDefaults is the rollback counterpart of
// stepWriteAgentBrowserDefaults. A full rollback that deletes the agent user
// removes the home anyway; this handles --keep-users, where it survives.
func actionRemoveAgentBrowserDefaults() step {
	return step{
		name: "remove-agent-browser-defaults",
		desc: "remove Pipelock's Chromium launch default from the agent's agent-browser config",
		undo: func(_ context.Context, env *installEnv) error {
			return removeAgentBrowserDefaults(env)
		},
	}
}
