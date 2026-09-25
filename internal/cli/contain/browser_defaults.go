// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/browserdefaults"
)

// agentBrowserDefaultsRecordFile is the ownership record for the Chromium
// default merged into the contained agent's agent-browser config.
const agentBrowserDefaultsRecordFile = "agent-browser-defaults.json"

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
func readAgentBrowserConfig(env *installEnv, path string) ([]byte, bool, error) {
	clean := filepath.Clean(path)
	if err := ensureSafeDirectory(env, filepath.Dir(clean)); err != nil {
		return nil, false, fmt.Errorf("agent-browser config: %w", err)
	}
	info, err := env.lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("stat %s: %w", clean, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("%s is a symlink; refusing privileged read", clean)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s exists and is not a regular file", clean)
	}
	// O_NOFOLLOW read: the lstat above can be raced by a swap, the open cannot.
	data, err := readRegularFileNoFollow(clean)
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", clean, err)
	}
	return data, true, nil
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
			if err := restoreBackup(env, agentBrowserConfigPath(env)); err != nil {
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
			if err := ensureAgentConfigDir(env, filepath.Dir(path), uid, gid); err != nil {
				return false, err
			}
			// Record first: if the config write then fails, the record is
			// restored; if the record write fails, the config was never touched.
			if err := writeAgentBrowserDefaultsRecord(env, rec.Marshal()); err != nil {
				return fail(err)
			}
			wroteRecord = true
			if err := backupAndWrite(env, path, merged, modeAgentConfig); err != nil {
				return fail(fmt.Errorf("write %s: %w", path, err))
			}
			wroteConfig = true
			if err := chownAgentConfigFile(env, path, uid, gid); err != nil {
				return fail(fmt.Errorf("chown %s: %w", path, err))
			}
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
		if err := env.removeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	case changed:
		uid, gid, err := uidGidFor(env, env.agentUserName)
		if err != nil {
			return fmt.Errorf("resolve %s uid: %w", env.agentUserName, err)
		}
		if err := ensureSafeWriteTarget(env, path); err != nil {
			return err
		}
		if err := env.writeFile(path, out, modeAgentConfig); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		if err := chownAgentConfigFile(env, path, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
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
