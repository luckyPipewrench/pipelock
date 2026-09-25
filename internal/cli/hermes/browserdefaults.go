// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/browserdefaults"
)

// browserFlag is the shared Chromium default; the merge and removal rules
// live in internal/browserdefaults so `pipelock contain install` and this
// command cannot drift.
const browserFlag = browserdefaults.Flag

// browserHome is the home agent-browser reads its user config from: the
// Hermes user's home, resolved exactly as install resolves its defaults
// (--home, else the running user's home). It never derives the home from the
// Hermes config path, which an operator may place anywhere.
func browserHome(home string) (string, error) {
	if home != "" {
		return home, nil
	}
	detected, err := userHomeDir()
	if err != nil {
		return "", fmt.Errorf("browser defaults: resolve home: %w", err)
	}
	if detected == "" {
		return "", errors.New("browser defaults: resolve home: empty home directory")
	}
	return detected, nil
}

func browserPaths(home string) (string, string) {
	return filepath.Join(home, ".agent-browser", "config.json"), filepath.Join(home, ".hermes", "pipelock-browser-defaults.json")
}

// readBrowserFile returns a regular file's bytes and whether it existed,
// refusing anything that is not a regular file (a symlink included).
func readBrowserFile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("browser defaults: refusing non-regular file %s", path)
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func readBrowserConfig(path string) (map[string]json.RawMessage, bool, error) {
	data, existed, err := readBrowserFile(path)
	if err != nil {
		return nil, false, err
	}
	if !existed {
		return map[string]json.RawMessage{}, false, nil
	}
	obj, err := browserdefaults.Parse(data)
	if err != nil {
		return nil, false, fmt.Errorf("%w in %s", err, path)
	}
	return obj, true, nil
}

func browserArgs(obj map[string]json.RawMessage) (string, error) {
	return browserdefaults.Args(obj)
}

func hasBrowserFlag(args string) bool {
	return browserdefaults.HasFlag(args)
}

// preflightBrowserDefaults performs every read and validation install needs
// without writing, so runInstall can refuse a bad agent-browser config before
// it changes anything else.
func preflightBrowserDefaults(home string) error {
	_, _, _, err := loadBrowserDefaultsForInstall(home)
	return err
}

// loadBrowserDefaultsForInstall returns the config bytes, whether the file
// existed, and whether Pipelock's flag is already present, after every
// validation install needs.
func loadBrowserDefaultsForInstall(home string) ([]byte, bool, bool, error) {
	path, state := browserPaths(home)
	data, existed, err := readBrowserFile(path)
	if err != nil {
		return nil, false, false, err
	}
	present, err := browserdefaults.Inspect(data)
	if err != nil {
		if errors.Is(err, browserdefaults.ErrMalformed) {
			return nil, false, false, fmt.Errorf("%w in %s", err, path)
		}
		return nil, false, false, err
	}
	if present {
		return data, existed, true, nil
	}
	if _, recorded, err := readBrowserFile(state); err != nil {
		return nil, false, false, err
	} else if recorded {
		return nil, false, false, errors.New("browser defaults: stale ownership record; run pipelock hermes rollback first")
	}
	return data, existed, false, nil
}

// writeBrowserOwnershipRecord writes the ownership record. It is a variable
// only so a test can fail this one write and prove the config is untouched.
var writeBrowserOwnershipRecord = writeFileAtomic

// writeBrowserConfig writes the agent-browser config. It is a variable only
// so a test can fail this one write and prove the original stays in place.
var writeBrowserConfig = writeFileAtomic

func installBrowserDefaults(home string) error {
	path, state := browserPaths(home)
	data, existed, already, err := loadBrowserDefaultsForInstall(home)
	if err != nil || already {
		return err
	}
	merged, rec, already, err := browserdefaults.Merge(data, existed)
	if err != nil || already {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// The ownership record is written first. If the config write then fails,
	// the record is removed again; if the record write fails, the config was
	// never touched. Either way Pipelock never leaves a flag that rollback
	// cannot attribute to it.
	if err := os.MkdirAll(filepath.Dir(state), 0o750); err != nil {
		return err
	}
	if err := writeBrowserOwnershipRecord(state, rec.Marshal()); err != nil {
		return err
	}
	if existed {
		if err := backupBrowserConfig(path); err != nil {
			_ = os.Remove(state)
			return err
		}
	}
	if err := writeBrowserConfig(path, merged); err != nil {
		_ = os.Remove(state)
		return err
	}
	return nil
}

// backupBrowserConfig copies the current config to <path>.bak.<nanos> and
// leaves the original in place. The replacement is written atomically
// afterward, so a failed write never leaves the active config missing, which
// a rename-based rotation would.
func backupBrowserConfig(path string) error {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("browser defaults: back up %s: %w", path, err)
	}
	backup := fmt.Sprintf("%s.bak.%d", path, time.Now().UTC().UnixNano())
	if err := writeFileAtomic(backup, data); err != nil {
		return fmt.Errorf("browser defaults: back up %s: %w", path, err)
	}
	return nil
}

func rollbackBrowserDefaults(home string) error {
	path, state := browserPaths(home)
	recordData, present, err := readBrowserFile(state)
	if err != nil || !present {
		return err
	}
	rec, err := browserdefaults.DecodeRecord(recordData)
	if err != nil {
		return err
	}
	data, exists, err := readBrowserFile(path)
	if err != nil {
		return err
	}
	if exists {
		out, remove, changed, err := browserdefaults.Remove(data, rec)
		if err != nil {
			if errors.Is(err, browserdefaults.ErrMalformed) {
				return fmt.Errorf("%w in %s", err, path)
			}
			return err
		}
		if remove {
			// Pipelock created the file and nothing else lives in it:
			// remove it outright rather than leaving a backup of our own flag.
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Remove(state)
		}
		if changed {
			if err := backupBrowserConfig(path); err != nil {
				return err
			}
			if err := writeBrowserConfig(path, out); err != nil {
				return err
			}
		}
	}
	return os.Remove(state)
}

func verifyBrowserDefaults(home string) (string, string) {
	path, _ := browserPaths(home)
	obj, present, err := readBrowserConfig(path)
	if err != nil {
		return "invalid", "repair or remove " + path + ", then run pipelock hermes install"
	}
	if !present {
		return "missing", "run pipelock hermes install"
	}
	args, err := browserArgs(obj)
	if err != nil {
		return "invalid", "make args in " + path + " a string, then run pipelock hermes install"
	}
	if !hasBrowserFlag(args) {
		return "missing", "run pipelock hermes install"
	}
	if env := os.Getenv("AGENT_BROWSER_ARGS"); env != "" && !hasBrowserFlag(env) {
		return "overridden", "include " + browserFlag + " in AGENT_BROWSER_ARGS, then run pipelock hermes verify"
	}
	return "present", ""
}
