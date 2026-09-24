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
	"strings"
)

const browserFlag = "--disable-blink-features=AutomationControlled"

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

func readBrowserConfig(path string) (map[string]json.RawMessage, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]json.RawMessage{}, false, nil
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
	if len(strings.TrimSpace(string(data))) == 0 {
		return map[string]json.RawMessage{}, true, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, false, fmt.Errorf("browser defaults: malformed JSON in %s", path)
	}
	return obj, true, nil
}

func browserArgs(obj map[string]json.RawMessage) (string, error) {
	data, ok := obj["args"]
	if !ok {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return "", errors.New("browser defaults: args must be a string")
	}
	return value, nil
}

// browserArgParts splits agent-browser's args string on both documented
// separators (comma and newline), so detection and removal agree.
func browserArgParts(args string) []string {
	return strings.FieldsFunc(args, func(r rune) bool { return r == ',' || r == '\n' })
}

func hasBrowserFlag(args string) bool {
	for _, part := range browserArgParts(args) {
		if strings.TrimSpace(part) == browserFlag {
			return true
		}
	}
	return false
}

func browserJSON(obj map[string]json.RawMessage) ([]byte, error) {
	data, err := json.MarshalIndent(obj, "", "  ")
	return append(data, '\n'), err
}

// preflightBrowserDefaults performs every read and validation install needs
// without writing, so runInstall can refuse a bad agent-browser config before
// it changes anything else.
func preflightBrowserDefaults(home string) error {
	_, _, _, _, err := loadBrowserDefaultsForInstall(home)
	return err
}

// loadBrowserDefaultsForInstall returns the parsed config, whether it existed,
// its args, and whether Pipelock's flag is already present.
func loadBrowserDefaultsForInstall(home string) (map[string]json.RawMessage, bool, string, bool, error) {
	path, state := browserPaths(home)
	obj, existed, err := readBrowserConfig(path)
	if err != nil {
		return nil, false, "", false, err
	}
	args, err := browserArgs(obj)
	if err != nil {
		return nil, false, "", false, err
	}
	if hasBrowserFlag(args) {
		return obj, existed, args, true, nil
	}
	if _, present, err := readBrowserConfig(state); err != nil {
		return nil, false, "", false, err
	} else if present {
		return nil, false, "", false, errors.New("browser defaults: stale ownership record; run pipelock hermes rollback first")
	}
	return obj, existed, args, false, nil
}

func installBrowserDefaults(home string) error {
	path, state := browserPaths(home)
	obj, existed, args, already, err := loadBrowserDefaultsForInstall(home)
	if err != nil || already {
		return err
	}
	original := args
	if args == "" {
		args = browserFlag
	} else {
		args = args + "," + browserFlag
	}
	obj["args"], _ = json.Marshal(args)
	data, err := browserJSON(obj)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if existed {
		if _, err := rotateExisting(path); err != nil {
			return err
		}
	}
	if err := writeFileAtomic(path, data); err != nil {
		return err
	}
	record, _ := json.Marshal(map[string]interface{}{"created": !existed, "original_args": original})
	if err := os.MkdirAll(filepath.Dir(state), 0o750); err != nil {
		return err
	}
	return writeFileAtomic(state, record)
}

func rollbackBrowserDefaults(home string) error {
	path, state := browserPaths(home)
	record, present, err := readBrowserConfig(state)
	if err != nil || !present {
		return err
	}
	var created bool
	var original string
	if err := json.Unmarshal(record["created"], &created); err != nil {
		return fmt.Errorf("browser defaults: malformed ownership record: %w", err)
	}
	if err := json.Unmarshal(record["original_args"], &original); err != nil {
		return fmt.Errorf("browser defaults: malformed ownership record: %w", err)
	}
	obj, exists, err := readBrowserConfig(path)
	if err != nil {
		return err
	}
	if exists {
		args, err := browserArgs(obj)
		if err != nil {
			return err
		}
		if hasBrowserFlag(args) {
			parts := browserArgParts(args)
			kept := make([]string, 0, len(parts))
			for _, part := range parts {
				if strings.TrimSpace(part) != browserFlag {
					kept = append(kept, part)
				}
			}
			remaining := strings.Join(kept, ",")
			if strings.Join(browserArgParts(original), ",") == remaining {
				// Nothing else changed since install: restore the operator's
				// value byte for byte, separators included.
				remaining = original
			}
			if remaining == "" {
				// Only Pipelock's flag is left. An operator who removed their
				// own arguments after install keeps that removal.
				delete(obj, "args")
			} else {
				obj["args"], _ = json.Marshal(remaining)
			}
			if created && len(obj) == 0 {
				// Pipelock created the file and nothing else lives in it:
				// remove it outright rather than leaving a backup of our own flag.
				if err := os.Remove(path); err != nil {
					return err
				}
				return os.Remove(state)
			}
			if _, err := rotateExisting(path); err != nil {
				return err
			}
			data, err := browserJSON(obj)
			if err != nil {
				return err
			}
			if err := writeFileAtomic(path, data); err != nil {
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
