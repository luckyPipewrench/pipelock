// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

var defaultSystemConfigPath = "/etc/pipelock/pipelock.yaml"

// LoadConfigOrDefault loads a config file if path is non-empty, otherwise
// returns the built-in defaults.
func LoadConfigOrDefault(path string) (*config.Config, error) {
	if path != "" {
		cfg, err := config.Load(path)
		if err != nil {
			return nil, fmt.Errorf("loading config %q: %w", path, err)
		}
		return cfg, nil
	}
	return config.Defaults(), nil
}

// InstallConfigResolution records the config path embedded into an installed
// hook/wrapper and the source used to choose it.
type InstallConfigResolution struct {
	Path     string
	Source   string
	Explicit bool
}

// ResolveConfigForInstall resolves the config an installer should embed into
// generated hook or wrapper commands. It intentionally never checks cwd-local
// pipelock.yaml files; install-time config must be stable and operator-owned,
// not dependent on the directory the agent later runs from.
func ResolveConfigForInstall(path string) (InstallConfigResolution, error) {
	if path != "" {
		clean, err := filepath.Abs(filepath.Clean(path))
		if err != nil {
			return InstallConfigResolution{}, fmt.Errorf("resolving config path %q: %w", path, err)
		}
		if err := ConfigPathIsSecure(clean); err != nil {
			return InstallConfigResolution{}, err
		}
		if _, err := config.Load(clean); err != nil {
			return InstallConfigResolution{}, fmt.Errorf("loading config %q: %w", clean, err)
		}
		return InstallConfigResolution{Path: clean, Source: "explicit --config", Explicit: true}, nil
	}

	discovered, err := DiscoverConfigPathStrict()
	if err != nil {
		return InstallConfigResolution{}, err
	}
	if discovered == "" {
		return InstallConfigResolution{Source: "built-in defaults"}, nil
	}
	if _, err := config.Load(discovered); err != nil {
		return InstallConfigResolution{}, fmt.Errorf("loading discovered config %q: %w", discovered, err)
	}
	return InstallConfigResolution{Path: discovered, Source: "auto-discovered"}, nil
}

// WriteInstallConfigProvenance reports the config an installer embedded. Keep
// this operator-facing; generated hooks may later run from arbitrary working
// directories, so the install output must make the trust boundary explicit.
func WriteInstallConfigProvenance(w io.Writer, surface string, resolved InstallConfigResolution, quiet bool) {
	if quiet || w == nil {
		return
	}
	if resolved.Path != "" {
		_, _ = fmt.Fprintf(w, "pipelock %s: config: %s (%s)\n", surface, resolved.Path, resolved.Source)
		return
	}
	_, _ = fmt.Fprintf(w, "pipelock %s: config: built-in defaults; no PIPELOCK_CONFIG, user config, or system config was found\n", surface)
	_, _ = fmt.Fprintln(w, "pipelock: the installed integration will use built-in defaults until reinstalled with --config or a standard config path exists")
}

// ConfigPathIsSecure verifies that a discovered config file is safe to trust.
// It rejects group/other-writable files and files not owned by root, the
// invoking user, or Pipelock's dedicated service account. The contain-managed
// /etc/pipelock path is service-owned on installed systems, while the contained
// agent remains a separate UID and must not be able to mutate it.
func ConfigPathIsSecure(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("config %q is not a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("config %q is writable by group or other", path)
	}
	ownerUID, ok := configPathOwnerUID(info)
	if !ok {
		return nil
	}
	if !configOwnershipSecure(ownerUID, currentEUID()) {
		return fmt.Errorf("config %q is owned by uid %d, not root or the invoking user", path, ownerUID)
	}
	return nil
}

func configOwnershipSecure(ownerUID, euid int) bool {
	return ownerUID == 0 || ownerUID == euid || configPathOwnerTrusted(ownerUID)
}

// DiscoverConfigPath returns the first config file pipelock would naturally
// look at, or empty string if none of the candidates exist. Search order
// mirrors the systemd unit and CLI convention:
//
//  1. $PIPELOCK_CONFIG (operator override)
//  2. $XDG_CONFIG_HOME/pipelock/pipelock.yaml
//  3. ~/.config/pipelock/pipelock.yaml
//  4. /etc/pipelock/pipelock.yaml
//
// Returns the absolute path on first hit and the empty string when nothing
// is found. Callers decide how to react to the empty-string return - for
// instance, the IDE install commands embed the discovered path into the
// wrapped argv so the spawned subprocess loads the same config as the
// operator's main pipelock service.
func DiscoverConfigPath() string {
	return discoverConfigPath(defaultSystemConfigPath)
}

// DiscoverConfigPathStrict returns the first secure config file pipelock would
// naturally look at. Unlike DiscoverConfigPath, candidate files that exist but
// are non-regular, unreadable, or unsafe are returned as errors instead of
// being silently skipped. Use this for security-sensitive commands where
// falling back to defaults would hide an unsafe operator config.
func DiscoverConfigPathStrict() (string, error) {
	return discoverConfigPathStrict(defaultSystemConfigPath)
}

func configPathCandidates(systemPath string) []string {
	candidates := []string{}

	if env := os.Getenv("PIPELOCK_CONFIG"); env != "" {
		candidates = append(candidates, env)
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "pipelock", "pipelock.yaml"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".config", "pipelock", "pipelock.yaml"))
	}
	if systemPath != "" {
		candidates = append(candidates, systemPath)
	}
	return candidates
}

func discoverConfigPath(systemPath string) string {
	for _, c := range configPathCandidates(systemPath) {
		clean, err := filepath.Abs(filepath.Clean(c))
		if err != nil {
			continue
		}
		info, err := os.Stat(clean)
		if err == nil && info.Mode().IsRegular() && ConfigPathIsSecure(clean) == nil {
			return clean
		}
	}
	return ""
}

func discoverConfigPathStrict(systemPath string) (string, error) {
	for _, c := range configPathCandidates(systemPath) {
		clean, err := filepath.Abs(filepath.Clean(c))
		if err != nil {
			return "", fmt.Errorf("resolving config path %q: %w", c, err)
		}
		info, err := os.Stat(clean)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", fmt.Errorf("stat config %q: %w", clean, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("config %q is not a regular file", clean)
		}
		if err := ConfigPathIsSecure(clean); err != nil {
			return "", err
		}
		return clean, nil
	}
	return "", nil
}
