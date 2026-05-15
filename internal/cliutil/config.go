// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

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
// is found. Callers decide how to react to the empty-string return — for
// instance, the IDE install commands embed the discovered path into the
// wrapped argv so the spawned subprocess loads the same config as the
// operator's main pipelock service.
func DiscoverConfigPath() string {
	return discoverConfigPath("/etc/pipelock/pipelock.yaml")
}

func discoverConfigPath(systemPath string) string {
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

	for _, c := range candidates {
		clean, err := filepath.Abs(filepath.Clean(c))
		if err != nil {
			continue
		}
		info, err := os.Stat(clean)
		if err == nil && info.Mode().IsRegular() {
			return clean
		}
	}
	return ""
}
