// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"fmt"

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
