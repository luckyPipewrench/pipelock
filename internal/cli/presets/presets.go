// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package presets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/configs"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	PresetClaudeCode   = "claude-code"
	PresetCursor       = "cursor"
	PresetGenericAgent = "generic-agent"
	PresetHostileModel = "hostile-model"
)

var All = []string{
	config.ModeStrict,
	config.ModeBalanced,
	config.ModeAudit,
	PresetClaudeCode,
	PresetCursor,
	PresetGenericAgent,
	PresetHostileModel,
}

var (
	ValidNames = strings.Join(All, ", ")
	FlagHelp   = "config preset: " + ValidNames
)

// YAML returns the config YAML bytes for a built-in preset.
func YAML(name string) ([]byte, error) {
	switch name {
	case config.ModeStrict:
		return marshal(strictPreset())
	case config.ModeBalanced:
		return marshal(config.Defaults())
	case config.ModeAudit:
		return marshal(auditPreset())
	case PresetClaudeCode, PresetCursor, PresetGenericAgent, PresetHostileModel:
		data, err := filePreset(name)
		if err != nil {
			return nil, err
		}
		return data, nil
	default:
		return nil, UnknownError(name)
	}
}

// Config returns a parsed config for a built-in preset.
func Config(name string) (*config.Config, error) {
	switch name {
	case config.ModeStrict:
		return validatedConfig(name, strictPreset())
	case config.ModeBalanced:
		return validatedConfig(name, config.Defaults())
	case config.ModeAudit:
		return validatedConfig(name, auditPreset())
	case PresetClaudeCode, PresetCursor, PresetGenericAgent, PresetHostileModel:
		data, err := filePreset(name)
		if err != nil {
			return nil, err
		}
		cfg, err := parseConfig(data)
		if err != nil {
			return nil, fmt.Errorf("parsing preset %q: %w", name, err)
		}
		return cfg, nil
	default:
		return nil, UnknownError(name)
	}
}

func UnknownError(name string) error {
	return fmt.Errorf("unknown preset %q: choose %s", name, ValidNames)
}

func filePreset(name string) ([]byte, error) {
	data, ok := configs.Preset(name)
	if !ok {
		return nil, fmt.Errorf("preset %q is not embedded", name)
	}
	if _, err := parseConfig(data); err != nil {
		return nil, fmt.Errorf("validating preset %q: %w", name, err)
	}
	return data, nil
}

func validatedConfig(name string, cfg *config.Config) (*config.Config, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating preset %q: %w", name, err)
	}
	return cfg, nil
}

func marshal(cfg *config.Config) ([]byte, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshaling config: %w", err)
	}
	return data, nil
}

func parseConfig(data []byte) (*config.Config, error) {
	cfg := &config.Config{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("empty YAML document")
		}
		return nil, err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, fmt.Errorf("multiple YAML documents not supported")
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := requireMappingDocument(data); err != nil {
		return nil, err
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func requireMappingDocument(data []byte) error {
	var doc yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("empty YAML document")
		}
		return err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("preset YAML must be a non-empty mapping document")
	}
	return nil
}

func strictPreset() *config.Config {
	cfg := config.Defaults()
	cfg.Mode = config.ModeStrict
	// In strict mode, the fetch proxy enforces the API allowlist.
	cfg.FetchProxy.Monitoring.EntropyThreshold = 3.5
	cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold = 3.5
	cfg.FetchProxy.Monitoring.MaxURLLength = 500
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 30
	return cfg
}

func auditPreset() *config.Config {
	cfg := config.Defaults()
	cfg.Mode = config.ModeAudit
	// Audit mode: detect and log everything but never block.
	// All DLP patterns, blocklists, and entropy checks stay active for
	// visibility - enforce=false makes them log-only.
	enforce := false
	cfg.Enforce = &enforce
	cfg.Logging.IncludeAllowed = true
	cfg.Logging.IncludeBlocked = true
	return cfg
}
