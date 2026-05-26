// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// UnmarshalYAML accepts a WatchPath in either of two YAML shapes. The bare
// string form is the legacy shape and is equivalent to a mapping with
// required:false. The mapping form lets the operator opt a path in to
// hard-fail-on-arm with required:true. Mixed lists are allowed.
//
// Legacy / default form:
//
//	watch_paths:
//	  - /etc/secrets
//
// Mapping form with explicit fields:
//
//	watch_paths:
//	  - path: /etc/secrets
//	    required: true
func (w *WatchPath) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		// Strict: tag must be a string so a bare boolean/integer is rejected
		// rather than coerced to its decimal/literal text.
		if value.Tag != "" && value.Tag != "!!str" {
			return fmt.Errorf("file_sentry.watch_paths entry must be a string or {path, required} mapping (got YAML tag %s)", value.Tag)
		}
		// Empty scalar ("- "" "") would later be resolved against the config
		// directory by load.go's relative-path normalization and silently
		// watch the wrong location. Reject at decode time instead.
		if value.Value == "" {
			return fmt.Errorf("file_sentry.watch_paths entry must not be an empty string")
		}
		w.Path = value.Value
		w.Required = false
		return nil
	case yaml.MappingNode:
		// Enforce the field set explicitly; typos like "require: true" would
		// otherwise silently leave Required=false and defeat the opt-in.
		// value.Content is [key0, val0, key1, val1, ...].
		for i := 0; i < len(value.Content); i += 2 {
			key := value.Content[i]
			switch key.Value {
			case "path", "required":
			default:
				return fmt.Errorf("file_sentry.watch_paths entry has unsupported field %q (allowed: path, required)", key.Value)
			}
		}
		raw := struct {
			Path     *string `yaml:"path"`
			Required *bool   `yaml:"required"`
		}{}
		if err := value.Decode(&raw); err != nil {
			return fmt.Errorf("file_sentry.watch_paths entry: %w", err)
		}
		if raw.Path == nil || *raw.Path == "" {
			return fmt.Errorf("file_sentry.watch_paths entry missing required field 'path'")
		}
		w.Path = *raw.Path
		if raw.Required != nil {
			w.Required = *raw.Required
		}
		return nil
	default:
		return fmt.Errorf("file_sentry.watch_paths entry must be a string or mapping (got YAML kind %d)", value.Kind)
	}
}
