// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package configs

import "embed"

//go:embed *.yaml
var presetFiles embed.FS

var filePresets = map[string]string{
	"claude-code":   "claude-code.yaml",
	"cursor":        "cursor.yaml",
	"generic-agent": "generic-agent.yaml",
	"hostile-model": "hostile-model.yaml",
}

// Preset returns the embedded YAML bytes for file-backed presets.
func Preset(name string) ([]byte, bool) {
	filename, ok := filePresets[name]
	if !ok {
		return nil, false
	}
	data, err := presetFiles.ReadFile(filename)
	if err != nil {
		return nil, false
	}
	return append([]byte(nil), data...), true
}
