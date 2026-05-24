// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import "embed"

// pluginFS holds the Python plugin source distributed with the binary.
// The tree is materialised verbatim into ~/.hermes/plugins/pipelock/ at
// install time; updating these files and rebuilding pipelock is the only
// supported way to change the installed plugin.
//
//go:embed plugin_template/*
var pluginFS embed.FS

// pluginRoot is the directory name inside pluginFS that wraps the plugin
// source. Stripped during extraction so files land directly under the
// configured target directory rather than nested one level deeper.
const pluginRoot = "plugin_template"
