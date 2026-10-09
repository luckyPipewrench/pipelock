// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !js

package config

// mcpAckFileKeySupported is true where a file key is opened without
// following symlinks and refused when group or others can read it.
const mcpAckFileKeySupported = true
