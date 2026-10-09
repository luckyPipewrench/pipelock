// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js

package config

// mcpAckFileKeySupported is false on the browser target, which has no host
// file permissions to verify.
const mcpAckFileKeySupported = false
