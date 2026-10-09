// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

// mcpAckFileKeySupported is false on Windows. File permission checks there
// do not inspect NTFS ACLs and the open cannot refuse a reparse point raced
// into place, so a file key's readership cannot be verified. An environment
// key works on every platform.
const mcpAckFileKeySupported = false
