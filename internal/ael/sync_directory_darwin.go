// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package ael

// macOS does not support fsync on directory descriptors. Artifact files still
// receive their own fsync before this best-effort directory durability step.
func syncDirectory(string) error { return nil }
