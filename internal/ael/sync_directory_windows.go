// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ael

// Windows does not expose a portable directory-fsync operation. The artifact
// files themselves are still flushed before lifecycle emission returns.
func syncDirectory(string) error { return nil }
