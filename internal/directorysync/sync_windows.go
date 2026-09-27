// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package directorysync

// Go cannot fsync a directory handle on Windows. NTFS journals directory
// metadata, so a newly created file's directory entry is recoverable after a crash.
func Sync(string) error { return nil }
