// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !darwin

package directorysync

import "os"

func Sync(path string) error {
	return syncWithOpen(path, func(name string) (directorySyncer, error) {
		// #nosec G304 -- the artifact directory is intentionally operator-configured.
		return os.Open(name)
	})
}
