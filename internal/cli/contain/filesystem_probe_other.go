// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package contain

import "context"

func probeFilesystemConfinementEnforce(context.Context, *probeEnv, filesystemProfile) (string, string) {
	return statusFail, "filesystem confinement canary requires Linux"
}
