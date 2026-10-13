// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package contain

import "context"

func probeFilesystemConfinementEnforce(context.Context, *probeEnv, filesystemProfile) (string, string) {
	return statusFail, "filesystem confinement canary requires Linux"
}

func probeManagedRuntimeMounts(context.Context, *probeEnv, filesystemProfile) (string, string) {
	return statusFail, "runtime mount canary requires Linux"
}
