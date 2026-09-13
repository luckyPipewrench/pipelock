// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package contain

import (
	"context"
	"errors"
	"io"
)

func isRoot() bool {
	return false
}

func containRunSupported() bool {
	return false
}

func launchContainedAgent(
	context.Context,
	*probeEnv,
	[]string,
	io.Reader,
	io.Writer,
	io.Writer,
) error {
	return errors.New("contain run is supported only on Linux")
}

// probePrivateTmp is referenced by allProbes in the platform-agnostic verify.go,
// so it must exist on every target the CLI binary builds for. The private-tmp
// canary depends on a transient systemd service with a private mount namespace,
// which only Linux provides; elsewhere it reports skip rather than failing to
// compile. The test seam is honored for parity with the Linux implementation.
func probePrivateTmp(ctx context.Context, env *probeEnv) (string, string) {
	if env.privateTmpProbe != nil {
		return env.privateTmpProbe(ctx, env)
	}
	return statusSkip, "private temporary-directory canary requires a Linux transient systemd service"
}
