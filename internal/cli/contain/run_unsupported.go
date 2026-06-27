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
