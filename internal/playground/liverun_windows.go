// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package playground

import (
	"errors"
	"os/exec"
)

func configureContainedCommand(_ *exec.Cmd, _ string) error {
	return errors.New("contained toy-agent execution is not supported on windows")
}
