// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js || plan9 || wasip1

package llmagent

import "os/exec"

const runCommandSupported = false

// configureRunCommand refuses targets that cannot kill a shell's descendants
// as one process group.
func configureRunCommand(_ *exec.Cmd) error {
	return errRunCommandUnsupported
}
