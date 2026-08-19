// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package contain

import (
	"fmt"
	"os"
)

// requireContainPrivilege reports why a privileged contain subcommand cannot
// run, or nil when it can.
//
// The platform split exists because os.Geteuid returns -1 on Windows, so a bare
// euid check there always failed with "use sudo" — a remedy Windows does not
// have. Naming an impossible fix is worse than naming none, so the Windows build
// says plainly that containment is unavailable instead.
func requireContainPrivilege(action string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s must be run as root (use sudo)", action)
	}
	return nil
}
