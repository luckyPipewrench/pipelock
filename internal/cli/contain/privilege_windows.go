// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package contain

import "fmt"

// requireContainPrivilege refuses privileged contain subcommands on Windows.
//
// Workstation containment installs nftables owner-match rules and a system
// systemd unit. Neither exists on Windows, so no privilege level makes these
// subcommands work and there is nothing for an operator to retry. The message
// says that rather than pointing at sudo, which Windows does not have. Use
// `pipelock run` for a proxy on this platform.
func requireContainPrivilege(action string) error {
	return fmt.Errorf("%s is not supported on Windows: workstation containment requires Linux nftables and systemd; run `pipelock run` for a local proxy instead", action)
}
