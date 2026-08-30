// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package contain

import "errors"

func requireContainHost() error {
	return errors.New("pipelock contain install requires a supported Linux host with systemd and nftables")
}
