// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// HardenProxyProcess prevents a same-UID wrapped MCP server from reading the
// proxy environment through /proc. It deliberately does not claim to turn a
// bearer credential into an independent operator authority: an authority
// mechanism still needs a credential the wrapped server cannot mint.
func HardenProxyProcess() error {
	return hardenProxyProcessWith(func() error {
		return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	})
}

func hardenProxyProcessWith(setDumpable func() error) error {
	if err := setDumpable(); err != nil {
		return fmt.Errorf("set non-dumpable: %w", err)
	}
	return nil
}
