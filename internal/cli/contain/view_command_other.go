// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package contain

import (
	"errors"

	"github.com/spf13/cobra"
)

func viewCmd() *cobra.Command {
	return &cobra.Command{Use: "view", Short: "Connect a VNC client to the contained display", RunE: func(*cobra.Command, []string) error {
		return errors.New("contain view is supported only on Linux")
	}}
}
