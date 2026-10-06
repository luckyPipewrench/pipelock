// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package contain

import (
	"errors"

	"github.com/spf13/cobra"
)

func launchPropertiesCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "launch-properties",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return errors.New("contain launch-properties is supported only on Linux")
		},
	}
}
