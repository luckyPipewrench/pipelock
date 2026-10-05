// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package exec

import (
	"errors"

	"github.com/spf13/cobra"
)

func launch(_ *cobra.Command, _, _ []string) error {
	return errors.New("exec is supported only on Unix and Windows")
}
