// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import "github.com/spf13/cobra"

// ExportRootCmd exposes the unexported rootCmd to external test packages
// (cli_test) so they can drive command-tree assertions without re-creating
// the cobra wiring. Test-only helper.
func ExportRootCmd() *cobra.Command { return rootCmd() }
