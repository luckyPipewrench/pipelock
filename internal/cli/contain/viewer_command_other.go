// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package contain

import "github.com/spf13/cobra"

func viewerCmd() *cobra.Command {
	return &cobra.Command{Use: "viewer", Hidden: true}
}
