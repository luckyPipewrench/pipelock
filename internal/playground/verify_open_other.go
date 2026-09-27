// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package playground

import "os"

func openRunArtifact(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
