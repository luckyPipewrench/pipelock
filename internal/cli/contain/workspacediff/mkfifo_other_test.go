// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package workspacediff

import "errors"

func makeFIFO(string) error {
	return errors.New("FIFO unsupported on this platform")
}
