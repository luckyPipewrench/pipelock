// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sandbox

import "fmt"

func mountPrivateShm() error {
	return fmt.Errorf("%w: private /dev/shm requires linux", ErrUnavailable)
}
