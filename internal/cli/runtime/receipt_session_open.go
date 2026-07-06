// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import "github.com/luckyPipewrench/pipelock/internal/receipt"

var beforeStartupSessionOpenForTest func(*receipt.Emitter) error

func emitStartupSessionOpen(e *receipt.Emitter) error {
	if beforeStartupSessionOpenForTest != nil {
		if err := beforeStartupSessionOpenForTest(e); err != nil {
			return err
		}
	}
	return e.EmitSessionOpen()
}
