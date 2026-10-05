// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build race

package normalize

// raceEnabled thins exhaustive differential sweeps under the race detector,
// which adds nothing to a pure function and multiplies their cost.
const raceEnabled = true
