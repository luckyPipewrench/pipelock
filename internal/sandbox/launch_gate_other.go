// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sandbox

import "os/exec"

// CmdNeedsHardeningGate is always false off Linux. UID/GID mapping is a Linux
// user-namespace concept, so no other platform has the map-write phase the gate
// orders against.
func CmdNeedsHardeningGate(_ *exec.Cmd) bool { return false }
