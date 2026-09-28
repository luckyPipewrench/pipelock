// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build unix && !aix && !linux && !darwin && !freebsd

package recorder

import "golang.org/x/sys/unix"

func evidenceTraversalAccess() int { return unix.O_RDONLY }
