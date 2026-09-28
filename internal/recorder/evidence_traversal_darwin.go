// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package recorder

// Darwin's O_SEARCH is O_EXEC | O_DIRECTORY. The caller supplies O_DIRECTORY.
// x/sys/unix does not export O_EXEC.
const darwinOpenExecute = 0x40000000

func evidenceTraversalAccess() int { return darwinOpenExecute }
