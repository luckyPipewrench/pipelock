// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package mcp

// startAdoptedReaper is a no-op on non-Linux builds. The reaper exists
// to drain descendants pipelock has adopted via PR_SET_CHILD_SUBREAPER,
// which is itself Linux-only (see subtree_other.go's enableSubreaper
// no-op). Without subreaper adoption there are no orphaned descendants
// to reap.
func startAdoptedReaper(_ int, _ <-chan struct{}) {}

// protectDirectChild is a no-op on non-Linux builds. Nothing walks /proc
// reaping adopted descendants here, so there is no sibling session that
// could consume this child's exit status.
func protectDirectChild(_ int) func() { return func() {} }

// lockChildStart is a no-op on non-Linux builds. It exists so the start-and-
// claim sequence reads identically on every platform; with no sweeps running
// there is nothing to exclude.
func lockChildStart() func() { return func() {} }
