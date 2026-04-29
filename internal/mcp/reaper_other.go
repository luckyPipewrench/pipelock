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
