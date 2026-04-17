// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package mcp

import "os/exec"

// setupChildProcessGroup is a no-op on Windows. Windows has no process
// group concept; pipelock's MCP stdio proxy still runs there for
// developer testing, it just cannot claim subtree ownership of any
// grandchildren the wrapped MCP server spawns.
func setupChildProcessGroup(_ *exec.Cmd) {}

// captureChildPgid returns 0 on Windows so the signal helpers below
// become no-ops without requiring each caller to branch on GOOS.
func captureChildPgid(_ int) int { return 0 }

// signalProcessGroupTerm is a no-op on Windows.
func signalProcessGroupTerm(_ int) {}

// terminateProcessGroup is a no-op on Windows.
func terminateProcessGroup(_ int) {}
