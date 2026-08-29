// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// RegisteredTopLevelCommandNames returns the command names registered directly
// below pipelock, including enterprise commands registered during package init.
// The capability manifest test uses this assembled command tree so adding an
// operator command cannot bypass the manifest by changing registration wiring.
//
// Hidden and deprecated commands are included deliberately. Cobra's
// IsAvailableCommand reports false for them, and filtering on it meant a
// command marked Hidden was shipped, runnable by anyone who typed it, and
// absent from the inventory with nothing failing. Being undocumented is a
// reason to exclude a command in the manifest, where the reason is written
// down and reviewed, not a reason to never enumerate it.
func RegisteredTopLevelCommandNames() []string {
	root := rootCmd()
	names := make([]string, 0, len(root.Commands()))
	for _, command := range root.Commands() {
		if isInventoriedCommand(command) {
			names = append(names, command.Name())
		}
	}
	sort.Strings(names)
	return names
}

// isInventoriedCommand reports whether a command is part of the shipped
// surface the manifest must account for. Only cobra's generated help command
// is skipped: it is machinery rather than product surface, and it exists on
// every command in the tree.
func isInventoriedCommand(command *cobra.Command) bool {
	return command.Name() != "help"
}

// RegisteredCommandPaths returns every available command path assembled under
// pipelock. Enterprise manifest tests use it to prove that a documented nested
// command is reachable in the enterprise build, not merely declared in a
// constructor that registration forgot to call.
func RegisteredCommandPaths() []string {
	root := rootCmd()
	paths := make([]string, 0)
	var visit func(prefix []string, command *cobra.Command)
	visit = func(prefix []string, command *cobra.Command) {
		path := append(append([]string{}, prefix...), command.Name())
		paths = append(paths, strings.Join(path, " "))
		for _, child := range command.Commands() {
			if isInventoriedCommand(child) {
				visit(path, child)
			}
		}
	}
	for _, command := range root.Commands() {
		if isInventoriedCommand(command) {
			visit([]string{"pipelock"}, command)
		}
	}
	sort.Strings(paths)
	return paths
}
