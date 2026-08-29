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
func RegisteredTopLevelCommandNames() []string {
	root := rootCmd()
	names := make([]string, 0, len(root.Commands()))
	for _, command := range root.Commands() {
		if command.IsAvailableCommand() {
			names = append(names, command.Name())
		}
	}
	sort.Strings(names)
	return names
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
			if child.IsAvailableCommand() {
				visit(path, child)
			}
		}
	}
	for _, command := range root.Commands() {
		if command.IsAvailableCommand() {
			visit([]string{"pipelock"}, command)
		}
	}
	sort.Strings(paths)
	return paths
}
